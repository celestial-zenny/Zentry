"""Base58 (Bitcoin alphabet) codec. Pure stdlib - Solana pubkeys are base58."""

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n:
        n, rem = divmod(n, 58)
        out.append(ALPHABET[rem])
    # every leading zero byte becomes a literal '1'
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return ("1" * pad) + out[::-1].decode()


def decode(s: str) -> bytes:
    n = 0
    for ch in s.encode():
        if ch not in _INDEX:
            raise ValueError(f"invalid base58 character: {chr(ch)!r}")
        n = n * 58 + _INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def is_pubkey(s: str) -> bool:
    """A Solana pubkey is 32 bytes of base58."""
    try:
        return len(decode(s)) == 32
    except ValueError:
        return False
