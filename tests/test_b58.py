import pytest

from authgraph import b58
from authgraph.layouts import SYSTEM_PROGRAM


def test_roundtrip_random_like():
    for raw in (b"\x01" * 32, bytes(range(32)), b"\xff" * 32):
        assert b58.decode(b58.encode(raw)) == raw


def test_system_program_is_32_zero_bytes():
    """All-'1' base58 is the all-zero pubkey - the leading-zero path."""
    assert b58.decode(SYSTEM_PROGRAM) == b"\x00" * 32
    assert b58.encode(b"\x00" * 32) == SYSTEM_PROGRAM


def test_known_pubkey_decodes_to_32_bytes():
    assert len(b58.decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")) == 32


def test_is_pubkey():
    assert b58.is_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    assert b58.is_pubkey(SYSTEM_PROGRAM)
    assert not b58.is_pubkey("tooshort")
    assert not b58.is_pubkey("0OIl")  # characters excluded from the alphabet


def test_invalid_character_rejected():
    with pytest.raises(ValueError):
        b58.decode("hello!world")


def test_empty():
    assert b58.encode(b"") == ""
    assert b58.decode("") == b""
