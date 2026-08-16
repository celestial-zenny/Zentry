"""Labels for well-known programs and mints.

Deliberately small. The tool's job is to *derive* trust from on-chain account
ownership, not to ship an unverifiable allowlist - so this only names things
that are cheap to confirm and useful for orientation.
"""

from __future__ import annotations

PROGRAMS = {
    "11111111111111111111111111111111": "System Program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "SPL Token-2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token Account",
    "BPFLoaderUpgradeab1e11111111111111111111111": "BPF Upgradeable Loader",
    "BPFLoader2111111111111111111111111111111111": "BPF Loader (immutable)",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": "Metaplex Token Metadata",
    "ComputeBudget111111111111111111111111111111": "Compute Budget",
}

# Mints only - issuer identity, not authority addresses.
MINTS = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC (Circle)",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT (Tether)",
    "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo": "PYUSD (Paxos / PayPal)",
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263": "BONK",
    "So11111111111111111111111111111111111111112": "Wrapped SOL",
}


def label_program(pubkey: str) -> str | None:
    return PROGRAMS.get(pubkey)


def label_mint(pubkey: str) -> str | None:
    return MINTS.get(pubkey)
