"""Byte-level parsers for SPL Mint, Token-2022 TLV extensions, and BPF
upgradeable-loader accounts.

Every offset here was checked against live mainnet accounts - see
tests/test_layouts.py, which replays captured fixtures offline.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import b58
from .extensions import Ext, decode_extension

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"

MINT_LEN = 82
# Token-2022 pads the base mint out to the size of a token Account (165) so the
# two can be told apart, then writes account_type at [165] and TLV from [166].
T22_ACCOUNT_TYPE_OFFSET = 165
T22_TLV_OFFSET = 166


class ParseError(ValueError):
    pass


@dataclass
class Mint:
    pubkey: str
    program: str
    mint_authority: str | None
    freeze_authority: str | None
    supply: int
    decimals: int
    is_initialized: bool
    extensions: list[Ext] = field(default_factory=list)

    @property
    def is_token2022(self) -> bool:
        return self.program == TOKEN_2022_PROGRAM

    @property
    def supply_ui(self) -> float:
        return self.supply / (10**self.decimals) if self.decimals else float(self.supply)


def _opt_pubkey(data: bytes, opt_off: int, key_off: int) -> str | None:
    """COption<Pubkey>: a u32 discriminant followed by the key."""
    if struct.unpack_from("<I", data, opt_off)[0] == 0:
        return None
    return b58.encode(data[key_off : key_off + 32])


def parse_mint(pubkey: str, owner: str, data: bytes) -> Mint:
    if len(data) < MINT_LEN:
        raise ParseError(f"{pubkey}: {len(data)} bytes is too short for a mint (need {MINT_LEN})")
    if owner not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise ParseError(f"{pubkey}: owned by {owner}, which is not a token program")

    m = Mint(
        pubkey=pubkey,
        program=owner,
        mint_authority=_opt_pubkey(data, 0, 4),
        supply=struct.unpack_from("<Q", data, 36)[0],
        decimals=data[44],
        is_initialized=bool(data[45]),
        freeze_authority=_opt_pubkey(data, 46, 50),
    )
    if owner == TOKEN_2022_PROGRAM and len(data) > T22_ACCOUNT_TYPE_OFFSET:
        m.extensions = parse_tlv(data)
    return m


def parse_tlv(data: bytes) -> list[Ext]:
    """Walk Token-2022's type-length-value extension region.

    Each entry is u16 type, u16 length, then that many bytes of value.
    """
    exts: list[Ext] = []
    off = T22_TLV_OFFSET
    while off + 4 <= len(data):
        ext_id, length = struct.unpack_from("<HH", data, off)
        off += 4
        if ext_id == 0 and length == 0:  # zero padding marks the end
            break
        if off + length > len(data):
            raise ParseError(f"extension {ext_id} claims {length} bytes but only {len(data)-off} remain")
        exts.append(decode_extension(ext_id, data[off : off + length]))
        off += length
    return exts


def parse_program_account(pubkey: str, data: bytes) -> str:
    """An upgradeable Program account is enum(2) + the ProgramData address."""
    if len(data) < 36:
        raise ParseError(f"{pubkey}: {len(data)} bytes is too short for a Program account")
    kind = struct.unpack_from("<I", data, 0)[0]
    if kind != 2:
        raise ParseError(f"{pubkey}: loader state {kind}, expected 2 (Program)")
    return b58.encode(data[4:36])


def parse_programdata(pubkey: str, data: bytes) -> tuple[int, str | None]:
    """ProgramData header: enum(3) + slot u64 + Option<Pubkey> upgrade authority.

    Returns (deployed_slot, upgrade_authority). A None authority means the
    program has been made immutable.
    """
    if len(data) < 45:
        raise ParseError(f"{pubkey}: {len(data)} bytes is too short for ProgramData")
    kind = struct.unpack_from("<I", data, 0)[0]
    if kind != 3:
        raise ParseError(f"{pubkey}: loader state {kind}, expected 3 (ProgramData)")
    slot = struct.unpack_from("<Q", data, 4)[0]
    if data[12] == 0:
        return slot, None
    return slot, b58.encode(data[13:45])
