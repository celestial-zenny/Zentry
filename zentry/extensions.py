"""Token-2022 extension table and the risk meaning of each one.

Extension IDs verified against live mainnet accounts (PYUSD carries 8 of them
and the TLV walk lands exactly on the end of its 866-byte account).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import b58

# Severity ordering used for sorting and scoring.
CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
SEVERITY_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
SEVERITY_WEIGHT = {CRITICAL: 40, HIGH: 22, MEDIUM: 9, LOW: 3, INFO: 0}

NAMES = {
    0: "Uninitialized",
    1: "TransferFeeConfig",
    2: "TransferFeeAmount",
    3: "MintCloseAuthority",
    4: "ConfidentialTransferMint",
    5: "ConfidentialTransferAccount",
    6: "DefaultAccountState",
    7: "ImmutableOwner",
    8: "MemoTransfer",
    9: "NonTransferable",
    10: "InterestBearingConfig",
    11: "CpiGuard",
    12: "PermanentDelegate",
    13: "NonTransferableAccount",
    14: "TransferHook",
    15: "TransferHookAccount",
    16: "ConfidentialTransferFeeConfig",
    17: "ConfidentialTransferFeeAmount",
    18: "MetadataPointer",
    19: "TokenMetadata",
    20: "GroupPointer",
    21: "TokenGroup",
    22: "GroupMemberPointer",
    23: "TokenGroupMember",
}


@dataclass
class Ext:
    """A decoded Token-2022 extension."""

    ext_id: int
    name: str
    raw: bytes
    severity: str = INFO
    note: str = ""
    # Authorities this extension hands to somebody, as {role: pubkey}.
    authorities: dict[str, str] = field(default_factory=dict)
    detail: dict[str, object] = field(default_factory=dict)


def _pk(raw: bytes, off: int) -> str | None:
    """Read a pubkey; all-zero means 'unset' in Token-2022 extension data."""
    chunk = raw[off : off + 32]
    if len(chunk) != 32 or chunk == b"\x00" * 32:
        return None
    return b58.encode(chunk)


def decode_extension(ext_id: int, raw: bytes) -> Ext:
    name = NAMES.get(ext_id, f"Unknown({ext_id})")
    e = Ext(ext_id=ext_id, name=name, raw=raw)

    if ext_id == 12:  # PermanentDelegate
        who = _pk(raw, 0)
        e.severity = CRITICAL
        e.note = "Can transfer or burn ANY holder's tokens, permanently and without consent."
        if who:
            e.authorities["permanent_delegate"] = who

    elif ext_id == 14:  # TransferHook: authority(32) + program_id(32)
        auth, prog = _pk(raw, 0), _pk(raw, 32)
        e.severity = HIGH
        e.note = "Arbitrary program runs on every transfer; it can reject sells."
        if auth:
            e.authorities["hook_authority"] = auth
        if prog:
            e.authorities["hook_program"] = prog
            e.detail["hook_program"] = prog
        else:
            e.severity = LOW
            e.note = "Transfer hook slot present but no program set."

    elif ext_id == 3:  # MintCloseAuthority
        who = _pk(raw, 0)
        e.severity = MEDIUM
        e.note = "Mint account can be closed once supply is zero."
        if who:
            e.authorities["mint_close_authority"] = who

    elif ext_id == 6:  # DefaultAccountState: 1 byte (1=Initialized, 2=Frozen)
        state = raw[0] if raw else 0
        e.detail["state"] = state
        if state == 2:
            e.severity = CRITICAL
            e.note = "New holder accounts are FROZEN by default - holders cannot transfer."
        else:
            e.severity = INFO
            e.note = "Default account state is Initialized (normal)."

    elif ext_id == 1:  # TransferFeeConfig, 108 bytes
        e.severity = MEDIUM
        cfg_auth, withdraw_auth = _pk(raw, 0), _pk(raw, 32)
        if cfg_auth:
            e.authorities["transfer_fee_config_authority"] = cfg_auth
        if withdraw_auth:
            e.authorities["withdraw_withheld_authority"] = withdraw_auth
        if len(raw) >= 108:
            older_bps = struct.unpack_from("<H", raw, 88)[0]
            newer_bps = struct.unpack_from("<H", raw, 106)[0]
            newer_max = struct.unpack_from("<Q", raw, 98)[0]
            e.detail.update(
                older_fee_bps=older_bps, current_fee_bps=newer_bps, maximum_fee=newer_max
            )
            pct = newer_bps / 100
            e.note = f"Transfer fee currently {pct:g}% ({newer_bps} bps)."
            if newer_bps >= 5000:
                e.severity = CRITICAL
                e.note += " At/above 50% this is confiscatory."
            elif newer_bps >= 1000:
                e.severity = HIGH
                e.note += " Above 10%."
            if cfg_auth:
                e.note += " An authority can still change it."
        else:
            e.note = "Transfer fee configured."

    elif ext_id == 9:  # NonTransferable
        e.severity = CRITICAL
        e.note = "Token is non-transferable (soulbound) - it can never be sold."

    elif ext_id == 10:  # InterestBearingConfig
        e.severity = LOW
        who = _pk(raw, 0)
        if who:
            e.authorities["rate_authority"] = who
        e.note = "Displayed balance accrues interest; cosmetic but can mislead UIs."

    elif ext_id == 4:  # ConfidentialTransferMint: authority(32)+auto_approve(1)+auditor(32)
        e.severity = LOW
        who = _pk(raw, 0)
        if who:
            e.authorities["confidential_transfer_authority"] = who
        e.note = "Confidential transfers enabled; balances may be hidden from explorers."

    elif ext_id in (18, 20, 22):  # pointer extensions: authority(32)+target(32)
        e.severity = INFO
        who = _pk(raw, 0)
        if who:
            e.authorities[f"{name}_authority"] = who
        e.note = "Metadata/group pointer."

    elif ext_id in (7, 8, 11, 19, 21, 23, 2, 5, 13, 15, 16, 17):
        e.severity = INFO
        e.note = "Informational extension; no direct holder risk."

    else:
        e.severity = LOW
        e.note = "Unrecognised extension - inspect manually."

    return e
