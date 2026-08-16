"""Offline tests for the transitive authority walk.

Synthetic accounts are hand-built from the byte layouts verified in
test_layouts.py, which lets the transfer-hook escalation path be tested without
hunting for a live hook-bearing mint (they are rare on mainnet).
"""

import struct

import pytest

from zentry import b58, graph
from zentry.graph import ABSENT, PDA, WALLET
from zentry.layouts import BPF_UPGRADEABLE_LOADER, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM
from zentry.rpc import Account


def pk(seed: int) -> str:
    """Deterministic valid 32-byte pubkey. Seed 0 is avoided - all-zero means 'unset'."""
    assert seed != 0
    return b58.encode(bytes([seed]) * 32)


def build_t22_mint(mint_auth=None, freeze_auth=None, exts=()):
    data = bytearray(165)  # base mint padded to Account size
    if mint_auth:
        struct.pack_into("<I", data, 0, 1)
        data[4:36] = b58.decode(mint_auth)
    struct.pack_into("<Q", data, 36, 1_000_000_000)
    data[44] = 9
    data[45] = 1
    if freeze_auth:
        struct.pack_into("<I", data, 46, 1)
        data[50:82] = b58.decode(freeze_auth)
    data.append(1)  # account_type = Mint at [165]
    for ext_id, value in exts:
        data += struct.pack("<HH", ext_id, len(value)) + value
    return bytes(data)


def program_account(programdata_addr):
    return struct.pack("<I", 2) + b58.decode(programdata_addr)


def programdata_account(upgrade_auth, slot=123456):
    head = struct.pack("<I", 3) + struct.pack("<Q", slot)
    if upgrade_auth is None:
        return head + b"\x00" + b"\x00" * 32
    return head + b"\x01" + b58.decode(upgrade_auth)


class FakeRpc:
    def __init__(self, accounts):
        self.accounts = accounts
        self.calls = 0

    def get_account(self, pubkey):
        self.calls += 1
        return self.accounts.get(pubkey)


def mk(pubkey, owner, data=b"", executable=False, lamports=1):
    return Account(pubkey=pubkey, owner=owner, lamports=lamports, executable=executable, data=data)


MINT = pk(9)
HOOK_PROG = pk(20)
HOOK_PD = pk(21)
HOOK_UPGRADER = pk(22)


def test_clean_mint_scores_zero():
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint())})
    rep = graph.analyse(rpc, MINT)
    assert rep.score == 0
    assert rep.verdict == "NO PRIVILEGED AUTHORITIES"
    assert rep.authorities == {}


def test_upgradeable_transfer_hook_is_critical():
    """The differentiator: hook program can be swapped, so the hook is untrustworthy."""
    hook_ext = b58.decode(pk(23)) + b58.decode(HOOK_PROG)  # authority + program
    rpc = FakeRpc(
        {
            MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(14, hook_ext)])),
            HOOK_PROG: mk(HOOK_PROG, BPF_UPGRADEABLE_LOADER, program_account(HOOK_PD), executable=True),
            HOOK_PD: mk(HOOK_PD, BPF_UPGRADEABLE_LOADER, programdata_account(HOOK_UPGRADER)),
            HOOK_UPGRADER: mk(HOOK_UPGRADER, SYSTEM_PROGRAM),
        }
    )
    rep = graph.analyse(rpc, MINT)
    assert rep.hook_program == HOOK_PROG
    assert rep.hook_upgradeable is True
    assert rep.hook_upgrade_authority == HOOK_UPGRADER
    titles = [f.title for f in rep.findings]
    assert "Transfer hook program is UPGRADEABLE" in titles
    crit = next(f for f in rep.findings if f.title == "Transfer hook program is UPGRADEABLE")
    assert crit.severity == "CRITICAL"
    assert "single keypair" in crit.detail


def test_immutable_transfer_hook_is_not_escalated():
    hook_ext = b58.decode(pk(23)) + b58.decode(HOOK_PROG)
    rpc = FakeRpc(
        {
            MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(14, hook_ext)])),
            HOOK_PROG: mk(HOOK_PROG, BPF_UPGRADEABLE_LOADER, program_account(HOOK_PD), executable=True),
            HOOK_PD: mk(HOOK_PD, BPF_UPGRADEABLE_LOADER, programdata_account(None)),
        }
    )
    rep = graph.analyse(rpc, MINT)
    assert rep.hook_upgradeable is False
    assert "Transfer hook program is UPGRADEABLE" not in [f.title for f in rep.findings]
    assert "Transfer hook program is immutable" in [f.title for f in rep.findings]


def test_no_follow_hooks_skips_the_walk():
    hook_ext = b58.decode(pk(23)) + b58.decode(HOOK_PROG)
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(14, hook_ext)]))})
    rep = graph.analyse(rpc, MINT, follow_hooks=False)
    assert rep.hook_program is None
    assert rep.hook_upgradeable is None


def test_permanent_delegate_on_bare_keypair_escalates():
    delegate = pk(31)
    rpc = FakeRpc(
        {
            MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(12, b58.decode(delegate))])),
            delegate: mk(delegate, SYSTEM_PROGRAM),
        }
    )
    rep = graph.analyse(rpc, MINT)
    assert rep.authorities[delegate].kind == WALLET
    titles = [f.title for f in rep.findings]
    assert "Token-2022: PermanentDelegate" in titles
    assert "Privileged authority is not behind a multisig" in titles
    assert rep.verdict == "DANGEROUS"


def test_authority_on_pda_is_reported_as_program_owned():
    delegate = pk(32)
    rpc = FakeRpc(
        {
            MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(12, b58.decode(delegate))])),
            delegate: mk(delegate, TOKEN_2022_PROGRAM),
        }
    )
    rep = graph.analyse(rpc, MINT)
    assert rep.authorities[delegate].kind == PDA
    # Still critical (the power exists), but no lone-key escalation on top.
    assert "Privileged authority is not behind a multisig" not in [f.title for f in rep.findings]


def test_missing_authority_account_is_absent_not_crash():
    delegate = pk(33)
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(12, b58.decode(delegate))]))})
    rep = graph.analyse(rpc, MINT)
    assert rep.authorities[delegate].kind == ABSENT


def test_default_account_state_frozen_is_critical():
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(6, b"\x02")]))})
    rep = graph.analyse(rpc, MINT)
    frozen = next(f for f in rep.findings if "DefaultAccountState" in f.title)
    assert frozen.severity == "CRITICAL"


def test_default_account_state_initialized_is_benign():
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(6, b"\x01")]))})
    rep = graph.analyse(rpc, MINT)
    assert rep.score == 0


def test_confiscatory_transfer_fee():
    # 108-byte TransferFeeConfig with newer fee = 10000 bps (100%)
    v = bytearray(108)
    v[0:32] = b58.decode(pk(41))
    struct.pack_into("<H", v, 106, 10_000)
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(1, bytes(v))]))})
    rep = graph.analyse(rpc, MINT)
    fee = next(f for f in rep.findings if "TransferFeeConfig" in f.title)
    assert fee.severity == "CRITICAL"
    assert "100%" in fee.detail


def test_non_transferable_is_critical():
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(exts=[(9, b"")]))})
    rep = graph.analyse(rpc, MINT)
    assert next(f for f in rep.findings if "NonTransferable" in f.title).severity == "CRITICAL"


def test_shared_authority_is_deduplicated():
    """One key holding several roles must appear once, with all roles listed."""
    shared = pk(51)
    exts = [(12, b58.decode(shared)), (3, b58.decode(shared))]
    rpc = FakeRpc(
        {
            MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(mint_auth=shared, freeze_auth=shared, exts=exts)),
            shared: mk(shared, SYSTEM_PROGRAM),
        }
    )
    rep = graph.analyse(rpc, MINT)
    assert len(rep.authorities) == 1
    roles = set(rep.authorities[shared].roles)
    assert {"mint_authority", "freeze_authority", "permanent_delegate", "mint_close_authority"} <= roles


def test_score_is_capped_at_100():
    exts = [(12, b58.decode(pk(61))), (9, b""), (6, b"\x02")]
    rpc = FakeRpc({MINT: mk(MINT, TOKEN_2022_PROGRAM, build_t22_mint(mint_auth=pk(62), freeze_auth=pk(63), exts=exts))})
    rep = graph.analyse(rpc, MINT)
    assert rep.score == 100


def test_unknown_mint_raises():
    rpc = FakeRpc({})
    with pytest.raises(ValueError, match="no such account"):
        graph.analyse(rpc, MINT)


def test_resolve_program_immutable():
    prog = pk(70)
    rpc = FakeRpc(
        {
            prog: mk(prog, BPF_UPGRADEABLE_LOADER, program_account(HOOK_PD), executable=True),
            HOOK_PD: mk(HOOK_PD, BPF_UPGRADEABLE_LOADER, programdata_account(None)),
        }
    )
    rep = graph.resolve_program(rpc, prog)
    assert rep.upgradeable is False
    assert rep.upgrade_authority is None


def test_resolve_program_upgradeable():
    prog = pk(71)
    rpc = FakeRpc(
        {
            prog: mk(prog, BPF_UPGRADEABLE_LOADER, program_account(HOOK_PD), executable=True),
            HOOK_PD: mk(HOOK_PD, BPF_UPGRADEABLE_LOADER, programdata_account(HOOK_UPGRADER, slot=999)),
            HOOK_UPGRADER: mk(HOOK_UPGRADER, SYSTEM_PROGRAM),
        }
    )
    rep = graph.resolve_program(rpc, prog)
    assert rep.upgradeable is True
    assert rep.deployed_slot == 999
    assert rep.authority_holder.kind == WALLET


def test_resolve_program_on_old_loader_is_immutable():
    prog = pk(72)
    rpc = FakeRpc({prog: mk(prog, "BPFLoader2111111111111111111111111111111111", b"", executable=True)})
    rep = graph.resolve_program(rpc, prog)
    assert rep.upgradeable is False
    assert rep.programdata is None
