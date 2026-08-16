"""Replay real mainnet accounts captured in tests/fixtures/accounts.json.

These run entirely offline, so CI needs no RPC access.
"""

import base64
import json
import pathlib

import pytest

from zentry import layouts
from zentry.layouts import TOKEN_2022_PROGRAM, TOKEN_PROGRAM

FIXTURES = json.loads((pathlib.Path(__file__).parent / "fixtures" / "accounts.json").read_text())


def acct(name):
    f = FIXTURES[name]
    return f["pubkey"], f["owner"], base64.b64decode(f["data_b64"])


def test_usdc_legacy_mint():
    pk, owner, data = acct("usdc_mint")
    assert owner == TOKEN_PROGRAM
    assert len(data) == layouts.MINT_LEN
    m = layouts.parse_mint(pk, owner, data)
    assert m.decimals == 6
    assert m.is_initialized
    assert not m.is_token2022
    # Circle holds both; this is the point of the tool, not a bug in the data.
    assert m.mint_authority is not None
    assert m.freeze_authority is not None
    assert m.extensions == []


def test_bonk_has_both_authorities_revoked():
    pk, owner, data = acct("bonk_mint")
    m = layouts.parse_mint(pk, owner, data)
    assert m.mint_authority is None
    assert m.freeze_authority is None
    assert m.decimals == 5


def test_pyusd_token2022_extensions():
    pk, owner, data = acct("pyusd_mint_t22")
    assert owner == TOKEN_2022_PROGRAM
    m = layouts.parse_mint(pk, owner, data)
    assert m.is_token2022
    assert m.decimals == 6
    found = {e.ext_id for e in m.extensions}
    # Verified live: PYUSD carries exactly these eight.
    assert found == {1, 3, 4, 12, 14, 16, 18, 19}
    names = {e.name for e in m.extensions}
    assert "PermanentDelegate" in names
    assert "TransferHook" in names


def test_pyusd_permanent_delegate_is_critical():
    pk, owner, data = acct("pyusd_mint_t22")
    m = layouts.parse_mint(pk, owner, data)
    pd = next(e for e in m.extensions if e.ext_id == 12)
    assert pd.severity == "CRITICAL"
    assert "permanent_delegate" in pd.authorities


def test_pyusd_transfer_hook_program_is_unset():
    """PYUSD declares the hook slot with a null program - must not cry wolf."""
    pk, owner, data = acct("pyusd_mint_t22")
    m = layouts.parse_mint(pk, owner, data)
    hook = next(e for e in m.extensions if e.ext_id == 14)
    assert hook.detail.get("hook_program") is None
    assert hook.severity == "LOW"


def test_tlv_walk_consumes_exactly_the_account():
    """A wrong extension-ID table would misalign and overrun - this catches it."""
    pk, owner, data = acct("pyusd_mint_t22")
    exts = layouts.parse_tlv(data)
    consumed = layouts.T22_TLV_OFFSET + sum(4 + len(e.raw) for e in exts)
    assert consumed <= len(data)
    assert len(exts) == 8


def test_program_and_programdata_chain():
    pk, owner, data = acct("t22_program")
    assert len(data) == 36
    pd_addr = layouts.parse_program_account(pk, data)
    assert pd_addr == FIXTURES["t22_programdata"]["pubkey"]

    pdpk, pdowner, pddata = acct("t22_programdata")
    slot, upgrade_auth = layouts.parse_programdata(pdpk, pddata)
    assert slot > 0
    assert upgrade_auth is not None  # Token-2022 is still upgradeable


def test_rejects_non_token_owner():
    pk, _owner, data = acct("usdc_mint")
    with pytest.raises(layouts.ParseError, match="not a token program"):
        layouts.parse_mint(pk, layouts.SYSTEM_PROGRAM, data)


def test_rejects_short_mint():
    with pytest.raises(layouts.ParseError, match="too short"):
        layouts.parse_mint("x", TOKEN_PROGRAM, b"\x00" * 10)


def test_rejects_wrong_loader_state():
    with pytest.raises(layouts.ParseError, match="expected 2"):
        layouts.parse_program_account("x", b"\x09" + b"\x00" * 40)
    with pytest.raises(layouts.ParseError, match="expected 3"):
        layouts.parse_programdata("x", b"\x09" + b"\x00" * 60)
