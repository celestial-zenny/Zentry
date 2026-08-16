"""Zentry web API - a thin, non-technical-friendly wrapper over zentry's scanner.

The CLI already emits everything a security engineer needs. This layer does a
different job: collapse zentry's five severity bands and per-extension findings
into the four questions an ordinary buyer actually has -

    Can someone print more?          -> mint
    Can someone freeze my account?   -> freeze
    Can someone take my tokens?      -> seize
    Can someone stop me selling?     -> transfer

Each answer is safe / caution / danger with a plain-English reason.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from zentry import __version__, b58, graph
from zentry.layouts import ParseError
from zentry.rpc import Rpc, RpcError

SAFE, CAUTION, DANGER = "safe", "caution", "danger"
_ORDER = {SAFE: 0, CAUTION: 1, DANGER: 2}

# Public Solana RPC is aggressively rate limited, which is fine for one person
# on a CLI and not fine for a deployed web app. Point this at a paid endpoint
# (Helius, QuickNode, Triton) in production.
RPC_ENDPOINT = os.getenv("SOLANA_RPC_URL", "mainnet")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", "120"))

# Token-2022 extension ids, mapped to the plain-language buckets above.
EXT_PERMANENT_DELEGATE = 12
EXT_TRANSFER_HOOK = 14
EXT_TRANSFER_FEE = 1
EXT_NON_TRANSFERABLE = 9
EXT_DEFAULT_ACCOUNT_STATE = 6
EXT_MINT_CLOSE_AUTHORITY = 3

app = FastAPI(
    title="Zentry",
    version=__version__,
    description="Map the transitive authority graph behind a Solana token mint.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# mint -> (expires_at, payload)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


@app.exception_handler(RequestValidationError)
async def _friendly_validation(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    """Pydantic's default body is a machine-readable blob of type/loc/msg dicts.

    Nobody pasting an address into a web form should ever see that.
    """
    return JSONResponse(
        status_code=400,
        content={
            "detail": (
                "Please paste a Solana token mint address. It should be 32 to 44 characters "
                "of base58 text, with no spaces."
            )
        },
    )


class ScanRequest(BaseModel):
    mint: str = Field(..., min_length=32, max_length=44, description="Solana token mint address")


# --------------------------------------------------------------------------- #
# risk helpers
# --------------------------------------------------------------------------- #

def _worst(*levels: str) -> str:
    return max(levels, key=lambda x: _ORDER[x]) if levels else SAFE


def _holder_of(report: graph.Report, pubkey: str | None) -> graph.Authority | None:
    return report.authorities.get(pubkey) if pubkey else None


def _held_as(auth: graph.Authority | None) -> str | None:
    """Human phrasing for how an authority is custodied."""
    if auth is None:
        return None
    return {
        graph.WALLET: "a single private key",
        graph.ABSENT: "a single private key (unfunded account)",
        graph.PDA: "a program-controlled account (likely a multisig or governance)",
        graph.PROGRAM: "an on-chain program",
    }.get(auth.kind, auth.kind)


def _concentration_risk(auth: graph.Authority | None) -> str:
    """A live authority on one key is worse than one behind a multisig."""
    if auth is None:
        return CAUTION
    if auth.kind in (graph.WALLET, graph.ABSENT):
        return DANGER
    return CAUTION


def _ext(report: graph.Report, ext_id: int):
    return next((e for e in report.mint.extensions if e.ext_id == ext_id), None)


# --------------------------------------------------------------------------- #
# the four buckets
# --------------------------------------------------------------------------- #

def _mint_bucket(report: graph.Report) -> dict[str, Any]:
    holder = report.mint.mint_authority
    auth = _holder_of(report, holder)
    close = _ext(report, EXT_MINT_CLOSE_AUTHORITY)

    if not holder:
        return {
            "type": "mint",
            "title": "Supply control",
            "question": "Can anyone create more of this token?",
            "active": False,
            "holder": None,
            "held_as": None,
            "risk": SAFE,
            "explanation": (
                "No. The mint authority has been permanently revoked, so the total supply "
                "is fixed. Nobody can create new tokens to dilute what you hold."
            ),
        }

    risk = _concentration_risk(auth)
    detail = (
        f"Yes. Whoever controls this address can create new tokens at any time, which "
        f"reduces the value of the ones you own. It is held by {_held_as(auth)}."
    )
    if risk == DANGER:
        detail += (
            " Because that is one key rather than a multisig, a single stolen or misused "
            "key is enough to inflate the supply."
        )
    if close:
        detail += " The mint account can also be closed once supply reaches zero."
    return {
        "type": "mint",
        "title": "Supply control",
        "question": "Can anyone create more of this token?",
        "active": True,
        "holder": holder,
        "held_as": _held_as(auth),
        "risk": risk,
        "explanation": detail,
    }


def _freeze_bucket(report: graph.Report) -> dict[str, Any]:
    holder = report.mint.freeze_authority
    auth = _holder_of(report, holder)
    das = _ext(report, EXT_DEFAULT_ACCOUNT_STATE)
    frozen_by_default = bool(das and das.detail.get("state") == 2)

    if not holder and not frozen_by_default:
        return {
            "type": "freeze",
            "title": "Account freezing",
            "question": "Can anyone freeze your wallet and stop you transacting?",
            "active": False,
            "holder": None,
            "held_as": None,
            "risk": SAFE,
            "explanation": (
                "No. The freeze authority has been revoked, so no one can lock your token "
                "account. Your ability to send or sell cannot be switched off."
            ),
        }

    risk = DANGER if frozen_by_default else _concentration_risk(auth)
    if frozen_by_default:
        detail = (
            "Yes, and worse than usual: new holder accounts start out FROZEN by default. "
            "Anyone receiving this token is unable to move it until an authority "
            "individually unfreezes them."
        )
    else:
        detail = (
            f"Yes. Whoever controls this address can freeze your token account, which "
            f"blocks you from sending or selling while it stays frozen. It is held by "
            f"{_held_as(auth)}."
        )
        if risk == DANGER:
            detail += " That is a single key, not a multisig."
    return {
        "type": "freeze",
        "title": "Account freezing",
        "question": "Can anyone freeze your wallet and stop you transacting?",
        "active": True,
        "holder": holder,
        "held_as": _held_as(auth),
        "risk": risk,
        "explanation": detail,
    }


def _seize_bucket(report: graph.Report) -> dict[str, Any]:
    pd = _ext(report, EXT_PERMANENT_DELEGATE)
    holder = pd.authorities.get("permanent_delegate") if pd else None
    auth = _holder_of(report, holder)

    if not pd or not holder:
        return {
            "type": "seize",
            "title": "Token seizure",
            "question": "Can anyone take your tokens directly out of your wallet?",
            "active": False,
            "holder": None,
            "held_as": None,
            "risk": SAFE,
            "explanation": (
                "No. There is no permanent delegate on this token, so nobody can move or "
                "burn your balance without your signature."
            ),
        }

    # This power is catastrophic regardless of custody, so it is never "caution".
    detail = (
        f"Yes. This token has a permanent delegate, which means the holder of this address "
        f"can transfer or burn tokens out of ANY wallet, including yours, without your "
        f"permission and at any time. It is held by {_held_as(auth)}."
    )
    if auth and auth.kind in (graph.WALLET, graph.ABSENT):
        detail += (
            " It sits on a single key, so one compromised key could drain every holder."
        )
    else:
        detail += (
            " It sits behind a program-controlled account, which is better than a lone key "
            "but does not remove the power itself. Regulated issuers often hold this "
            "deliberately, for court-ordered clawbacks."
        )
    return {
        "type": "seize",
        "title": "Token seizure",
        "question": "Can anyone take your tokens directly out of your wallet?",
        "active": True,
        "holder": holder,
        "held_as": _held_as(auth),
        "risk": DANGER,
        "explanation": detail,
    }


def _transfer_bucket(report: graph.Report) -> dict[str, Any]:
    hook = _ext(report, EXT_TRANSFER_HOOK)
    fee = _ext(report, EXT_TRANSFER_FEE)
    nt = _ext(report, EXT_NON_TRANSFERABLE)
    hook_program = report.hook_program

    if nt:
        return {
            "type": "transfer",
            "title": "Selling and transfers",
            "question": "Can anyone block or tax your ability to sell?",
            "active": True,
            "holder": None,
            "held_as": None,
            "risk": DANGER,
            "explanation": (
                "This token is marked non-transferable. It can never be sent or sold by "
                "anyone, ever. If you bought it expecting to trade it, you cannot."
            ),
        }

    notes: list[str] = []
    risk = SAFE
    holder: str | None = None

    if hook_program:
        holder = hook_program
        if report.hook_upgradeable:
            risk = _worst(risk, DANGER)
            notes.append(
                f"Every transfer of this token runs through a separate program first, and "
                f"that program can still be rewritten by {report.hook_upgrade_authority}. "
                f"Code that allows selling today can be replaced with code that blocks it "
                f"tomorrow, without the token itself changing."
            )
        elif report.hook_upgradeable is False:
            risk = _worst(risk, CAUTION)
            notes.append(
                "Every transfer runs through a separate program first, but that program's "
                "upgrade authority has been revoked, so its rules are now fixed."
            )
        else:
            risk = _worst(risk, CAUTION)
            notes.append(
                "Every transfer runs through a separate program first. Zentry could not "
                "determine whether that program can still be changed."
            )

    if fee:
        bps = fee.detail.get("current_fee_bps")
        pct = (bps / 100) if isinstance(bps, (int, float)) else None
        can_change = bool(fee.authorities.get("transfer_fee_config_authority"))
        if pct is not None and pct >= 50:
            risk = _worst(risk, DANGER)
            notes.append(f"A {pct:g}% fee is taken on every transfer, which is confiscatory.")
        elif pct is not None and pct > 0:
            risk = _worst(risk, CAUTION if pct < 10 else DANGER)
            notes.append(f"A {pct:g}% fee is taken on every transfer.")
        else:
            risk = _worst(risk, CAUTION if can_change else SAFE)
            notes.append("A transfer fee is configured, currently set to 0%.")
        if can_change:
            risk = _worst(risk, CAUTION)
            notes.append("An authority can raise that fee later.")

    if not notes:
        return {
            "type": "transfer",
            "title": "Selling and transfers",
            "question": "Can anyone block or tax your ability to sell?",
            "active": False,
            "holder": None,
            "held_as": None,
            "risk": SAFE,
            "explanation": (
                "No. There is no transfer hook and no transfer fee, so nothing sits between "
                "you and a normal sale."
            ),
        }

    return {
        "type": "transfer",
        "title": "Selling and transfers",
        "question": "Can anyone block or tax your ability to sell?",
        "active": True,
        "holder": holder,
        "held_as": None,
        "risk": risk,
        "explanation": " ".join(notes),
    }


# --------------------------------------------------------------------------- #
# summary
# --------------------------------------------------------------------------- #

def _overall(report: graph.Report, buckets: list[dict[str, Any]]) -> str:
    """The banner must never contradict the cards.

    Deriving this from the raw score alone produced a red banner above four
    non-red cards (USDC scores 44 while both its authorities sit behind
    multisigs), which reads as a broken tool. So the headline is the worst
    individual card - with a floor, so anything zentry flagged that the four
    buckets don't model still shows up as caution rather than vanishing.
    """
    worst = _worst(*[b["risk"] for b in buckets]) if buckets else SAFE
    if worst == SAFE and report.score >= 15:
        return CAUTION
    return worst


def _summary(report: graph.Report, buckets: list[dict[str, Any]]) -> str:
    name = report.label or "This token"
    standard = "a Token-2022 token" if report.mint.is_token2022 else "a standard SPL token"
    active = [b for b in buckets if b["active"]]
    dangers = [b for b in buckets if b["risk"] == DANGER]

    if not active:
        return (
            f"{name} has no active privileged authorities. Its mint and freeze authorities "
            f"have both been revoked and no extensions grant anyone special power over "
            f"holders, so nobody can inflate the supply, freeze your account, seize your "
            f"balance, or block you from selling. This is the safest configuration a token "
            f"can have. That says nothing about the project's value, liquidity, or team - "
            f"only that the token contract itself gives no one control over you."
        )

    powers = {
        "mint": "create new tokens",
        "freeze": "freeze your account",
        "seize": "take tokens straight out of your wallet",
        "transfer": "interfere with your ability to sell",
    }
    listed = [powers[b["type"]] for b in active]
    if len(listed) == 1:
        phrase = listed[0]
    else:
        phrase = ", ".join(listed[:-1]) + f", and {listed[-1]}"

    lone_key = [
        b for b in active
        if b["held_as"] and b["held_as"].startswith("a single private key")
    ]

    out = f"{name} is {standard} where someone can still {phrase}. "

    if lone_key:
        out += (
            f"Critically, {len(lone_key)} of those powers "
            f"{'is' if len(lone_key) == 1 else 'are'} controlled by a single private key "
            f"rather than a multisig, so one stolen or misused key is enough to use "
            f"{'it' if len(lone_key) == 1 else 'them'} against holders. "
        )
    else:
        out += (
            "Each of those powers sits behind a program-controlled account rather than a "
            "lone key, which is how established issuers normally custody them. "
        )

    if dangers:
        out += (
            "Treat this as high risk unless you specifically trust whoever holds those "
            "keys. "
        )
    else:
        out += "Nothing here is automatically disqualifying, but go in informed. "

    out += (
        "Bear in mind that powerful authorities are not proof of bad intent - regulated "
        "stablecoins hold freeze and clawback powers on purpose. Zentry reports what "
        "someone is technically able to do to you, not what they intend to do."
    )
    return out


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

def _build_payload(report: graph.Report) -> dict[str, Any]:
    buckets = [
        _mint_bucket(report),
        _freeze_bucket(report),
        _seize_bucket(report),
        _transfer_bucket(report),
    ]
    return {
        "mint": report.mint.pubkey,
        "label": report.label,
        "token_standard": "Token-2022" if report.mint.is_token2022 else "SPL Token",
        "supply": report.mint.supply_ui,
        "decimals": report.mint.decimals,
        "overall_risk": _overall(report, buckets),
        "score": report.score,
        "technical_verdict": report.verdict,
        "summary": _summary(report, buckets),
        "authorities": buckets,
        "technical_findings": [
            {"severity": f.severity, "title": f.title, "detail": f.detail}
            for f in report.findings
        ],
        "rpc_calls": report.rpc_calls,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "name": "Zentry",
        "version": __version__,
        "endpoints": {"scan": "POST /scan {\"mint\": \"<address>\"}", "health": "GET /health"},
    }


@app.post("/scan")
def scan(req: ScanRequest) -> dict[str, Any]:
    mint = req.mint.strip()

    if not b58.is_pubkey(mint):
        raise HTTPException(
            status_code=400,
            detail=(
                "That does not look like a Solana address. A mint address is 32-44 "
                "characters of base58 - no 0, O, I or l."
            ),
        )

    now = time.time()
    hit = _cache.get(mint)
    if hit and hit[0] > now:
        return {**hit[1], "cached": True}

    try:
        rpc = Rpc(RPC_ENDPOINT)
        report = graph.analyse(rpc, mint)
    except RpcError as exc:
        # Upstream problem, not the caller's fault.
        raise HTTPException(
            status_code=503,
            detail=(
                "Could not reach the Solana network right now. This is usually public RPC "
                "rate limiting - please try again in a moment."
            ),
        ) from exc
    except ParseError as exc:
        # ParseError subclasses ValueError, so it must be caught first.
        # Both failure shapes mean the same thing to a non-technical user: the
        # address is real but it isn't a token mint. A program account trips the
        # length check (36 bytes) before the owner check ever runs, so match both.
        msg = str(exc)
        if "not a token program" in msg or "too short for a mint" in msg:
            raise HTTPException(
                status_code=400,
                detail=(
                    "That address exists on Solana but it is not a token mint. It looks like "
                    "a wallet, a program, or a token account. Paste the token's mint address "
                    "instead - that's the one explorers label 'Mint'."
                ),
            ) from exc
        raise HTTPException(
            status_code=422,
            detail=(
                "That account exists but Zentry could not read it as a token mint. It may be "
                "a non-standard or corrupted token."
            ),
        ) from exc
    except ValueError as exc:
        if "no such account" in str(exc):
            raise HTTPException(
                status_code=404,
                detail=(
                    "No account with that address exists on Solana mainnet. Check for a "
                    "typo, or confirm the token is on mainnet rather than devnet."
                ),
            ) from exc
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace to the browser
        raise HTTPException(
            status_code=500,
            detail="Something went wrong while scanning that token. Please try again.",
        ) from exc

    payload = _build_payload(report)
    _cache[mint] = (now + CACHE_TTL, payload)
    if len(_cache) > 512:  # crude bound; restart clears it
        for k in sorted(_cache, key=lambda k: _cache[k][0])[:128]:
            _cache.pop(k, None)
    return {**payload, "cached": False}
