"""Transitive authority resolution - the part other scanners skip.

A null-check on mintAuthority is shallow. What actually decides holder risk is
*who* holds each authority, and whether any program in the path can be swapped
out later. So for every authority we ask what kind of account holds it, and for
program authorities (notably a Token-2022 transfer hook) we follow the chain to
the ProgramData account and read its upgrade authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import layouts, registry
from .extensions import CRITICAL, HIGH, INFO, LOW, MEDIUM, SEVERITY_RANK, SEVERITY_WEIGHT
from .layouts import BPF_UPGRADEABLE_LOADER, SYSTEM_PROGRAM, Mint
from .rpc import Rpc

# How an authority is held. This is the signal a plain null-check throws away.
WALLET = "single keypair"
PDA = "program-owned (PDA / multisig / governance)"
ABSENT = "no account on chain"
PROGRAM = "executable program"


@dataclass
class Authority:
    pubkey: str
    roles: list[str] = field(default_factory=list)
    kind: str = ABSENT
    owner: str | None = None
    owner_label: str | None = None
    lamports: int = 0


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    subject: str | None = None


@dataclass
class Report:
    mint: Mint
    label: str | None
    authorities: dict[str, Authority]
    findings: list[Finding]
    hook_program: str | None = None
    hook_upgradeable: bool | None = None
    hook_upgrade_authority: str | None = None
    rpc_calls: int = 0

    @property
    def score(self) -> int:
        """0 = nothing holder-hostile found, 100 = maximally dangerous."""
        total = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return min(100, total)

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 70:
            return "DANGEROUS"
        if s >= 40:
            return "HIGH RISK"
        if s >= 15:
            return "CAUTION"
        if s > 0:
            return "MINOR NOTES"
        return "NO PRIVILEGED AUTHORITIES"


def _classify(rpc: Rpc, pubkey: str) -> Authority:
    a = Authority(pubkey=pubkey)
    acct = rpc.get_account(pubkey)
    if acct is None:
        # Note: an absent account can still sign. It just holds no lamports or
        # data, which means it is a plain keypair rather than a PDA.
        a.kind = ABSENT
        return a
    a.owner = acct.owner
    a.owner_label = registry.label_program(acct.owner)
    a.lamports = acct.lamports
    if acct.executable:
        a.kind = PROGRAM
    elif acct.owner == SYSTEM_PROGRAM:
        a.kind = WALLET
    else:
        a.kind = PDA
    return a


def _concentration_note(a: Authority) -> str:
    if a.kind == WALLET:
        return "held by a single keypair - one compromised key is enough"
    if a.kind == ABSENT:
        return "no account on chain, so it is a bare keypair with no multisig protection"
    if a.kind == PDA:
        owner = a.owner_label or a.owner
        return f"held by a program-owned PDA ({owner}), which suggests multisig or governance"
    if a.kind == PROGRAM:
        return "held by an executable program"
    return ""


@dataclass
class ProgramReport:
    program: str
    label: str | None
    loader: str
    programdata: str | None
    deployed_slot: int | None
    upgrade_authority: str | None
    authority_holder: Authority | None

    @property
    def upgradeable(self) -> bool:
        return self.upgrade_authority is not None


def resolve_program(rpc: Rpc, program_id: str) -> ProgramReport:
    """Read a program's upgrade authority.

    Useful on its own: "can this program be rewritten under me, and by whom?"
    is the same question that decides whether a transfer hook can be trusted.
    """
    acct = rpc.get_account(program_id)
    if acct is None:
        raise ValueError(f"{program_id}: no such account on this cluster")

    rep = ProgramReport(
        program=program_id,
        label=registry.label_program(program_id),
        loader=acct.owner,
        programdata=None,
        deployed_slot=None,
        upgrade_authority=None,
        authority_holder=None,
    )
    if acct.owner != BPF_UPGRADEABLE_LOADER:
        # Anything on the old loader is immutable by construction.
        return rep

    pd_addr = layouts.parse_program_account(program_id, acct.data)
    rep.programdata = pd_addr
    pd = rpc.get_account(pd_addr)
    if pd is None:
        raise ValueError(f"{pd_addr}: ProgramData account missing")
    slot, upgrade_auth = layouts.parse_programdata(pd_addr, pd.data)
    rep.deployed_slot = slot
    rep.upgrade_authority = upgrade_auth
    if upgrade_auth:
        rep.authority_holder = _classify(rpc, upgrade_auth)
    return rep


def analyse(rpc: Rpc, mint_pubkey: str, follow_hooks: bool = True) -> Report:
    acct = rpc.get_account(mint_pubkey)
    if acct is None:
        raise ValueError(f"{mint_pubkey}: no such account on this cluster")
    mint = layouts.parse_mint(mint_pubkey, acct.owner, acct.data)

    findings: list[Finding] = []
    # role -> pubkey, deduplicated into Authority objects afterwards
    roles: dict[str, str] = {}

    if mint.mint_authority:
        roles["mint_authority"] = mint.mint_authority
        findings.append(
            Finding(
                HIGH,
                "Mint authority is active",
                "Supply can be inflated at will; your share can be diluted to nothing.",
                mint.mint_authority,
            )
        )
    if mint.freeze_authority:
        roles["freeze_authority"] = mint.freeze_authority
        findings.append(
            Finding(
                HIGH,
                "Freeze authority is active",
                "Your token account can be frozen, which blocks you from selling.",
                mint.freeze_authority,
            )
        )

    for ext in mint.extensions:
        for role, pk in ext.authorities.items():
            roles[role] = pk
        if ext.severity != INFO:
            findings.append(
                Finding(
                    ext.severity,
                    f"Token-2022: {ext.name}",
                    ext.note,
                    next(iter(ext.authorities.values()), None),
                )
            )

    # Resolve who holds each authority.
    authorities: dict[str, Authority] = {}
    for role, pk in roles.items():
        if pk in authorities:
            authorities[pk].roles.append(role)
        else:
            a = _classify(rpc, pk)
            a.roles.append(role)
            authorities[pk] = a

    # Escalate when a dangerous authority sits on a lone keypair.
    for a in authorities.values():
        dangerous = {"permanent_delegate", "freeze_authority", "mint_authority"} & set(a.roles)
        if dangerous and a.kind in (WALLET, ABSENT):
            # A permanent delegate on a single key is the worst case there is:
            # one compromised key can seize every holder's balance.
            sev = CRITICAL if "permanent_delegate" in dangerous else HIGH
            findings.append(
                Finding(
                    sev,
                    "Privileged authority is not behind a multisig",
                    f"{', '.join(sorted(dangerous))} {_concentration_note(a)}.",
                    a.pubkey,
                )
            )

    report = Report(
        mint=mint,
        label=registry.label_mint(mint_pubkey),
        authorities=authorities,
        findings=findings,
    )

    # The transitive hop: a transfer hook is only as trustworthy as the upgrade
    # authority of the program behind it.
    hook = next(
        (e.detail.get("hook_program") for e in mint.extensions if e.ext_id == 14 and e.detail.get("hook_program")),
        None,
    )
    if hook and follow_hooks:
        report.hook_program = str(hook)
        try:
            prog = rpc.get_account(report.hook_program)
            if prog and prog.owner == BPF_UPGRADEABLE_LOADER:
                pd_addr = layouts.parse_program_account(report.hook_program, prog.data)
                pd = rpc.get_account(pd_addr)
                if pd:
                    _slot, upgrade_auth = layouts.parse_programdata(pd_addr, pd.data)
                    report.hook_upgradeable = upgrade_auth is not None
                    report.hook_upgrade_authority = upgrade_auth
                    if upgrade_auth:
                        holder = _classify(rpc, upgrade_auth)
                        findings.append(
                            Finding(
                                CRITICAL,
                                "Transfer hook program is UPGRADEABLE",
                                (
                                    f"The hook that runs on every transfer can be rewritten by "
                                    f"{upgrade_auth} ({_concentration_note(holder)}). A hook that "
                                    f"permits sells today can be swapped for one that blocks them."
                                ),
                                upgrade_auth,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                INFO,
                                "Transfer hook program is immutable",
                                "Its upgrade authority has been revoked, so the hook logic is fixed.",
                                report.hook_program,
                            )
                        )
            elif prog:
                report.hook_upgradeable = False
                findings.append(
                    Finding(
                        LOW,
                        "Transfer hook uses a non-upgradeable loader",
                        f"Hook program is owned by {registry.label_program(prog.owner) or prog.owner}.",
                        report.hook_program,
                    )
                )
        except (layouts.ParseError, ValueError) as exc:
            findings.append(
                Finding(LOW, "Could not resolve transfer hook program", str(exc), report.hook_program)
            )

    if not findings:
        findings.append(
            Finding(
                INFO,
                "No privileged authorities found",
                "Mint and freeze authorities are revoked and no hostile extensions are set.",
            )
        )

    findings.sort(key=lambda f: SEVERITY_RANK[f.severity])
    report.findings = findings
    report.rpc_calls = rpc.calls
    return report
