"""CLI entrypoint. Rich rendering plus a --json mode and a CI-friendly exit code."""

from __future__ import annotations

import json
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from . import __version__, b58, graph, registry
from .extensions import CRITICAL, HIGH, INFO, LOW, MEDIUM
from .graph import ABSENT, PDA, PROGRAM, WALLET
from .layouts import TOKEN_2022_PROGRAM, ParseError
from .rpc import CLUSTERS, Rpc, RpcError

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

SEV_STYLE = {
    CRITICAL: "bold red",
    HIGH: "red",
    MEDIUM: "yellow",
    LOW: "cyan",
    INFO: "dim",
}
VERDICT_STYLE = {
    "DANGEROUS": "bold white on red",
    "HIGH RISK": "bold red",
    "CAUTION": "bold yellow",
    "MINOR NOTES": "cyan",
    "NO PRIVILEGED AUTHORITIES": "bold green",
}
KIND_STYLE = {WALLET: "red", ABSENT: "yellow", PDA: "green", PROGRAM: "cyan"}

# Exit non-zero at or above this score so CI can gate on it.
FAIL_SCORE = 40


def _render(report: graph.Report) -> None:
    m = report.mint
    prog = "Token-2022" if m.is_token2022 else "SPL Token"
    title = report.label or "unlabelled mint"

    console.print()
    console.print(
        Panel(
            f"[bold]{m.pubkey}[/bold]\n"
            f"{title}   ·   {prog}   ·   {m.supply_ui:,.4f} supply   ·   {m.decimals} decimals",
            title="authgraph",
            border_style="blue",
        )
    )

    style = VERDICT_STYLE.get(report.verdict, "white")
    console.print(f"  [{style}] {report.verdict} [/{style}]  risk score {report.score}/100\n")

    tbl = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    tbl.add_column("severity", width=9)
    tbl.add_column("finding", width=42)
    tbl.add_column("why it matters", overflow="fold")
    for f in report.findings:
        tbl.add_row(f"[{SEV_STYLE[f.severity]}]{f.severity}[/]", f.title, f.detail)
    console.print(tbl)

    if report.authorities:
        console.print()
        tree = Tree(f"[bold]authority graph[/bold]  ({m.pubkey[:8]}…)")
        for a in sorted(report.authorities.values(), key=lambda x: x.pubkey):
            ks = KIND_STYLE.get(a.kind, "white")
            node = tree.add(
                f"[bold]{', '.join(sorted(a.roles))}[/bold] → {a.pubkey}  [{ks}]{a.kind}[/{ks}]"
            )
            if a.owner:
                node.add(f"[dim]owned by[/dim] {a.owner_label or a.owner}")
        if report.hook_program:
            hook = tree.add(f"[bold]transfer hook[/bold] → {report.hook_program}")
            if report.hook_upgradeable is None:
                hook.add("[yellow]upgrade status unresolved[/yellow]")
            elif report.hook_upgradeable:
                hook.add(f"[bold red]UPGRADEABLE[/bold red] by {report.hook_upgrade_authority}")
            else:
                hook.add("[green]immutable[/green]")
        console.print(tree)

    console.print(f"\n[dim]{report.rpc_calls} RPC calls[/dim]\n")


def _as_dict(report: graph.Report) -> dict:
    m = report.mint
    return {
        "mint": m.pubkey,
        "label": report.label,
        "program": m.program,
        "is_token_2022": m.is_token2022,
        "supply": m.supply,
        "decimals": m.decimals,
        "mint_authority": m.mint_authority,
        "freeze_authority": m.freeze_authority,
        "verdict": report.verdict,
        "score": report.score,
        "extensions": [
            {
                "id": e.ext_id,
                "name": e.name,
                "severity": e.severity,
                "note": e.note,
                "authorities": e.authorities,
                "detail": e.detail,
            }
            for e in m.extensions
        ],
        "authorities": [
            {
                "pubkey": a.pubkey,
                "roles": sorted(a.roles),
                "kind": a.kind,
                "owner": a.owner,
                "owner_label": a.owner_label,
            }
            for a in report.authorities.values()
        ],
        "transfer_hook": {
            "program": report.hook_program,
            "upgradeable": report.hook_upgradeable,
            "upgrade_authority": report.hook_upgrade_authority,
        },
        "findings": [
            {"severity": f.severity, "title": f.title, "detail": f.detail, "subject": f.subject}
            for f in report.findings
        ],
        "rpc_calls": report.rpc_calls,
    }


@app.command()
def scan(
    mint: str = typer.Argument(..., help="Mint address (base58)"),
    cluster: str = typer.Option("mainnet", "--cluster", "-c", help=f"One of {', '.join(CLUSTERS)}, or an RPC URL"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a rendered report"),
    follow_hooks: bool = typer.Option(True, "--follow-hooks/--no-follow-hooks", help="Resolve transfer-hook upgrade authority"),
) -> None:
    """Scan a mint and map every authority that can act on holders."""
    if not b58.is_pubkey(mint):
        console.print(f"[bold red]error[/bold red] {mint!r} is not a 32-byte base58 pubkey")
        raise typer.Exit(2)
    try:
        rpc = Rpc(cluster)
        report = graph.analyse(rpc, mint, follow_hooks=follow_hooks)
    except (RpcError, ParseError, ValueError) as exc:
        console.print(f"[bold red]error[/bold red] {exc}")
        raise typer.Exit(2)

    if as_json:
        print(json.dumps(_as_dict(report), indent=2))
    else:
        _render(report)
    raise typer.Exit(1 if report.score >= FAIL_SCORE else 0)


@app.command()
def program(
    program_id: str = typer.Argument(..., help="Program ID (base58)"),
    cluster: str = typer.Option("mainnet", "--cluster", "-c"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Resolve a program's upgrade authority - can it be rewritten, and by whom?"""
    if not b58.is_pubkey(program_id):
        console.print(f"[bold red]error[/bold red] {program_id!r} is not a 32-byte base58 pubkey")
        raise typer.Exit(2)
    try:
        rpc = Rpc(cluster)
        rep = graph.resolve_program(rpc, program_id)
    except (RpcError, ParseError, ValueError) as exc:
        console.print(f"[bold red]error[/bold red] {exc}")
        raise typer.Exit(2)

    if as_json:
        holder = rep.authority_holder
        print(
            json.dumps(
                {
                    "program": rep.program,
                    "label": rep.label,
                    "loader": rep.loader,
                    "programdata": rep.programdata,
                    "deployed_slot": rep.deployed_slot,
                    "upgradeable": rep.upgradeable,
                    "upgrade_authority": rep.upgrade_authority,
                    "authority_kind": holder.kind if holder else None,
                    "authority_owner": holder.owner if holder else None,
                },
                indent=2,
            )
        )
        raise typer.Exit(1 if rep.upgradeable else 0)

    console.print()
    console.print(
        Panel(
            f"[bold]{rep.program}[/bold]\n{rep.label or 'unlabelled program'}   ·   "
            f"loader {registry.label_program(rep.loader) or rep.loader}",
            title="authgraph program",
            border_style="blue",
        )
    )
    if rep.upgradeable:
        holder = rep.authority_holder
        ks = KIND_STYLE.get(holder.kind, "white") if holder else "white"
        console.print("  [bold white on red] UPGRADEABLE [/bold white on red]")
        console.print(f"  upgrade authority : {rep.upgrade_authority}")
        if holder:
            console.print(f"  held as           : [{ks}]{holder.kind}[/{ks}]")
            if holder.owner:
                console.print(f"  authority owner   : {holder.owner_label or holder.owner}")
        console.print(f"  programdata       : {rep.programdata}")
        console.print(f"  deployed slot     : {rep.deployed_slot}")
        console.print("\n  [dim]The program's logic can be replaced by that authority at any time.[/dim]\n")
    else:
        console.print("  [bold green] IMMUTABLE [/bold green]")
        console.print("  No upgrade authority; this program's logic is fixed.\n")
    raise typer.Exit(1 if rep.upgradeable else 0)


@app.command()
def health(
    cluster: str = typer.Option("mainnet", "--cluster", "-c"),
) -> None:
    """Check that the RPC endpoint answers."""
    rpc = Rpc(cluster)
    console.print(f"{rpc.endpoint} → {rpc.health()}")


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"authgraph {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
