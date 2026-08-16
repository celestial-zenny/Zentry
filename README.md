# authgraph

**Map the transitive authority graph behind a Solana token — who can freeze you, seize your balance, mint against you, or block your sells.**

Every other token checker asks *"is `mintAuthority` null?"* and stops there. That question is too shallow to be useful, for two reasons:

1. **It ignores who holds the authority.** An authority on a bare keypair is one stolen key away from a drain. The same authority behind a multisig is a governance process. A null-check scores them identically.
2. **It ignores Token-2022 entirely.** Token Extensions introduced privileges with no EVM equivalent — `PermanentDelegate` can move *anyone's* tokens; a `TransferHook` runs arbitrary code on every transfer and can reject sells. And that hook program is usually **itself upgradeable**, so a hook that permits sells today can be swapped tomorrow.

`authgraph` resolves the whole chain: mint → every authority → what kind of account holds it → and for hook programs, onward to the ProgramData account to read *its* upgrade authority.

---

## It disagrees with null-checkers on real tokens

```
Token    Score    Why
BONK       0/100  mint + freeze authority both revoked
USDC      44/100  both authorities active, but held by program-owned multisigs
PYUSD    100/100  seven authorities on ONE bare keypair, incl. PermanentDelegate
```

USDC and PYUSD both carry full issuer privileges. A null-check rates them the same. `authgraph` shows that one keeps them behind multisigs and the other does not:

```
$ authgraph scan 2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo

╭───────────────────────────────── authgraph ──────────────────────────────────╮
│ 2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo                                 │
│ PYUSD (Paxos / PayPal)   ·   Token-2022   ·   678,763,765.2299 supply         │
╰──────────────────────────────────────────────────────────────────────────────╯
   DANGEROUS   risk score 100/100

severity    finding                                     why it matters
CRITICAL    Token-2022: PermanentDelegate               Can transfer or burn ANY
                                                        holder's tokens.
CRITICAL    Privileged authority is not behind a        freeze_authority,
            multisig                                    permanent_delegate held
                                                        by a single keypair.
HIGH        Mint authority is active                    Supply can be inflated.
HIGH        Freeze authority is active                  Blocks you from selling.

authority graph  (2b1kV6Dk…)
├── freeze_authority, permanent_delegate, mint_close_authority,
│   transfer_fee_config_authority, withdraw_withheld_authority, … →
│   2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk  single keypair
│   └── owned by System Program
└── mint_authority → 8Jornc27vtAYPkwDzsZVgLQchAYyC8nD7aCNPCDV8Qk2  program-owned
    └── owned by SPL Token-2022
```

> **A high score is not an accusation.** The score measures *holder-facing privilege*, not intent. PYUSD is a regulated stablecoin, and its freeze and clawback powers are deliberate compliance features — a regulated issuer is required to have them. What the tool tells you is what those authorities *can do to a holder*, and how concentrated they are. Read it as a capability map, never as a verdict on legitimacy.

---

## Install

```bash
git clone https://github.com/USER/authgraph.git
cd authgraph
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

On Debian-derived systems (Parrot, Kali, Ubuntu 23.04+) the system Python is
`EXTERNALLY-MANAGED` (PEP 668), so the venv above is required rather than
optional. To skip installing altogether, run it straight from a clone:

```bash
python3 -m authgraph scan <MINT>
```

Runtime deps are only `requests`, `rich`, and `typer` — no `web3`, no `solana-py`, no compiled extensions. The one RPC method it needs (`getAccountInfo`) requires **no API key** on the public mainnet endpoint.

## Usage

```bash
authgraph scan <MINT>                      # full authority report
authgraph scan <MINT> --json               # machine-readable
authgraph scan <MINT> --no-follow-hooks    # skip the transitive hook walk
authgraph scan <MINT> -c devnet            # or -c https://your-rpc.example
authgraph program <PROGRAM_ID>             # can this program be rewritten, and by whom?
authgraph health                           # is the RPC answering?
```

`authgraph program` is useful on its own. Note that the two token programs differ:

```
$ authgraph program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
   IMMUTABLE      # legacy SPL Token: upgrade authority revoked

$ authgraph program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
   UPGRADEABLE    # Token-2022: still rewritable by a single keypair
  upgrade authority : AeLmXCbPaQHGWRLr2saFsEVfmMNuKnxRAbWCT9P5twgz
```

### In CI

Exit codes make it gateable: **0** = below the risk threshold, **1** = at or above it, **2** = bad input or RPC failure.

```yaml
- run: authgraph scan ${{ env.MINT }}    # fails the job at score >= 40
```

## What it flags

| Signal | Severity | Why |
|---|---|---|
| `PermanentDelegate` | CRITICAL | Can transfer or burn **any** holder's tokens, forever |
| `DefaultAccountState = Frozen` | CRITICAL | New holders are frozen on arrival |
| `NonTransferable` | CRITICAL | Soulbound — can never be sold |
| `TransferFee` ≥ 50% | CRITICAL | Confiscatory |
| **Transfer hook program upgradeable** | CRITICAL | Sell-blocking logic can be swapped in later |
| Privileged authority on a lone keypair | CRITICAL / HIGH | One stolen key is enough |
| `mintAuthority` active | HIGH | Supply can be inflated, diluting you |
| `freezeAuthority` active | HIGH | Your account can be frozen |
| `TransferHook` with a program set | HIGH | Arbitrary code gates every transfer |
| `MintCloseAuthority` | MEDIUM | Mint can be closed at zero supply |
| `TransferFeeConfig` | MEDIUM | Fee is changeable by its authority |
| `InterestBearingConfig` | LOW | Displayed balance drifts from real balance |

### The authority-kind signal

Rather than ship an unverifiable allowlist of "known good" multisigs, `authgraph` **derives** concentration from the authority account's owner:

| Kind | Meaning | Risk |
|---|---|---|
| `single keypair` | System-owned — one private key | Highest |
| `no account on chain` | Bare keypair, unfunded; **can still sign** | High |
| `program-owned (PDA / multisig / governance)` | Controlled by program logic | Lower |
| `executable program` | The authority is a program | Context-dependent |

## How it works

Everything is parsed from raw account bytes — no ABI, no IDL, no indexer:

- **SPL Mint** (82 bytes) — `COption<Pubkey>` mint authority, supply, decimals, freeze authority.
- **Token-2022** — base mint padded to 165 bytes, `account_type` at `[165]`, then TLV extensions from `[166]`: `u16` type, `u16` length, value.
- **BPF upgradeable loader** — `Program` account (enum `2`) points at a `ProgramData` account (enum `3`), whose header carries the deployed slot and an `Option<Pubkey>` upgrade authority.

Extension IDs were verified against live mainnet accounts: the TLV walk over PYUSD lands exactly on the end of its 866-byte account, which a wrong table would not do.

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

33 tests, **no network access required.** Real mainnet accounts are captured as base64 in `tests/fixtures/accounts.json` and replayed offline; the transfer-hook escalation path is covered by synthetic accounts built from the same verified layouts, since hook-bearing mints are rare on mainnet.

## Limitations

Read these before trusting the output:

- **It is a capability map, not an audit.** It reports what authorities *can* do. It cannot tell a compliance control from a rug vector — that is your judgement call, which is why it shows you who holds what.
- **It does not inspect program logic.** For a transfer hook it reports *whether* the program can be replaced, not what the current bytecode does.
- **No liquidity or market analysis.** Nothing about LP locks, holder concentration, or trading behaviour.
- **`no account on chain` is not safe.** An unfunded authority still signs perfectly well.
- **The label registry is deliberately tiny.** Unlabelled is the normal case, not a warning.
- **Public RPC is rate-limited.** Pass `-c <your-rpc-url>` for volume.

## License

MIT
