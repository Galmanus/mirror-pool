# riverrun

<p align="center">
  <img src="assets/banner.jpg" alt="riverrun — a glitched desert valley, the ledger's terrain scrambled" width="480">
</p>

> Built for the **`mirror-pool`** bounty — *Privacy-Through-Noise tooling for
> Solana*. *riverrun* is the first word of Joyce's *Finnegans Wake*, the river that
> flows in a circle back to its own beginning: a funding trail with no origin to trace.

[![Rust](https://img.shields.io/badge/Rust-end%20to%20end-000000?logo=rust)](https://www.rust-lang.org)
[![Solana](https://img.shields.io/badge/Solana-SBF%20program-14F195?logo=solana&logoColor=black)](https://solana.com/privacy)
[![tests](https://img.shields.io/badge/tests-99%20green-4c1)](#workspace)
[![CLI](https://img.shields.io/badge/CLI-preflight%20%C2%B7%20audit%20%C2%B7%20--json-14F195)](#the-tool-runs-today)
[![post-quantum](https://img.shields.io/badge/STARK-post--quantum%2C%20no%20setup-8A2BE2)](#why-post-quantum-and-transparent)
[![license](https://img.shields.io/badge/license-MIT-blue)](#license)

**A production tool that measures the real anonymity any Solana privacy pool gives you — before you trust it.**

Every privacy pool advertises `1/k`: k members, so a one-in-k guess. That number
counts members, and as a measure of anonymity it overstates, because it ignores
where the members' money came from — and on a public ledger, that is public.
`riverrun` is a finished CLI that reads public chain data and returns the anonymity
a pool *actually* delivers. Run against a live SOL pool on mainnet, the **30**
advertised members were worth an effective **6.5**, and one member, alone in the
origin of their money, was worth exactly **1**. It is protocol-agnostic — it works
against any pool it has never seen, including the other submissions in this bounty.

**Who it's for** — anyone who doesn't want to be an open book on-chain:
**algotraders** whose strategies get reverse-engineered · **whales** whose every move
is shadowed and front-run · **market makers** protecting flow and inventory ·
**protocols & agents** operating without broadcasting their playbook · **everyday
users** who simply don't want to be clustered and profiled. The privacy that used to
need a specialist, in one command.

### Install

```bash
# from a clone (installs the `riverrun` binary onto your PATH)
cargo install --path crates/riverrun-trace --features onchain

# or straight from git
cargo install --git https://github.com/solanabr/mirror-pool \
  --features onchain riverrun-trace
```

### Run it

The simplest question, *"am I exposed?"* — one command, one argument, your wallet:

```console
$ riverrun preflight <YOUR_WALLET>
```

It samples the pool, traces your funding graph against it, and answers in plain
words: **EXPOSED**, **WEAK**, or **OK** — with what to do about it. To score a whole
pool instead of one wallet:

```console
$ riverrun audit 9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD
=== funding-graph exposure of a live anonymity set ===
pool                   : 9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD
severity               : CRITICAL
depositors sampled     : 30
reach an origin        : 11/30 (37%)
advertised k           : 30  ->  effective k : 6.5  (worst case 1)
```

A set advertising 30 delivers an effective 6.5, and one member is alone in their
provenance class (`severity: critical` fires whenever any member is fully exposed).
Method and the arithmetic behind the number: [`docs/EFFECTIVE_K.md`](docs/EFFECTIVE_K.md).

Machine-readable, for pipelines and CI — and it reports its **own reliability**, so
a rate-limited or unreachable RPC can never be mistaken for a clean "private"
result. A real run just now, over the public mainnet-beta endpoint (verbatim, `jq`
selecting fields):

```console
$ riverrun audit 9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD 6 --json \
    | jq '{severity, advertised_k, effective_k, worst_case, reliable, rpc_failures}'
{
  "severity": "critical",
  "advertised_k": 6,
  "effective_k": 1.2599210498948732,
  "worst_case": 1,
  "reliable": false,
  "rpc_failures": 2
}
```

`reliable: false` because the public RPC rate-limited two calls: the tool marks the
result **partial** rather than silently reporting a smaller number as fact. Point
`$SOLANA_RPC` at a paid endpoint for a clean, complete run.

| command | what it answers |
|---|---|
| `preflight <wallet> [pool]` | the anonymity **you** would get in a pool, before you deposit |
| `audit <pool>` | a live pool's effective k vs the k it advertises, with a severity |
| `trace <wallet>` | one wallet's funding provenance, hop by hop |
| `exhibit` | the metric on riverrun's own constructions — offline, deterministic |

Global flags: `--json` (machine-readable on stdout, progress on stderr — `| jq` is
clean), `--version`. Exit codes: `0` ok, `1` no data (RPC unreachable **or** empty
pool — a network failure never reads as "private"), `2` bad usage or address.
Endpoint is `$SOLANA_RPC`, else mainnet-beta. Every live result is a **floor**:
a bounded, SOL-only trace, so "OK" means "no cheap attribution found", never
"anonymous".

**Two maturity levels, kept honest — and this is the whole story of the repo.**
The **measurement tooling** (`preflight` / `audit` / `trace` / `exhibit`) is
finished, machine-readable, and runs today against mainnet. *That is the
deliverable.* Behind it is a **research** pool — a post-quantum STARK that severs
the actor↔action link — that is implemented and tested but hand-rolled and
unaudited: a prototype, not for production, and marked as such wherever it appears.
Collapsing the two would be dishonest in both directions, so the repo never does.
Everything is Rust, MIT, **99 tests green**. See all of it in one command —
`./demo.sh` — or read the **[whitepaper (PDF)](paper/riverrun.pdf)**.

---

### The three things worth your 30 seconds

1. **The tool, and it runs today.** `preflight` / `audit` read public chain data and
   return the anonymity *you* would actually get in any pool — protocol-agnostic,
   `--json`, works against pools it has never seen. Measured live on mainnet:
   advertised **k=30**, effective **6.5**, worst case **1**.
   → [The tool runs today](#the-tool-runs-today) · [Your k is not your k](#your-k-is-not-your-k)
2. **Why that number is the whole story.** On a public chain, what identifies you is
   not the amount, it is *who* acted. The funding graph is public, so it collapses
   the anonymity that member-count hides — and almost nobody measures it.
   → [Your k is not your k](#your-k-is-not-your-k)
3. **The research behind the tool.** A post-quantum STARK pool (membership +
   nullifier + action in one proof, no trusted setup) and a **coordinator** agent
   that forms crowds maximizing effective-k. Implemented, tested, honestly marked a
   prototype. → [Security status](#security-status--honest-limitations)

**Contents:** [the tool](#the-tool-runs-today) · [the ruler](#your-k-is-not-your-k) ·
[pre-flight](#pre-flight-your-anonymity-before-you-act) ·
[the coordinator](#the-coordinator-an-agent-that-forms-private-crowds) ·
[who it's for](#who-this-is-for) · [the mechanism](#the-mechanism) ·
[post-quantum](#why-post-quantum-and-transparent) ·
[the adversaries](#the-privacy-is-proven-by-adversaries-in-this-repo) ·
[cost](#what-one-execution-costs) · [comparison](#how-this-compares) ·
[workspace & run it](#workspace) · [security status](#security-status--honest-limitations) ·
[related work](#related-work)

---

## The tool runs today

The deliverable is a finished CLI. No custody, no novel crypto on anyone's funds:
it reads public chain data and returns numbers, so it works against any pool in this
class — including ones it has never seen.

```bash
# your anonymity in a pool, before you deposit (the one to run first)
cargo run --features onchain --bin riverrun -- preflight <YOUR_WALLET> [POOL]

# a live pool's effective k vs the k it advertises
cargo run --features onchain --bin riverrun -- audit <POOL> 30

# one wallet's funding provenance, one hop at a time
cargo run --features onchain --bin riverrun -- trace <WALLET>

# the metric on riverrun's own constructions — offline, no RPC, deterministic
cargo run --features onchain --bin riverrun -- exhibit --json
```

Every command takes `--json` for a machine-readable result on stdout (progress stays
on stderr, so `| jq` is clean). Exit codes: `0` ok, `1` no data (RPC or empty pool),
`2` usage. Results from live data are a **floor**: a bounded, SOL-only backward
trace, so "OK" means "no cheap attribution found", never "anonymous". The offline
`exhibit` is deterministic and needs no network — the fastest way to see the metric:

```json
{
  "command": "exhibit",
  "constructions": [
    { "construction": "rooted_decoy",     "effective_k": 500.2 },
    { "construction": "cyclic_ambiguous", "effective_k": 2000.0 },
    { "construction": "cyclic_rootless",  "effective_k": 2000.0 }
  ]
}
```

Same 2000 members each row: decoys that still trace to one origin are worth 500;
circularity dissolves the origin and they are worth the full 2000. That is the idea
the next section measures on real money.

## Your k is not your k

Start here, because everything clever below is built on this one idea.

Every pool reports its privacy as `1/k`: there are `k` members, so a one-in-`k`
guess. **That number counts members, and it is wrong.** It ignores where the members'
money came from — and on a public ledger, that is public. Trace a member's wallet
backward and you often reach a known origin: an exchange, a service. Sort the crowd
by origin, and learning the actor's origin no longer leaves `k` suspects. It leaves
only the members who share it. The crowd you are hidden in is your *provenance
class*, not the whole set.

Nobody had measured this on Solana. We did, against a **live SOL privacy pool on
mainnet**, sampling 30 real depositors:

| | |
|---|---|
| reach an attributable origin | **11 / 30 (37%)**, mean **1.18 hops** |
| **advertised k** | **30** |
| **effective k** | **6.5** |
| **worst case** | **1** — one depositor alone in their provenance class |

```bash
cargo run --features onchain --bin riverrun -- audit <POOL> 30
```

A set advertising 30 delivers 6.5, and one member gets nothing at all. This is not a
flaw in that pool — no pool controls where its users' money came from, which is
exactly why the channel goes unmeasured and keeps working. The measure is the
effective anonymity-set size of Serjantov & Danezis (2002), and it runs on riverrun
too: the same 2000 members are worth **500** under the construction the field ships
and **2000** under circularity (a funding cycle with no origin — the *Finnegans Wake*
image, as a number). Method and the arithmetic that was wrong the first time:
**[docs/EFFECTIVE_K.md](docs/EFFECTIVE_K.md)**.

## Pre-flight: your anonymity, before you act

That measurement audits a pool. Turn it around and it **protects a user**. Before you
deposit into *any* pool, `preflight` traces *your* funding graph, samples the pool's
depositors, and tells you the anonymity *you* would get there:

```bash
cargo run --features onchain --bin riverrun -- preflight <YOUR_WALLET> [POOL]
```

It answers in plain words — *"7 of 9 share your provenance class — OK"*, or *"EXPOSED:
the pool's size is irrelevant to you; fund from a common origin, or wait for a
same-origin crowd."* It reads public chain data, not any pool's internals, so it
works against a program it has never seen — including the other repos in this bounty.
Auditing pools reaches auditors; protecting a user at the moment they act reaches
every user of every privacy protocol on the chain.
**[docs/PREFLIGHT.md](docs/PREFLIGHT.md)**.

## The coordinator: an agent that forms private crowds

If you can *measure* a crowd's anonymity, an agent can *form* a good one on purpose.
That is the coordination layer the brief asks for. The rule is backwards from
intuition until you see the formula: a crowd where everyone shares a funding origin
is **strong** (learning the origin narrows nothing — everyone's is the same); a crowd
of distinct origins is **weak** (the origin names the one member who has it). So the
agent groups members who share an origin and holds back the singletons who would be
exposed.

```bash
cargo run --release -p riverrun-trace --example coordinator
```

A *smaller* round, chosen well, beats batching everyone: a round of 8 at effective-k
4.1 versus a round of 10 at 3.1, with nobody exposed — proven by test, shown live.
And each round hands its members a **proof-carrying certificate** (the AXL pattern):
an admitted member re-verifies the round's anonymity themselves, trusting nothing the
agent said. Not "don't act" — "act in *this* crowd, and here is the proof it is
private." **[docs/COORDINATOR.md](docs/COORDINATOR.md)**.

---

## Who this is for

On a public chain your **behavior** is your fingerprint — when you act, how much,
what you buy — and it clusters you even when your name is hidden. riverrun severs
the **actor ↔ action** link so you act from inside a crowd wearing the same mask.
That serves anyone who doesn't want to be an open book on-chain:

- **Algotraders** whose strategies would otherwise be reverse-engineered.
- **Whales** whose every move is shadowed and front-run.
- **Market makers** protecting flow and inventory.
- **Protocols & agents** operating without broadcasting their playbook.
- **Everyday users** who simply don't want to be clustered and profiled — the
  privacy that used to require a specialist.

It hides *who did it*, which is orthogonal to and composes with value/recipient
confidentiality (the roadmap target is the author's Stellar rail **Vineland**,
which hides *how much / to whom* — not yet integrated).

---

## Why "riverrun" — and what the book gave us

*Finnegans Wake* (James Joyce, 1939) is a novel with **no beginning**. Its last
sentence breaks off mid-phrase — *"a way a lone a last a loved a long the"* — and
runs straight into its first word, *"riverrun."* The book is a circle. It is written
in a dream-language where every word carries many meanings at once, and it runs on
Giambattista Vico's idea that history moves in cycles that return to their start —
the pun *"a commodius vicus of recirculation"* hides Vico's name. Its river, Anna
Livia, flows to the sea and comes back as rain.

That is not decoration here. Three of the book's ideas are load-bearing:

- **A circle has no beginning.** The book's core structural fact — no origin, no
  source — is exactly the defense against the funding-graph attack. A funding trail
  that loops back on itself has no origin to trace, so an adversary who walks it
  backward never reaches an attributable start. The same 2000 members are worth
  **500** with an origin and **2000** without one — measured in
  [the ruler](#your-k-is-not-your-k).
- **The *ricorso* — the return that begins again.** Vico's fourth age restarts the
  cycle. riverrun borrows it to let the anonymity set be **reborn** each cycle, so a
  member's history stops accumulating and no one is linked across epochs
  (whitepaper §5).
- **Irreducible polysemy.** In the book, a word doesn't hide its "real" meaning — it
  *has* no single one; every reading is valid, none privileged. That is the
  **ambiguous-origin** construction: the funding trail reaches *many* origins, none
  privileged, so "which is the real one" is **undefined**, not hidden. We measure
  **2.90 bits** of doubt about which, at full effective-k. And it is the *robust*
  version: "no origin" (the circle above) is an idealization that, the moment one
  funding source is a known exchange, degrades exactly to this — ambiguity is where
  the defense actually lives.
- **Here Comes Everybody.** The book's protagonist, HCE, is at once one man and
  everyone — an identity that dissolves into the crowd. That is the anonymity set:
  you act as *everybody*, and which one you are is undecidable.
  *(Disanalogy: HCE is a single dream-figure who is everyone; here there are many
  real members, and the cryptography makes which one acted genuinely undefined, not
  merely hidden.)*

---

## The mechanism

The flow mirrors Tornado, but the payload is a **behavior**, not a fund transfer:

1. **Commit** (the "deposit"). A member publishes `C = H(secret ‖ action)` into
   the pool's Merkle set. This registers *"some member of this set intends action
   A"* — without revealing who.
2. **Execute** (the "withdrawal" / *saque*). Later, ideally in a synchronized
   round of identical actions, action `A` is performed from a fresh identity with
   a zero-knowledge proof: *"I know a `secret` whose commitment `H(secret‖A)` is
   in the set, and my nullifier this round is `n`."* The action is public; the
   author is not.
3. **Settle.** The pool verifies the proof, checks the nullifier is fresh (one
   execution per member per round — anti-replay), spends it, and releases the
   action. The public transcript is `{root, action, nullifier}` with no link back
   to a commitment.

Run it — `cargo run --manifest-path crates/riverrun-pool-zk/Cargo.toml --example behavior_pool --release`:

```
committed members : 4
set root          : 25c8d68dde1c377d…

synchronized round — public transcript the observer sees:
#     action (public)       nullifier           proof
------------------------------------------------------------------
1     5741524448544957…     f581d90d496307d1…   12503 B
2     5741524448544957…     89df1399c83ef190…   11445 B
3     5741524448544957…     5b1bfe289200b40e…   11605 B
4     5741524448544957…     4cabddd8e0f0a6b3…   11767 B

An observer's chance of mapping any execution to its author is 1/4.
double execution, same round  -> NullifierSpent
action the member never committed -> BadProof
```

Both guards are enforced by the proof, not by a field comparison: the leaf is
`Rescue(secret, action)` and the action is a public input, so swapping the action
makes the STARK fail to verify.

Same action, distinct nullifiers, one root. The nullifier is `Rescue(secret‖round)`
— unlinkable to any commitment. Grow the set to `k` and the actor↔action link is
`1/k`, by construction. (`crates/riverrun-pool-zk/src/lib.rs`)

## Why post-quantum — and why that means *now*

This is the one property riverrun has that a pairing-based design cannot retrofit,
and the reason it has to be built today rather than "when quantum arrives."

**A blockchain is a permanent, public record.** Every commitment, every nullifier,
every action is written down forever. So consider *harvest now, decrypt later*: an
adversary records the chain today and waits. The day a cryptographically-relevant
quantum computer exists, it turns that saved copy over and breaks every privacy
guarantee that rested on elliptic curves — **retroactively**, on activity that is
years old. Migrating to post-quantum crypto *after* the machine exists does nothing,
because the data was already harvested. For a ledger that never forgets, behavioral
privacy has to be post-quantum **from the first transaction**.

riverrun's whole core — commitment, Merkle set, nullifier, membership relation — is
one collision-resistant hash (Rescue-Prime, FRI). No pairings, no elliptic curves in
the property that hides *who acted*, no trusted setup, no per-circuit ceremony. A
future quantum computer **cannot retroactively unmask** a past actor, because the
hiding rests on hashes, which Shor's algorithm does not break.

**The honest boundary, stated so it can't be used against us.** The interim on-chain
attestation is an Ed25519 signature, which is *classical*. But it protects
**soundness** (that a valid membership proof existed), not **anonymity**. A quantum
computer that broke Ed25519 could *forge* an attestation — a liveness/soundness
failure — but it still could not say *which member* acted, because that is hidden by
the hash layer, not the signature. So the precise claim is exact and defensible:
**riverrun's anonymity is post-quantum; no future quantum computer retroactively
unmasks who acted.**

The tradeoff is real and named: hash-based STARKs mean bigger proofs than Groth16,
and higher on-chain verification cost (the M31 port in [What one execution
costs](#what-one-execution-costs) is how that shrinks). Pairing-based designs get
small proofs by resting privacy on elliptic curves and a ceremony — a fine trade for
data that is *not* meant to outlive the decade on a permanent ledger. riverrun takes
the other side on purpose.

## The privacy is proven by adversaries in this repo

The discipline: **build the attacker; the defense is its dual.** You cannot
credibly claim privacy against an attack you never ran.

- **Behavioral channel** (`cargo run -p riverrun-eval`). A clustering attacker that
  fingerprints wallets by co-buy timing and position sizing — the real Solana
  signal. Against a synchronized round of identical actions it collapses to
  chance: **12.5% attribution at k=8, 1.5% at k=64** (= `1/k`). Same attacker,
  same population; the only difference is the pool.

- **Provenance channel** (`riverrun exhibit`). The leak every noise tool
  leaves open: trace a wallet's funding *backward* and reach an attributable
  origin. The `provenance-tracer` measures it, and — proven on **live mainnet** —
  a shallow, SOL-only walk names an origin for a real user wallet in **two hops**.
  The repo also ships the *defense*: a cyclic-provenance construction that drives
  the tracer's root-hit rate to 0 (or dissolves *which* origin across many, 2.9
  bits of ambiguity). This axis is hard for every noise-based design, riverrun
  included — the contribution here is measuring it rather than assuming it away,
  and the same ruler now runs against **live pools**, not only this repo's
  constructions. See [Your k is not your k](#your-k-is-not-your-k).

## What one execution costs

`cargo run --release --manifest-path crates/riverrun-stark/Cargo.toml --example bench`

| set size | proof | prove | verify | setup artifacts |
|---:|---:|---:|---:|---:|
| 4 | 11,929 B | **2.0 ms** | 0.20 ms | **0 bytes** |
| 64 | 17,045 B | **3.7 ms** | 0.35 ms | **0 bytes** |
| 16,384 | 19,064 B | **8.1 ms** | 0.43 ms | **0 bytes** |

An anonymity set of **16,384 members** proves in **8 milliseconds**. Proof size
grows logarithmically — 4096× the members costs 1.6× the proof.

The column that decides whether this is deployable is the last one. A
pairing-based system needs a proving key produced by a ceremony and shipped to
every client; for a Merkle circuit of this depth that is tens of megabytes of
setup which must exist, be trusted, and be distributed before anyone can prove
anything. riverrun's prover is the code. For the audience the brief names —
agents, market makers, ordinary users proving before each action — that is the
difference between a tool that ships and one that needs an install.

The honest other side: 12–19 KB does not fit in a 1,232-byte Solana transaction,
which is why the proof is verified off-chain today. Both halves of that trade are
in Security status.

## How this compares

Honest placement, because a reader deserves to know what riverrun is *not*. Every
row here is a real system, and each is better than riverrun at what it was built
for.

| approach | hides | on-chain verification | trusted setup | post-quantum |
|---|---|---|---|---|
| **Groth16 on Solana** (`groth16-solana`, Light/Helius) | whatever the circuit says | yes, ~250k CU, 256-byte proof | **yes, a ceremony** | no (BN254) |
| **Circle STARK** ([murkl](https://github.com/exidz/murkl)) | transfers, in anonymous pools | yes, ~31k CU, ~8.7 KB proof | no | yes |
| **MPC / FHE** ([Arcium](https://www.arcium.com/), Umbra) | shared encrypted state, balances, amounts | via the MXE network | no | depends on the primitive |
| **Confidential Transfers** (Token-2022) | amounts and balances | native, protocol level | no | no (ElGamal) |
| **riverrun** | the **actor↔action link** — who did it, not what or how much | **no**, an M-of-N committee attests | no | yes (hash-based) |

Efficiency cuts both ways and it is worth being exact about which way. On
**verification compute**, a small-field STARK is the cheapest thing on this list:
murkl verifies at ~31k CU, against ~250k CU for a Groth16 verifier — 8× cheaper,
post-quantum, and with no ceremony. On **proof size**, Groth16's 256 bytes beats
every STARK here by two orders of magnitude, and that is what buys it a
single-transaction verification path. On **prover cost and setup**, riverrun wins
outright: 8 ms for a 16,384-member set and nothing to distribute.

Read the last row honestly. riverrun is the only one whose payload is *behaviour*
rather than value, which is what the `mirror-pool` brief asks for, and it needs no
ceremony. It is also the only one that does not verify its proof on-chain, and
that is a real deficit, not a design preference — see Security status for the
correction on why, and the roadmap for the path.

The comparison that matters most is with the Circle STARK work: it demonstrates
that transparent, post-quantum, on-chain verification is *available today* on
Solana at 31k CU. riverrun proves a different statement, but there is no excuse
left for proving it off-chain forever.

## Cost — cheap by construction

Because riverrun hides *behavior* and not funds, its on-chain footprint is a
**17-byte nullifier account** and an event — no value moves, so a private action is
on the order of **$0.0002**.

**Proven live on devnet, on the current M-of-N committee code** (program
`BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az`, pool
`CoSHQ1rFvBe6hVzCWKyqDUGdbyGftWxByiuueDp1GnLH`). The full behavioral-cloak lifecycle
ran end to end with four distinct roles — authority, verifier, member, relayer —
kept separate on purpose, because the claim *is* who signs what:

| step | signed by | signature |
|---|---|---|
| `commit` | the **member** | [`4jdxSfVe…`](https://explorer.solana.com/tx/4jdxSfVedXG723C6vP3RCJmDMfrsitXkzkKF6ydSBPxBV7mdPoYzLfdYyoCaVjnjwrnQKqz4rFfvaNe314VULzqx?cluster=devnet) |
| **`execute`** | the **relayer alone** | [`23Uz6pjh…`](https://explorer.solana.com/tx/23Uz6pjh4Bqb6pQjMHpwKESzdNddy8bmZ9mMedm5hQHFCXFKyJLKTRggyGs1Xdghbo5zvP237D9Tcgwv9EGLFi25?cluster=devnet) |
| `execute` (double-spend) | rejected on-chain | nullifier PDA already exists |

Open the `execute` transaction and check the signer set: it is the **relayer** only.
The member's key signed `commit` (joining the crowd) and **nothing else** — it is
absent from the action itself. That is the behavioral cloak, on a permanent public
ledger, verifiable by anyone. Reproduce: `cargo run --manifest-path
programs/mirror-pool/Cargo.toml --example devnet_demo`.

## Workspace

| crate | what it is | status |
|---|---|---|
| `riverrun-core` | the post-quantum primitives and the membership *relation* (commitment, Merkle set, nullifier). Specification only — nothing here proves anything | 19 tests |
| `riverrun-eval` | adversarial harness for the behavioral channel — clustering attacker → chance | 4 tests + exhibit |
| `riverrun-trace` | the `provenance-tracer`: backward funding-graph adversary + circularity defense + live-mainnet adapter | 7 tests + 2 exhibits |
| `programs/mirror-pool` | the on-chain Solana program: commitment accumulator, per-round nullifier registry (PDA-per-nullifier anti-replay), published root, verifier-attested settlement, entry fee + anonymity-set floor | builds to `.so`; 15 e2e tests green (10 committee-of-one for back-compat + 5 M-of-N quorum); **the current committee code is deployed and exercised live on devnet** (full commit + relayer-execute lifecycle, [signatures](#cost--cheap-by-construction)) |
| `crates/riverrun-stark` | the post-quantum, transparent **STARK proving the whole relation** — membership, nullifier and action in one proof (Rescue-Prime + FRI, no trusted setup) — plus the ricorso primitives and relation | 23 tests green (excluded — pulls Winterfell) |
| `crates/riverrun-pool-zk` | **the** pool: commit → execute → settle driven by the STARK. `Execution` carries an opaque proof + public data only, never the secret | 7 tests + demo (excluded — pulls Winterfell) |

**Everything this repo claims, in one command:**

```bash
./demo.sh          # offline stages, ~1 min
./demo.sh --live   # also measures a live mainnet pool, ~5 min
```

It runs the suites, the mechanism, both adversaries, the ruler, and — if the SBF
toolchain is present — builds the on-chain program and runs its e2e tests. Every
stage prints numbers; where a number is a floor rather than a result, the stage
says so.

Or piece by piece:

```bash
cargo test --workspace                                            # 34 tests green
cargo run --manifest-path crates/riverrun-pool-zk/Cargo.toml \
  --example behavior_pool --release                                # the mechanism
cargo run -p riverrun-eval                                        # behavioral deanon → chance
cargo run -p riverrun-trace --features onchain --bin riverrun -- exhibit  # provenance: field vs circularity
# the unified CLI — one binary, four verbs (needs --features onchain for live data):
cargo run -p riverrun-trace --features onchain --bin riverrun -- help
cargo run -p riverrun-trace --features onchain --bin riverrun -- preflight <WALLET>  # your anonymity before you act
cargo run -p riverrun-trace --features onchain --bin riverrun -- audit <POOL> 30      # a pool's effective k
cargo run -p riverrun-trace --features onchain --bin riverrun -- trace <WALLET>       # one wallet's provenance

# on-chain program (needs the Solana SBF toolchain):
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml            # → deployable .so
cargo test --manifest-path programs/mirror-pool/Cargo.toml --test e2e      # on-chain lifecycle e2e
cargo test --manifest-path crates/riverrun-stark/Cargo.toml                # STARK: membership + nullifier binding
cargo test --manifest-path crates/riverrun-pool-zk/Cargo.toml              # the pool driven by the STARK
```

**99 tests green** in total: 50 host + 27 STARK + 7 pool-zk + 15 on-chain e2e.

## Security status & honest limitations

This repo is two things with two different maturity levels, and collapsing them
would be dishonest in both directions.

**Runnable today, against mainnet, by anyone: the measurement tooling.**
The `riverrun` CLI (`preflight` / `audit` / `trace` / `exhibit`) is a finished tool.
They take a pool program or an address, read public chain data, and return
numbers. They do not depend on riverrun's cryptography and work against any
construction in this class — including the other repos in this bounty when they
ship theirs. If you take one thing from here, take the ruler.

**Research, and not to be deployed: the pool itself.** The cryptography is
implemented and tested, but the AIR is hand-rolled and unaudited, and one gap
below is a trust assumption rather than a proof.

> **The pool is a research prototype — NOT production-ready, NOT audited.** An
> internal adversarial audit (see below) found gaps that mean the *shipped* pool
> does not yet protect a real user. Current state:
> 1. **In `riverrun-pool-zk`, membership and the nullifier are now one proof.**
>    The `Execution` carries an opaque STARK plus public data only — the secret
>    never leaves the prover — and the AIR witnesses both membership under the root
>    *and* that the revealed nullifier `Rescue(secret, round)` came from that same
>    secret. Pairing a valid membership proof with a chosen nullifier no longer
>    verifies, so "one action per member per round" is enforced cryptographically.
>    Two things this does **not** mean: the AIR is hand-rolled and unaudited
>    (passing negative tests are necessary, not sufficient, for soundness).
>    There is no longer a second, non-hiding pool: the reference proof that
>    carried the witness in the clear has been deleted, and `riverrun-core` is now
>    primitives and the relation only.
>
>    The **action is bound too**: the leaf is `Rescue(secret, action)` and the
>    action is a public input of the same proof, so a member executes the intent
>    they registered and not another. Public inputs are
>    `{root, nullifier, round, action}`.
> 2. **On-chain, `execute` requires an M-of-N verifier *committee* attestation —
>    but it still does not verify the proof itself.** The pool names a **committee**
>    of verifier keys and a threshold **M**, and an execution must carry Ed25519
>    signatures from at least M **distinct** committee members (checked through the
>    native sigverify precompile and instruction introspection) over exactly the
>    `(pool, root, action, nullifier, round)` being settled, where `root` must be
>    the one the authority published for the round. An arbitrary signer can no
>    longer settle an action, and a watcher can no longer front-run a nullifier out
>    of the mempool. **This is a named, quorum-bounded trust assumption, not
>    soundness:** a false attestation now requires **M colluding verifiers**, not
>    one. This is the Wake's Four (Mamalujo) — the annalists who judge as a quorum,
>    none authoritative alone — read out of the book and built
>    ([docs/FINNEGANS_WAKE_STUDY.md](docs/FINNEGANS_WAKE_STUDY.md)).
>
>    Why not verify on-chain — and the honest correction. An earlier version of
>    this README said on-chain STARK verification does not fit on Solana. **That
>    was wrong, and it has been done**, including with Winterfell, the library
>    this repo uses:
>
>    - *Full L1 On-Chain ZK-STARK+PQC Verification on Solana* ([eprint
>      2025/1741](https://eprint.iacr.org/2025/1741)) adapts Winterfell 0.12 with
>      SHA-256 routed to the `hashv` syscall, inlining suppressed in the FRI
>      hotspots for SBF stack limits, and a custom bump allocator. Measured on
>      devnet over n=100: `verify_stark` **mean 1.10M CU, max 1.19M**, inside the
>      1.4M budget, for a **4,437-byte** proof (~249 CU per proof byte).
>    - **murkl** ships a Circle STARK verifier as a general-purpose CPI target:
>      ~8.7 KB proof, **~31k CU**, M31/QM31, 128-bit post-quantum.
>    - **mosaic** (wienerlabs) implements FRI-STARK verification **chunked across
>      transactions** with a resumable verifier and a checkpoint state machine,
>      validated end to end on SBF.
>
>    And it is no longer unmeasured for *this* repo either. `programs/stark-verifier`
>    runs riverrun's real verifier on SBF and prices it: **3.77M CU at k=4, 7.13M
>    CU at k=64** (`cargo test --manifest-path programs/stark-verifier/Cargo.toml
>    --test cu`). Both exceed the 1.4M per-transaction cap, so it needs chunked
>    execution across transactions — which is exactly what mosaic implements. The
>    number is consistent with eprint 2025/1741's 1.1M CU for a 4.4 KB proof: we
>    spend 3.4x the CU for a 2.7x larger proof.
>
>    So the blocker is not feasibility, it is *this repo's choices*. Our proof is
>    **12,057–16,536 bytes** against a 1,232-byte transaction limit, because the
>    AIR is a Rescue-Prime Merkle path over the 128-bit field rather than a
>    minimal AIR over a 31-bit one. The path forward is a smaller field and a
>    cheaper hash — Circle STARK over M31 verifies at ~31k CU (murkl), inside one
>    transaction. It is a field change, not a possibility proof, and it needs no
>    trusted setup.
>
> 3. **The anonymity set is priced, not protected.** `commit` charges an
>    `entry_fee` and `execute` refuses to settle below a `k_min` floor, so
>    inflating the set from k to k+m costs m·fee instead of nothing and a set of
>    one cannot be settled against. That prices Sybil inflation; it does not
>    prevent it. An attacker with money still buys k. What is new here is that the
>    same repo can *measure* the cheap version of that attack: sybils have to be
>    funded, and funding is what `pool-provenance` reads — the live scan already
>    reports shared-funder collisions across a real depositor population.
>
>    The better construction is known and not implemented here. Anonymous
>    Self-Credentials ([eprint 2025/618](https://eprint.iacr.org/2025/618)) gets
>    Sybil resistance cryptographically rather than economically: one nullifier
>    per verifier, so a master identity registers exactly one pseudonym per pool,
>    with nullifiers across pools unlinkable. One seat per identity, enforced,
>    instead of one seat per fee paid. See
>    [docs/RELATED_WORK.md](docs/RELATED_WORK.md).
>
> Closing #2 properly (verify a proof on-chain, whether chunked STARK or a
> pairing-based verifier via `alt_bn128`), plus decentralized round progression,
> 128-bit STARK parameters, and a multisig/renounced upgrade authority, is what
> production would require. Do not deploy this to guard real funds or identities until then.

A threat model is only useful if its assumptions are on the table, so here are
ours.

- **The proof keeps the witness off the wire, but it is not formally
  zero-knowledge.** Winterfell 0.13 has no witness randomization, so the honest
  claim is "the secret does not appear in the transmitted proof" — checked over 20
  proofs, not proven. That check earns its keep: the first version of the binding
  AIR held the secret in a column that was constant across the trace, and since a
  constant column has a constant low-degree extension, the secret landed in every
  FRI opening — 20 leaks out of 20. Confining it to the rows where it is
  load-bearing fixed that (0 out of 20).
- **Negative tests can be decorative.** The public-input rejection tests here pass
  even with the binding constraint deleted, because the boundary assertions alone
  reject them. The test that actually guards the binding builds the trace an
  attacker would want — hash one secret, carry another member — and deleting the
  constraint was checked to make it fail.

  The action binding repeated the lesson exactly. Announcing a different action in
  the public inputs is rejected even with **no** action constraint at all, because
  the action feeds the Fiat-Shamir transcript — the first two tests written for it
  stayed green through the mutation, which is how they were caught being useless.
  The real attack hashes the committed action into the leaf, so the Merkle path
  still resolves, while announcing a different one; deleting the constraint makes
  that forged proof verify. Every claim of the form "X is bound" in this repo has
  a test that was checked to fail without the constraint it claims to test.
- **The mainnet provenance trace is shallow** — SOL-only, depth-bounded. It
  *under*-reports the leak. Hub labels are an activity heuristic standing in for a
  real tag database (Arkham/Chainalysis); no CEX addresses are fabricated.
- **"Rootless" provenance assumes unattributable funding.** One known CEX entry
  degrades it to "ambiguous origin" — still a large win, but a measured, smaller
  one.
- **Consensus forces one settlement.** Value moves one way; you cannot make the
  ledger a cycle. Circularity and exchangeability live on the attribution/ownership
  layer the analyst reads, not the value layer consensus enforces.

## Related work

riverrun's *goal* is not new — hiding which member of a set acted is anonymous
authentication, and PrivDID, anonymous credentials and PLUME's deterministic
nullifiers all live there. The effective-k metric is Serjantov & Danezis (2002).
Measuring advertised-versus-true anonymity is an established programme on
Ethereum (Tutela, Béres et al., the 2025 cross-chain Tornado study). On-chain
STARK verification on Solana has been done, including with Winterfell.

What is narrowly different here is the payload — behaviour rather than value —
and that the funding graph is measured rather than assumed away, on riverrun's
own constructions as well as other people's. The full accounting, including what
the literature says this repo's anti-Sybil *should* be:
**[docs/RELATED_WORK.md](docs/RELATED_WORK.md)**.

## Roadmap / research directions

- **Verify the proof on-chain, and stop trusting the verifier.** This is the top
  of the list, and the prior art says how. eprint 2025/1741 verifies a Winterfell
  STARK on Solana L1 at ~1.1M CU for a 4.4 KB proof; murkl does a Circle STARK at
  ~31k CU over M31; mosaic chunks FRI verification across transactions with a
  resumable verifier. The work for riverrun is to get our proof small and cheap
  enough to follow them: **move off the 128-bit field**, which is what makes both
  the proof (12–16 KB) and the per-operation cost large. A Circle STARK over M31
  with a keccak or `hashv`-routed transcript is the concrete target. Nothing here
  needs a trusted setup.
- An independent review of the hand-rolled AIR. Negative tests passing is
  necessary, not sufficient.
- Longer-running / Surfpool soak of the on-chain program (already deployed and
  exercised on devnet; in-process e2e passes).
- **LWE-hard cover** — anchor indistinguishability on Learning-With-Errors so
  separating real from cover is provably as hard as worst-case lattice problems
  (measured → *provable* privacy). Paper track.
- **Provenance flow** — a monotone privacy functional (a Perelman-style Lyapunov
  quantity) under which any trace flows to a canonical, indistinguishable form.
  Paper track.

## References

Nothing here is claimed from nowhere. The metric, the primitives, the on-chain
verification, and the systems riverrun is measured against are all public work;
where riverrun is behind the state of the art, the reference says so. Full
accounting in [docs/RELATED_WORK.md](docs/RELATED_WORK.md) and
[docs/EFFECTIVE_K.md](docs/EFFECTIVE_K.md).

**Anonymity metrics & mixer de-anonymization**
- Serjantov & Danezis, *Towards an Information Theoretic Metric for Anonymity*,
  PET 2002 (Outstanding Paper) — the effective anonymity-set size `effective_k`
  implements. <https://bib.mixnetworks.org/pdf/serjantov2002towards.pdf>
- Wu et al., *Tutela: Assessing User-Privacy on Ethereum and Tornado Cash*,
  arXiv:2201.06811 — true-vs-advertised pool size. <https://arxiv.org/abs/2201.06811>
- Béres et al., *Blockchain is Watching You: Profiling and Deanonymizing
  Ethereum Users*, arXiv:2005.14051. <https://arxiv.org/abs/2005.14051>
- *Clustering Deposit and Withdrawal Activity in Tornado Cash*, arXiv:2510.09433
  (2025) — 20–35% of withdrawals linked cross-chain. <https://arxiv.org/abs/2510.09433>
- Du et al., *Breaking the Anonymity of Ethereum Mixing Services Using Graph
  Feature Learning*, IEEE TIFS 2024. <https://doi.org/10.1109/TIFS.2023.3326984>

**Nullifiers & anonymous authentication**
- Gupta & Gurkan, *PLUME: An ECDSA Nullifier Scheme*, ePrint 2022/1255 —
  formalizes the deterministic nullifier riverrun uses. <https://eprint.iacr.org/2022/1255>
- *PrivDID*, ePrint 2026/127 — session unlinkability, no trusted setup.
  <https://eprint.iacr.org/2026/127>
- *Anonymous Self-Credentials*, ePrint 2025/618 — one-nullifier-per-verifier
  Sybil resistance, the anti-Sybil riverrun's `entry_fee` *should* become.
  <https://eprint.iacr.org/2025/618>
- *Formalizing Privacy of Anonymous Credentials: A Provably Secure Framework with
  Predicate Proofs*, ePrint 2026/1373 — the identity/credential-privacy threat
  model riverrun works in. <https://eprint.iacr.org/2026/1373>
- *Re2creds: Reusable Anonymous Credentials*, ePrint 2026/119 — reusable
  presentations without linkage. <https://eprint.iacr.org/2026/119>

**On-chain STARK verification on Solana** (the roadmap, with numbers)
- Yano, *Full L1 On-Chain ZK-STARK+PQC Verification on Solana: A Measurement
  Study*, ePrint 2025/1741 — a Winterfell STARK on L1 at ~1.1M CU / 4.4 KB proof.
  <https://eprint.iacr.org/2025/1741>
- **murkl** — Circle STARK verifier as a Solana CPI target, ~31k CU over M31,
  post-quantum. <https://github.com/exidz/murkl>
- **mosaic** (Wiener Labs) — trait-based on-chain verifier lib; chunked FRI-STARK
  across transactions. <https://github.com/wienerlabs/mosaic>

**Proving stack & fields**
- Szepieniec, Ashur & Dhooghe, *Rescue-Prime: a Standard Specification (SoK)*,
  ePrint 2020/1143 — the arithmetization-oriented hash the AIR computes in-circuit.
  <https://eprint.iacr.org/2020/1143>
- **Winterfell** — the STARK prover/verifier riverrun builds on (Rescue-Prime
  Merkle AIR, f128). <https://github.com/facebook/winterfell>
- **Plonky3** — small-field toolkit, HVZK work. <https://github.com/Plonky3/Plonky3>
- **Stwo / S-two** (StarkWare) — production Circle STARK over M31, the target
  field for a cheap on-chain port. <https://github.com/starkware-libs/stwo>

**Solana privacy ecosystem** (what riverrun is placed against)
- Confidential Transfers (Token-2022) — native encrypted amounts.
  <https://solana.com/privacy>
- `groth16-solana` (Light Protocol / Helius) — the one production ZK verifier on
  Solana today. <https://github.com/Lightprotocol/groth16-solana> ·
  [Helius acquires Light](https://www.helius.dev/blog/light-protocol-acquisition)
- **Arcium** — MPC/FHE confidential compute, C-SPL. <https://www.arcium.com/>
- **Umbra** — Arcium-based shielded pool. <https://sdk.umbraprivacy.com/introduction>
- **Privacy Cash** — the live SOL pool `riverrun audit` measures
  (`9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD`).
  <https://github.com/Privacy-Cash/privacy-cash>

**The bounty & the name**
- Superteam Brazil, *Build Privacy-Through-Noise tooling for Solana*.
  <https://github.com/solanabr>
- Joyce, *Finnegans Wake* (1939) — "riverrun, past Eve and Adam's, by a commodius
  vicus of recirculation"; Vico's cycle is the *ricorso* the set-rebirth borrows.

## License

MIT. Portions of the STARK AIR are adapted from the Winterfell `merkle` example
(MIT, Meta). See individual file headers.
