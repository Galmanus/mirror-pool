# riverrun

> The submission for the **`mirror-pool`** bounty ("Tornado cash for synchronized
> actions"). *riverrun* is the first word of Joyce's *Finnegans Wake* — the river
> that flows in a circle back to its own beginning. That circle is the system's
> core defense: a funding trail with no origin to trace.

**Tornado Cash for behavioral patterns and actions — not funds.**

Tornado Cash breaks the link between a *deposit* and a *withdrawal* of money.
`riverrun` breaks the link between a **committed intent** and an **executed
action**: a swap, a claim, a vote, a withdrawal from a protocol. Amounts are
neither hidden nor the point — what is severed is the **actor ↔ action** link, the
thing modern chain-analysis clusters on. Post-quantum and transparent: built from
hashes, no trusted setup, no ceremony.

Everything here is Rust, MIT, and runs today. Rather than assert the privacy
claims, the repo ships the adversaries that check them — one of them run against
live Solana mainnet. Where a claim doesn't hold yet, it's written down in
[Security status](#security-status--honest-limitations).

## Your k is not your k

Every pool in this space reports `1/k`. That number counts members. It says
nothing about where those members' money came from, and on a public ledger that
is public. Sort a set into classes by funding provenance and learning the actor's
class leaves only that class to guess within.

Nobody had measured it. Run against a **live Tornado-style SOL privacy pool on
Solana mainnet**, sampling 30 real depositors:

| | |
|---|---|
| reach an attributable origin | **11 / 30 (37%)**, mean **1.18 hops** |
| **advertised k** | **30** |
| **effective k** | **6.5** |
| **worst case** | **1** — one depositor alone in their provenance class |

```bash
cargo run --features onchain --bin pool-provenance -- <POOL_PROGRAM_ID> 30
```

This is not a flaw in that pool: no deposit-pool design controls where its users'
money came from, which is exactly why the channel goes unmeasured and keeps
working. It applies to riverrun too — so the same ruler runs over riverrun's own
constructions, where the same 2000 members are worth **500** under the
construction the field ships and **2000** under circularity. Method, caveats and
the arithmetic that was wrong the first time: **[docs/EFFECTIVE_K.md](docs/EFFECTIVE_K.md)**.

---

## What you can actually do with it — and why it matters to a real person

On a public chain, *everything you do is watched and tied back to you* — not by
your name, but by your **behavior**: when you act, how much, what you buy, who you
follow. That fingerprint lets an employer, a stalker, a scammer, a data broker, or
a hostile government profile you from your on-chain life. Today, strong on-chain
privacy is a luxury for the technical and the wealthy.

`riverrun` gives that privacy to an ordinary person. You do the *same* action —
get paid, save, claim an airdrop, vote in a DAO, trade — but the link between
**you** and **what you did** is cut. You act from inside a crowd wearing the same
mask.

- **A worker paid in crypto** is no longer profiled by their salary and every
  purchase that follows it.
- **A saver** isn't marked as a target the moment a scammer sees their balance
  move.
- **An activist or journalist** can transact without that transaction becoming a
  trail back to them.
- **A DAO voter** votes without fear of retaliation.
- **Anyone** gets the financial privacy that used to require a specialist — with
  one honest promise: *what you do with your money is your business again.*

That is the point. The cryptography below exists to deliver **that feeling** to a
person who will never read it.

---

## Who this is for

Anyone who doesn't want to be an open book on-chain:

- **Algotraders** who don't want their strategies reverse-engineered.
- **Whales** who don't want every move shadowed and front-run.
- **Market makers** protecting flow and inventory.
- **Protocols & agents** that need to operate without broadcasting their playbook.
- **Everyday users** who simply don't want to be clustered, profiled, and tracked.

riverrun protects the **behavior** layer for all of them — the actor↔action link —
which is orthogonal to, and composes with, value/recipient confidentiality.

### Where it composes (roadmap — not yet built)

riverrun is designed to be the behavioral-privacy layer of a confidential
settlement rail. The author's payments rail, **Vineland** — a non-custodial dollar
layer on Stellar with a *live* zero-knowledge **confidential-compliance** layer
(amounts and recipients hidden, with selective disclosure to a regulator key) — is
the intended integration target: Vineland hides *how much* and *to whom*; riverrun
adds *who* and *what behavior*. Together they are a full private settlement rail
for the audience above. This composition is a **roadmap item, not yet built** — and
crucially it must preserve Vineland's *provable-compliance / selective-disclosure*
framing rather than become pure hiding. See Security status.

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

## Why post-quantum and transparent

The whole core — commitment, Merkle set, nullifier, membership relation — is built
from one collision-resistant hash. No pairings, no trusted setup, no per-circuit
ceremony. That makes it **post-quantum** (hash-based) and **transparent** (nothing
to trust).

That's a tradeoff, not a free win. Pairing-based systems (Groth16) are mature,
battle-tested and produce far smaller proofs — for most applications they're the
right call. What they ask for in exchange is a per-circuit ceremony and security
resting on elliptic curves. For privacy meant to outlast a quantum adversary,
riverrun takes the other side of that trade: bigger proofs, hash-based
assumptions, nothing to trust.

## The privacy is proven by adversaries in this repo

The discipline: **build the attacker; the defense is its dual.** You cannot
credibly claim privacy against an attack you never ran.

- **Behavioral channel** (`cargo run -p riverrun-eval`). A clustering attacker that
  fingerprints wallets by co-buy timing and position sizing — the real Solana
  signal. Against a synchronized round of identical actions it collapses to
  chance: **12.5% attribution at k=8, 1.5% at k=64** (= `1/k`). Same attacker,
  same population; the only difference is the pool.

- **Provenance channel** (`cargo run -p riverrun-trace --bin provenance-tracer`). The leak every noise tool
  leaves open: trace a wallet's funding *backward* and reach an attributable
  origin. The `provenance-tracer` measures it, and — proven on **live mainnet** —
  a shallow, SOL-only walk names an origin for a real user wallet in **two hops**.
  The repo also ships the *defense*: a cyclic-provenance construction that drives
  the tracer's root-hit rate to 0 (or dissolves *which* origin across many, 2.9
  bits of ambiguity). This axis is hard for every noise-based design, riverrun
  included — the contribution here is measuring it rather than assuming it away,
  and the same ruler now runs against **live pools**, not only this repo's
  constructions. See [Your k is not your k](#your-k-is-not-your-k).

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
| **riverrun** | the **actor↔action link** — who did it, not what or how much | **no**, a named verifier attests | no | yes (hash-based) |

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

Because riverrun hides *behavior* and not funds, its on-chain footprint is tiny:
an execution writes a **17-byte nullifier account** and emits an event. No value
moves; no ZK is verified on-chain in the MVP. Deployed and exercised on **devnet**
(program `BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az`):

| operation | cost |
|---|---|
| `execute` (the action / withdrawal) — writes the nullifier | **~0.00101 SOL** |
| `commit` — fee only | ~0.000005 SOL |
| `initialize` — one-time pool account (85 bytes) | ~0.00148 SOL |

A full commit + execute is **~0.001 SOL per member per action** — on the order of
$0.0002. That is the whole design bet: privacy *for behavior* is cheap precisely
because nothing of value moves and nothing heavy is verified on-chain. Systems
that hide funds or verify a proof on-chain necessarily pay much more per
operation — they're solving a harder problem, and the comparison is about scope,
not quality.

**Measured live on devnet, not estimated** — though that measurement predates the
verifier attestation. The attestation adds one Ed25519 precompile instruction: no
new account, no new transaction signature, so no rent and no extra base fee, and
the transaction stays well inside the size limit. The figures below should
therefore still hold, but they have not been re-measured on devnet. A full
`initialize + commit + execute`
run (plus a rejected double-spend) cost **0.002507 SOL** total by wallet-balance
delta, matching the rent math above — so per action (commit + execute) is
**~0.00102 SOL**. The nullifier anti-replay was verified on a real cluster: the
double-spend attempt was rejected on-chain
([execute tx](https://explorer.solana.com/tx/coUCBWh4dsbRsUZHHZy62bK28JCfrF47RzhxPhSdSq1mpHRkucuxq5EiwSL8j1azxqPZdcetpMCB9rnAukYSbzX?cluster=devnet)).
Reproduce: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example devnet_demo`.

## Workspace

| crate | what it is | status |
|---|---|---|
| `riverrun-core` | the post-quantum primitives and the membership *relation* (commitment, Merkle set, nullifier). Specification only — nothing here proves anything | 19 tests |
| `riverrun-eval` | adversarial harness for the behavioral channel — clustering attacker → chance | 4 tests + exhibit |
| `riverrun-trace` | the `provenance-tracer`: backward funding-graph adversary + circularity defense + live-mainnet adapter | 7 tests + 2 exhibits |
| `programs/mirror-pool` | the on-chain Solana program: commitment accumulator, per-round nullifier registry (PDA-per-nullifier anti-replay), published root, verifier-attested settlement, entry fee + anonymity-set floor | builds to `.so`; 10 e2e tests green; **deployed + exercised live on devnet** (that deployment predates the attestation change) |
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
cargo run -p riverrun-trace --bin provenance-tracer                                       # provenance: field vs circularity
cargo run -p riverrun-trace --features onchain --bin onchain-trace  # live mainnet trace, one wallet
cargo run -p riverrun-trace --features onchain --bin pool-provenance \
  -- 9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD 30    # effective k of a live pool

# on-chain program (needs the Solana SBF toolchain):
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml            # → deployable .so
cargo test --manifest-path programs/mirror-pool/Cargo.toml --test e2e      # on-chain lifecycle e2e
cargo test --manifest-path crates/riverrun-stark/Cargo.toml                # STARK: membership + nullifier binding
cargo test --manifest-path crates/riverrun-pool-zk/Cargo.toml              # the pool driven by the STARK
```

**74 tests green** in total: 34 host + 23 STARK + 7 pool-zk + 10 on-chain e2e.

## Security status & honest limitations

This repo is two things with two different maturity levels, and collapsing them
would be dishonest in both directions.

**Runnable today, against mainnet, by anyone: the measurement tooling.**
`provenance-tracer`, `onchain-trace` and `pool-provenance` are finished tools.
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
> 2. **On-chain, `execute` now requires a named verifier's attestation — but it
>    still does not verify the proof itself.** The pool names a `verifier` key, and
>    an execution must carry that key's Ed25519 signature (checked through the
>    native sigverify precompile and instruction introspection) over exactly the
>    `(pool, root, action, nullifier, round)` being settled, where `root` must be
>    the one the authority published for the round. An arbitrary signer can no
>    longer settle an action, and a watcher can no longer front-run a nullifier out
>    of the mempool. **This is a named trust assumption, not soundness:** a
>    dishonest verifier can attest to a membership proof that does not exist.
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
>    So the blocker is not feasibility, it is *this repo's choices*. Our proof is
>    **12,057–16,536 bytes** against a 1,232-byte transaction limit, because the
>    AIR is a Rescue-Prime Merkle path over the 128-bit field rather than a
>    minimal AIR over a 31-bit one. Chunk-uploading 16 KB costs ~0.115 SOL of rent
>    against ~0.001 SOL for an entire action today. The path forward is a smaller
>    field and a cheaper hash — Circle STARK over M31, or Winterfell driven
>    through the `hashv` syscall — not a claim that it cannot be done. The SBF
>    compute cost of *our* verifier is not measured.
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

## License

MIT.
