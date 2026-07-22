# mirror-pool

**Tornado Cash for behavioral patterns and actions — not funds.**

Tornado Cash breaks the link between a *deposit* and a *withdrawal* of money.
`mirror-pool` breaks the link between a **committed intent** and an **executed
action**: a swap, a claim, a vote, a withdrawal from a protocol. Amounts are
neither hidden nor the point — what is severed is the **actor ↔ action** link, the
thing modern chain-analysis clusters on. Post-quantum and transparent: built from
hashes, no trusted setup, no ceremony.

Everything here is Rust, MIT, and runs today. The privacy claims are not
asserted — they are checked by adversaries shipped in the same repo, one of them
proven on live Solana mainnet.

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

Run it — `cargo run -p mirror-core --example behavior_pool`:

```
committed members : 5
set root          : 2976a5c8dd79af48…

synchronized round — public transcript the observer sees:
#     action (public)       nullifier
------------------------------------------------
1     61ff9ae885391e85…     7c854b8fb313f8ea…
2     61ff9ae885391e85…     75d8860a57408da4…
...
5     61ff9ae885391e85…     0549d58e2b5be44c…

An observer's chance of mapping any execution to its author is 1/5.
double execution, same round  -> NullifierSpent
tampered action after proof   -> ActionMismatch
```

Same action, distinct nullifiers, one root. The nullifier is `H(secret‖round)` —
unlinkable to any commitment. Grow the set to `k` and the actor↔action link is
`1/k`, by construction. (`crates/mirror-core/src/pool.rs`)

## Why post-quantum and transparent

The whole core — commitment, Merkle set, nullifier, membership relation — is built
from one collision-resistant hash. No pairings, no trusted setup, no per-circuit
ceremony. That makes it **post-quantum** (hash-based) and **transparent** (nothing
to trust), unlike Groth16 mixers whose ceremony is itself a liability. Privacy
meant to outlast a quantum adversary cannot rest on elliptic-curve pairings; it
can rest on hashes.

## The privacy is proven by adversaries in this repo

The discipline: **build the attacker; the defense is its dual.** You cannot
credibly claim privacy against an attack you never ran.

- **Behavioral channel** (`cargo run -p mirror-eval`). A clustering attacker that
  fingerprints wallets by co-buy timing and position sizing — the real Solana
  signal. Against a synchronized round of identical actions it collapses to
  chance: **12.5% attribution at k=8, 1.5% at k=64** (= `1/k`). Same attacker,
  same population; the only difference is the pool.

- **Provenance channel** (`cargo run -p mirror-trace`). The leak every noise tool
  leaves open: trace a wallet's funding *backward* and reach an attributable
  origin. The `provenance-tracer` measures it, and — proven on **live mainnet** —
  a shallow, SOL-only walk names an origin for a real user wallet in **two hops**.
  The repo also ships the *defense*: a cyclic-provenance construction that drives
  the tracer's root-hit rate to 0 (or dissolves *which* origin across many, 2.9
  bits of ambiguity). This is the axis the field admits it cannot close.

## Workspace

| crate | what it is | status |
|---|---|---|
| `mirror-core` | the behavioral pool + its post-quantum primitives (commitment, Merkle set, nullifier, membership, `BehaviorPool`) | 27 tests + demo |
| `mirror-eval` | adversarial harness for the behavioral channel — clustering attacker → chance | 4 tests + exhibit |
| `mirror-trace` | the `provenance-tracer`: backward funding-graph adversary + circularity defense + live-mainnet adapter | 7 tests + 2 exhibits |
| `programs/mirror-pool` | the on-chain Solana program: commitment accumulator, per-round nullifier registry (PDA-per-nullifier anti-replay), action settlement | builds to `.so`; e2e green |

```bash
cargo test --workspace                                            # 38 tests green
cargo run -p mirror-core --example behavior_pool                  # the mechanism
cargo run -p mirror-eval                                          # behavioral deanon → chance
cargo run -p mirror-trace                                         # provenance: field vs circularity
cargo run -p mirror-trace --features onchain --bin onchain-trace  # live mainnet trace

# on-chain program (needs the Solana SBF toolchain):
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml            # → deployable .so
cargo test --manifest-path programs/mirror-pool/Cargo.toml --test e2e      # on-chain lifecycle e2e
```

## Honest limitations

A threat model that hides its assumptions is theater.

- **Membership proofs use a transparent reference backend** (it carries the
  witness). It is *sound* — the verifier accepts only valid witnesses — and drives
  the full commit→execute→settle protocol end to end, but it is not yet
  succinct/zero-knowledge on the wire. The post-quantum STARK backend
  (`crates/mirror-stark`, research track) upgrades exactly that seam, proving the
  identical relation with `action` public and `secret` private.
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

- Live-cluster / Surfpool soak of the on-chain program (the in-process e2e
  already passes; a devnet deploy + soak is the next step) and on-chain
  verification of the membership proof.
- Post-quantum STARK membership (`mirror-stark`): succinct, zero-knowledge,
  transparent.
- **LWE-hard cover** — anchor indistinguishability on Learning-With-Errors so
  separating real from cover is provably as hard as worst-case lattice problems
  (measured → *provable* privacy). Paper track.
- **Provenance flow** — a monotone privacy functional (a Perelman-style Lyapunov
  quantity) under which any trace flows to a canonical, indistinguishable form.
  Paper track.

## License

MIT.
