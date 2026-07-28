# Architecture

What's actually in this repo, module by module, with an honest status on
each: `[live]` (deployed and used, not just tested), `[tested]` (real tests
green, not deployed/wired into settlement), `[blocked]` (built, real, and
currently stopped by a diagnosed, named problem, not a mystery).

```
mirror-pool/
  crates/
    riverrun-core        # hash-based commitment/nullifier/Merkle/membership primitives [tested]
    riverrun-stark        # Winterfell f128 STARK: the current, working membership proof [live off-chain, on-chain verified via stark-verifier]
    riverrun-m31           # riverrun's own Circle-STARK (Plonky3): the post-quantum, no-committee path [tested natively, blocked on-chain]
    riverrun-pool-zk       # behavioral pool carrying an opaque STARK membership proof, not the secret [tested]
    riverrun-eval          # the ruler: adversarial evaluation, effective-k against real chain-clustering attacks [live, run against mainnet pools]
    riverrun-trace         # provenance-tracer: adversarial funding-graph de-anonymizer [live on mainnet]
    riverrun-sdk            # act(): the one-call flow a fund integrates [tested]
  programs/
    mirror-pool             # the on-chain Anchor program: commit/execute/execute_batch/execute_verified/advance_round [live on devnet]
    stark-verifier           # on-chain Winterfell verifier, priced in real CU [tested, works on-chain]
    riverrun-m31-verifier     # on-chain riverrun-m31 verifier: loads and executes, blocked by a real memory wall [blocked, diagnosed]
  docs/
    ARCHITECTURE.md          # this file
    RELATED_WORK.md           # the literature riverrun sits in, and where it departs from it
    SECURITY.md                # the threat model: what each settlement path defends against
    EFFECTIVE_K.md               # the ruler and the arithmetic behind it
    M31_CIRCLE_STARK.md           # the Circle-STARK migration spec, including what's built and what's blocked
    DEFENSE.md                     # honest answers to the hardest questions a panel could ask
    POST_QUANTUM_VS_CURVE_POOLS.md  # hash vs curve, the design-axis comparison
    DEVNET_ROUND.md                  # the live round on devnet, every signature
    adr/                               # architecture decision records (numbered, immutable)
  paper/
    riverrun.pdf / riverrun.tex          # the whitepaper: philosophy, cryptography, proofs
    metacognitive-security-surface.pdf    # companion paper: the generative-layer-alignment argument riverrun's honesty discipline formalizes
  Cargo.toml                                # host workspace (riverrun-core/eval/sdk/trace only; heavy crates build standalone)
```

## Why the workspace is split the way it is

`Cargo.toml`'s default `[workspace] members` is deliberately small
(`riverrun-core`, `riverrun-eval`, `riverrun-sdk`, `riverrun-trace`): these
build fast, pull no heavy toolchain, and are what `cargo test --workspace`
runs (117 tests). `riverrun-stark` (Winterfell), `riverrun-m31` (Plonky3),
`riverrun-pool-zk`, and every `programs/*` crate are in `exclude`, each
buildable standalone via its own `cargo test --manifest-path`. This is not
an oversight: it means anyone touching the cryptographic core never
involuntarily pulls in a Solana SBF toolchain or a STARK proving stack just
to run the fast tests, and each heavy crate's own README/module docs state
exactly how to build and test it.

## The two membership-proof paths, honestly compared

riverrun has never had exactly one proof system; it has had two, at
different points on the "how much of the trustless-on-chain property is
actually shipped" axis, and this repo keeps both real rather than deleting
the one that isn't finished:

| | `riverrun-stark` (Winterfell, f128) | `riverrun-m31` (Plonky3, Circle-STARK) |
|---|---|---|
| Field | 128-bit (`2^128 − 45·2^40 + 1`) | Mersenne-31 (`2^31 − 1`) |
| In-circuit hash | Rescue-Prime | Poseidon2 |
| Proof size | 12–16 KB | ~78 KB at 40 queries (measured) |
| On-chain verification | Yes, measured (`programs/stark-verifier`: 1.57M–3.77M CU across query counts 4–28 at k=4, every one of them over Solana's 1.4M/tx cap) | Loads and executes; blocked by a real, diagnosed memory ceiling inside `verify()` itself, independent of proof size or AIR complexity |
| What settles live today | Nothing directly; live settlement uses the M-of-N committee path | Nothing; this is the roadmap item |

Neither is "the fake one." `riverrun-stark`'s on-chain verifier genuinely
runs and is genuinely priced; it just costs more CU than a single real
transaction affords at production security. `riverrun-m31` genuinely has
smaller proofs and a real shot at fitting Solana's CU budget, and is real,
tested, in-repo code, not vendored, not a claim; it just hasn't cleared
Solana's heap ceiling yet, for reasons named precisely in
`docs/M31_CIRCLE_STARK.md`, not hand-waved.

## What actually settles value on-chain, today

`programs/mirror-pool`'s `execute` / `execute_batch` paths, gated by an M-of-N
Ed25519 committee attestation over a digest binding `{pool, root, round,
action, nullifiers, recipients}`. No shared escrow (`grep -rn escrow
programs/mirror-pool/src/` returns nothing): a relayer pays each round's
recipients directly from its own transaction, which is also why riverrun
structurally cannot have the class of fund-draining bug a shared-escrow
design can (see `docs/DEFENSE.md`).

## Extending riverrun to a new protocol or interaction

`riverrun-sdk`'s `act()` flow (`crates/riverrun-sdk/src/lib.rs`) is generic over
two traits, not hardcoded to one chain backend or one proof system:

```rust
pub trait Backend {
    fn commit(&mut self, commitment: &Commitment) -> Result<(), String>;
    fn await_round(&mut self) -> Result<RoundInfo, String>;
    fn settle(&mut self, round: &RoundInfo, nullifier: &Nullifier, action: &[u8],
               recipient: &[u8; 32], amount: u64, proof: &Proof) -> Result<String, String>;
}

pub trait Prover {
    fn prove(&self, secret: &Secret, context: &[u8], action: &[u8],
              round: &RoundInfo) -> Result<Proof, String>;
}
```

`act()` itself (the commit/wait-for-crowd/refuse-below-floor/prove/settle
sequence, and the anonymity-floor enforcement) never changes when either trait
gets a new implementation. This is not a hypothetical extension point; it is
already exercised three different ways in this repo:

- `SimBackend`/`SimProver` (`crates/riverrun-sdk/examples/position_bot.rs`): an
  in-memory, deterministic backend and a no-op prover, for offline testing.
- The real devnet backend (`programs/mirror-pool/examples/act_devnet.rs`),
  settling the same `act()` calls for real, on-chain.
- Two real, independent provers, `riverrun-stark` (Winterfell f128) and
  `riverrun-m31` (Plonky3 Circle-STARK), either of which can sit behind
  `Prover` without `act()`'s own logic changing at all.

**A new protocol or interaction** is a new `req.action` byte string (the
`ActRequest.action` field is caller-defined, not a fixed enum) plus, if it
settles somewhere riverrun doesn't already reach, one new `Backend` impl. Adding
a new settlement chain, a new relayer network, or a new kind of on-chain action
does not require touching `riverrun-core`'s commitment/nullifier math, the
proof system, or `act()`'s own control flow, only the trait impl for the new
target.
