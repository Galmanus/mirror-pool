# riverrun — security status & honest limitations

The full audit, threat model, and negative results. A condensed summary lives in the README.


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
> pairing-based verifier via `alt_bn128`), plus decentralized round progression
> and a multisig/renounced upgrade authority, is what production would require.
> **Two items previously on this list are now closed.** (a) The shipped STARK
> parameters are 128-bit: **43 FRI queries at blow-up 8 with 16 bits of grinding
> (~145-bit conjectured)**, replacing the ~84-bit demo set — the query/FRI
> soundness margin is no longer the weak link (the in-circuit Rescue round count
> is still the demo set and is the remaining hash-side hardening). (b) Member
> secrets are now minted from the OS CSPRNG — `Secret::random()` in
> `riverrun-core` and `random_secret()` in `riverrun-pool-zk`, 256 bits — instead
> of being left to the caller, closing the low-entropy footgun that would have
> made the hiding breakable regardless of the primitive. Do not deploy this to
> guard real funds or identities until then.

A threat model is only useful if its assumptions are on the table, so here are
ours.

- **The proof keeps the witness off the wire, but it is not formally
  zero-knowledge.** Winterfell has **no** witness randomization in *any* release —
  verified against its `main` branch, whose `ProofOptions` still carries no zk/salt
  toggle. Winterfell is a transparent STARK for post-quantum *soundness*, not a
  zk-STARK; a deterministic proof is a function of the witness and provably carries
  information about it. So the honest claim is only "the secret does not appear
  verbatim in the transmitted proof" — checked over 20 proofs, not proven. Formal
  witness-hiding is not a Winterfell flag we failed to set; it needs a different,
  genuinely zero-knowledge post-quantum backend (e.g. a Circle STARK over M31 with
  ZK), which would also cut the on-chain verification cost in #2 — the same
  migration closes both. That check earns its keep: the first version of the binding
  AIR held the secret in a column that was constant across the trace, and since a
  constant column has a constant low-degree extension, the secret landed in every
  FRI opening — 20 leaks out of 20. Confining it to the rows where it is
  load-bearing fixed that (0 out of 20). Scope of the residual, stated precisely:
  the STARK proof is verified **off-chain** and is **never written to the chain** —
  the permanent on-chain record of an execution is only the nullifier (a `Rescue`
  PRF output, unlinkable across rounds), the published root, action, and round. So
  a *harvest-now-decrypt-later* adversary who archives the chain today gets no
  proof bytes to mine later; the non-formal-ZK gap bounds only whoever sees the
  proof off-chain (the verifier committee), not the forever-record. That is why
  the harvest-now-decrypt-later exposure of the *ledger* is already post-quantum,
  while the formal-ZK gap remains open for the off-chain proof path.
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

