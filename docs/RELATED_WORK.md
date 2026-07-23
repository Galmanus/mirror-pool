# Related work

What riverrun borrows, what it does differently, and — where it matters — what
the literature says riverrun should do next. Written because a submission that
does not know its own field is a submission a reviewer stops trusting.

## The privacy goal is not new

"Hide *which* member of a set performed an action" is anonymous authentication,
and it has a literature.

- **Session unlinkability.** PrivDID ([eprint 2026/127](https://eprint.iacr.org/2026/127))
  states the goal exactly: multiple presentations "should not be correlatable to
  a single identity holder, thereby preventing long-term behavioral tracking",
  via a ring signature over a dynamically selected anonymity set, with no trusted
  setup.
- **Anonymous credentials with predicate proofs** ([eprint 2026/1373](https://eprint.iacr.org/2026/1373),
  [Re2creds](https://eprint.iacr.org/2026/119)) give identity privacy and
  credential privacy under the same threat model riverrun works in: a verifier
  who wants to correlate sessions.

So riverrun's *goal* is established. What is specific here is the instantiation:
synchronized rounds of identical on-chain actions, settled by a Solana program,
with the anonymity set built from on-chain commitments — and, below, the
measurement.

## The nullifier is a known primitive, and ours is the standard shape

**PLUME** ([eprint 2022/1255](https://eprint.iacr.org/2022/1255), Gupta &
Gurkan) formalises deterministic nullifiers as "a public commitment to a specific
anonymous account, to forbid actions like double spending, or allow a consistent
identity between anonymous actions", proving uniqueness, secrecy and existential
unforgeability. riverrun's `nullifier = Rescue(secret, round)` is that primitive
with the round as the scope, and the AIR binds it to the same secret that proves
membership.

## What the literature says our anti-Sybil should be

riverrun prices a seat (`entry_fee`) and refuses to settle below a floor
(`k_min`). That is weaker than the state of the art, and the better construction
is known.

**Anonymous Self-Credentials** ([eprint 2025/618](https://eprint.iacr.org/2025/618))
gets Sybil resistance *cryptographically* rather than economically: a master
credential produces exactly **one nullifier per verifier**, so a holder can
register exactly one pseudonym with each verifier, while nullifiers across
different verifiers stay unlinkable. Applied here, a member would derive a
registration nullifier from a scarce master identity and the pool, and `commit`
would spend it — one seat per identity, enforced, instead of one seat per fee
paid.

That is the right fix and riverrun does not implement it. The gap is named in the
README's Security status rather than dressed up.

## Measuring anonymity: the metric is 2002, the channel is not

- **Serjantov & Danezis**, *Towards an Information Theoretic Metric for Anonymity*
  (PET 2002, Outstanding Paper award) define the **effective anonymity set size**
  as the entropy of the distribution linking subjects to the observed event.
  `riverrun_trace::effective_k` is that metric, conditioned on a provenance
  partition. **Díaz et al.** normalise it; we do not, following Danezis's
  objection that the normalised form measures fulfilled potential — a set of one
  scores 1.0 while providing nothing.
- **Measuring advertised-versus-true anonymity is an established programme, on
  Ethereum.** Tutela ([arXiv 2201.06811](https://arxiv.org/abs/2201.06811))
  reports the true size of Tornado Cash pools by excluding compromised deposits.
  Béres et al., *Blockchain is Watching You*, profile users by quasi-identifiers
  and apply them to Tornado. A cross-chain study
  ([arXiv 2510.09433](https://arxiv.org/abs/2510.09433), Oct 2025) links
  5.1–12.6% of Tornado withdrawals by address reuse and transactional linkage,
  plus 15–22 points more with FIFO temporal matching. Du et al. (IEEE TIFS 2024)
  correlate mixing addresses with graph neural networks.

Every one of those heuristics is **behavioural** — address reuse, timing, FIFO
ordering, wallet fingerprints. None conditions on the **funding graph**, and none
has been run on **Solana**. That is where [EFFECTIVE_K.md](EFFECTIVE_K.md) sits,
and the fact that our 37% lands in the same range as their 20–35% is a sanity
check on the tool rather than a claim of novelty about the number.

## On-chain STARK verification on Solana: done, and not by us

riverrun does not verify its proof on-chain. It previously claimed this was
infeasible. It is not:

- **[eprint 2025/1741](https://eprint.iacr.org/2025/1741)**, *Full L1 On-Chain
  ZK-STARK+PQC Verification on Solana*, adapts **Winterfell 0.12** — the library
  this repo uses — with SHA-256 routed through the `hashv` syscall, inlining
  suppressed in FRI hotspots for SBF stack limits, and a custom bump allocator.
  Measured over n=100 on devnet: `verify_stark` **mean 1.10M CU, max 1.19M**,
  inside the 1.4M budget, for a **4,437-byte** proof (~249 CU/proof-byte).
- **[murkl](https://github.com/exidz/murkl)** ships a **Circle STARK** verifier as
  a general-purpose CPI target: ~8.7 KB proof, **~31k CU**, M31/QM31, 128-bit,
  post-quantum, no trusted setup — powering anonymous transfer pools.
- **[mosaic](https://github.com/wienerlabs/mosaic)** verifies FRI-STARKs **chunked
  across transactions** with a resumable verifier and a checkpoint state machine,
  validated end to end on SBF.

The blocker is riverrun's own choices — a Rescue-Prime Merkle AIR over a 128-bit
field, giving a 12–16 KB proof — not the platform. The path is a 31-bit field and
a syscall-routed hash.

## Where riverrun is actually different

Three things, stated narrowly.

1. **The payload is behaviour, not value.** Everything above hides amounts,
   balances, transfers or credentials. riverrun's public transcript is
   `{root, action, nullifier}`: the action is public and its author is not.
2. **The funding graph is measured, not assumed away.** The repo ships the
   adversary, runs it on mainnet, and reports the effective k of a real pool —
   including riverrun's own constructions under the same ruler.
3. **No trusted setup, and the honesty is load-bearing.** Every "X is bound"
   claim in this repo has a test that was verified to fail without the constraint
   it tests. Three of those tests were found to be decorative that way, and are
   named in the commit log rather than quietly fixed.
