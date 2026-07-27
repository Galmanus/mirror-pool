# Hash-based vs curve-based privacy pools: an honest comparison

This is a design-axis comparison, not a takedown. Behavioral privacy pools on
Solana are converging on the same thesis (mix a synchronized round of identical
actions so on-chain clustering cannot attribute them), and there is more than one
honest way to build one. The dividing line that matters on a permanent public
ledger is the cryptographic foundation: **hash-based and transparent** (what
riverrun is) versus **curve-based with a trusted setup** (Groth16 over BN254, the
mainstream zk-SNARK path, and what the one production on-chain verifier on Solana,
`groth16-solana` / the native `alt_bn128` syscalls, supports today).

Both can be built well. They are not equivalent, and the difference is not
cosmetic.

## Where curve-based pools are genuinely ahead today

State this plainly, because it is true and it is the part riverrun still has to
answer.

- **Proof size.** A Groth16 proof is 3 group elements, about 256 bytes, constant
  regardless of circuit size. A STARK proof is tens to hundreds of kilobytes. On a
  chain that charges for bytes, that is a real, present cost.
- **On-chain verification is mature today.** `groth16-solana` verifies a BN254
  pairing proof in roughly 200k compute units using the runtime's native
  `alt_bn128` syscalls. It is deployed, it works, and a curve-based pool can settle
  a round with trustless on-chain verification right now, no committee.
- **Tooling.** Circom, snarkjs, and a decade of ceremony infrastructure are
  battle-tested and familiar.

If the only axis were "can a real proof be verified on-chain trustlessly this
week," curve-based pools win it. riverrun's on-chain verifier is an M31 Circle
STARK proven inside the Solana VM at about 160k compute units (LiteSVM,
wrong-action rejected), not yet on a live cluster; the live settlement path falls
back to a committee. That gap is named honestly in the README and it is the thing
riverrun is closing.

## Where hash-based pools are structurally ahead, permanently

These are not features that curve-based pools can add. They are consequences of
the choice of primitive, and reversing them means abandoning Groth16.

### 1. No trusted setup, nothing to trust, nothing to leak

A Groth16 circuit needs a **trusted-setup ceremony** that produces a structured
reference string. The ceremony also produces toxic waste: secret randomness that,
if any participant keeps it, lets that participant **forge proofs**, which in a
pool means minting membership or draining value without being a member. The
standard mitigation is a multi-party ceremony that is safe as long as at least one
participant is honest and actually destroyed their share. That is a real
assumption a user cannot verify after the fact.

riverrun has no ceremony and no toxic waste. Its soundness rests on the collision
resistance of a hash function and the FRI low-degree test. There is no secret whose
leak breaks the system, because there is no secret in the setup at all. This is the
meaning of "transparent" in a transparent proof system.

### 2. Post-quantum by construction, not by patch

This is the decisive one on a permanent ledger, and it is an inequality, not a
mood. Let **X** be how long the anonymity must hold, **Y** the time to migrate,
and **Z** the time until a cryptographically-relevant quantum computer exists.
Mosca's observation: if **X + Y > Z**, you have already lost.

For a permanent public ledger, **X is effectively infinite**: the chain is copied,
free and forever, the moment a transaction lands. An adversary harvests it today
and waits. When a quantum computer arrives, Shor's algorithm recovers discrete
logs and breaks the pairing-based unlinkability of every Groth16 proof and every
BN254 commitment ever posted. The privacy of a curve-based pool is therefore
**computational and retroactive**: everything it shields today is de-anonymizable
later. Harvest-now-decrypt-later is not a risk to manage on a permanent ledger, it
is a certainty, unless the primitive is already quantum-safe the day it is posted.

riverrun stores only hash outputs on-chain: the commitment `H(secret || action)`,
the nullifier `H(secret || round)`, and the Merkle root. There is no public key,
no curve point, no pairing, nothing for Shor to attack. Grover's algorithm halves
the effective security of a hash, and the 256-bit primitives already absorb that
to 128 bits. What riverrun hides today stays hidden after quantum arrives. This is
"everlasting" unlinkability, and a curve-based pool cannot reach it without
replacing its proof system with a hash-based one.

NIST finalized its post-quantum standards (FIPS 203/204/205) in August 2024. For a
privacy tool whose guarantee is meant to be permanent, "post-quantum" in 2026 is
not an upgrade path, it is a precondition.

## The honest scorecard

| axis | curve-based (Groth16/BN254) | hash-based (riverrun, STARK) |
|---|---|---|
| proof size | ~256 bytes, constant | tens to hundreds of KB |
| on-chain verify, live today | yes (`groth16-solana`, ~200k CU) | VM-proven (M31, ~160k CU), committee fallback on cluster |
| trusted setup | required (ceremony, toxic waste) | none (transparent) |
| post-quantum | no (Shor breaks it retroactively) | yes (hash-based, everlasting) |
| behavioral k-anonymity | yes | yes |
| recipient/relayer binding | yes (ext-data hash) | yes (action bound in the AIR) |
| effective-k measurement | yes | yes (Serjantov-Danezis, plus the self-fill and funding-graph rulers) |
| identity layer beyond the pool | no | yes (riverrun ID, seven powers) |

## What this means for the choice

If the anonymity only needs to hold for a short window, curve-based pools are a
smaller, faster, well-tooled answer, and their trusted-setup risk is a one-time
ceremony a user can choose to trust. If the anonymity is meant to be **permanent**,
which is the only honest promise on a ledger that never forgets, then a foundation
that is retroactively breakable by a machine we can already describe is shipping a
guarantee it cannot keep. That is the case riverrun is built on, and it is why the
foundation is hashes from the first line rather than a curve with a patch planned.

The remaining work is symmetric and honest: riverrun must bring its post-quantum
on-chain verifier from the VM to a live cluster to match what curve-based pools
already demonstrate. When it does, it is post-quantum, transparent, and verified
on-chain with no committee at once. A curve-based pool cannot follow it there
without becoming a hash-based pool.

## Sources

- M. Mosca, "Cybersecurity in an era with quantum computers: will we be ready?"
  IEEE Security & Privacy, 2018.
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), August 2024.
- Serjantov and Danezis, "Towards an Information Theoretic Metric for Anonymity,"
  PETS 2002 (the effective-k / entropy metric).
- Ben-Sasson et al., "Scalable, transparent, and post-quantum secure computational
  integrity" (STARKs), 2018.
- `groth16-solana` and the Solana `alt_bn128` syscalls (the production on-chain
  Groth16 verifier this comparison refers to).
