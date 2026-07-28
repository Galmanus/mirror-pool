# ADR-0002: Compose the M31 relation from two proofs via a shared public value, not one monolithic AIR

**Status:** accepted
**Date:** 2026-07-28

## Context

`docs/M31_CIRCLE_STARK.md` specifies riverrun's full M31 relation as one
proof binding four facts: leaf formation (§1a), membership under a root
(§1b), and nullifier binding (§1c). `binding.rs` (§1a+§1c: a leaf and a
nullifier share one secret) and `membership.rs` (§1b: a leaf sits under a
root via a private path) were each built and proved independently first.
The question this ADR answers: fuse them into one trace, or compose two
separately-verified proofs.

Fusing them into one AIR is real, larger work: `binding.rs`'s two
permutation calls live side by side in one row (via
`VectorizedPoseidon2Air`); `membership.rs`'s Merkle fold is a chain across
multiple rows (via `SubAirBuilder` plus a private per-row selector bit and
`next_slice()` transition constraints). A single AIR serving both row shapes
needs a row-type-selector column multiplexing two incompatible layouts,
which was not attempted.

## Decision

`relation.rs`'s `prove_full_relation`/`verify_full_relation` call
`binding::prove_binding` and `membership::prove_membership` independently,
then check that `binding`'s public `leaf` output, truncated to
`membership::DIGEST_LEN`, equals `membership`'s public `leaf` input, checked
in plain Rust, outside either proof's algebraic constraints. This is exactly
the composition an on-chain verifier would do cheaply: two proof checks plus
one public-value equality check.

## Alternatives considered

- **One monolithic AIR (row-type selector).** The "real" fused version this
  ADR defers, not rejects outright. Larger, harder, and not needed to get a
  real, sound, end-to-end proof of the full relation working first.
- **Skip composition, ship the two proofs unlinked.** Rejected: without the
  shared-leaf check, nothing ties "this leaf/nullifier pair" to "this leaf
  sits under this root," a party could present a genuine binding proof for
  one leaf and a genuine membership proof for a *different* leaf and have
  both individually verify. The regression test in `relation.rs`
  (`mixing_one_members_binding_with_a_different_members_membership_fails`)
  exists specifically because this was checked, not assumed.

## Consequences

- Real, verified today: `prove_full_relation`/`verify_full_relation`, 14 (now
  16) tests green, no vendored code at the time this was written.
- Inherits both modules' own provisional conventions without resolving them:
  `binding.rs`'s secret/context split and `membership.rs`'s digest-truncation
  width are each concrete choices made to have something real to prove
  against, not settled security arguments (named in both modules' own docs).
- On-chain, this means two proof-verify calls per settlement instead of one,
  a real cost (in CU and in transaction complexity) a fused AIR would avoid.
  Not measured yet: on-chain verification of either proof individually hit
  its own wall first (ADR-0003's context; see
  `programs/riverrun-m31-verifier`'s module doc for the current state).
