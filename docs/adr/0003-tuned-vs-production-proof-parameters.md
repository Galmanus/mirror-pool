# ADR-0003: Expose explicit `_tuned` variants for reduced-security measurement, never silently weaken the production path

**Status:** accepted
**Date:** 2026-07-28

## Context

A production `BindingProof` (40 FRI queries) serializes to ~78 KB. Measuring
real on-chain verification cost via LiteSVM needs the proof to fit inside a
serialized transaction message, which turned out to cap at 65535 bytes
(a `u16` length field in `solana-message`), confirmed directly (`"length
larger than u16"`), not assumed from documentation. No proof at production
security fits. Getting any real, on-chain-measured number at all requires
proving at a reduced query count.

The risk this ADR exists to name: reducing FRI queries for a size-fitting
demo is a real security-relevant change (fewer queries is measurably weaker
soundness), and doing it invisibly (e.g. hardcoding a smaller `num_queries`
inside `make_config()`) would silently ship a weaker proof under the same
name a caller would reasonably expect to be production-grade.

## Decision

`make_config()` (used by `prove_binding`/`verify_binding`) stays hardcoded at
40 queries, unconditionally. A parallel `make_config_tuned(num_queries)`,
`prove_binding_tuned(..., num_queries)`, `verify_binding_tuned(...,
num_queries)` exist alongside, and the production functions are defined as
one-line callers of the tuned ones with `40` hardcoded, not the other way
around, so weakening the production path would require visibly deleting that
delegation, not just changing a default argument.

`programs/riverrun-m31-verifier`'s on-chain program takes `num_queries` as
an explicit field in its instruction data (a `u16` prefix), rather than
hardcoding a query count in the program itself, so any caller's choice of
security/size tradeoff is visible in the instruction, not assumed by the
verifier.

## Alternatives considered

- **A `#[cfg(test)]`-only reduced-parameter path.** Rejected: would hide the
  tradeoff from anything outside the test build (including, eventually, a
  real caller who might reasonably want a documented reduced-security tier
  for a different reason), and couples a security parameter to a build
  profile rather than an explicit call.
- **Just lower the default query count everywhere.** Rejected outright: this
  is exactly "fake the finish," shipping a weaker proof to make a demo work
  and calling it done.
- **Don't measure on-chain cost until the message-size problem has a real
  fix (the buffer-account staging `docs/M31_CIRCLE_STARK.md` specifies).**
  Considered, and still the right call for a *production* number. Rejected
  for getting *any* real signal at all in the meantime: even a reduced-
  parameter measurement (this ADR's approach) surfaced a real, independent
  finding (the peak-memory ceiling inside `verify()`, present at every query
  count tried down to 4) that would not have been found by waiting.

## Consequences

- The production API (`prove_binding`/`verify_binding`) cannot be weakened
  by a caller who doesn't explicitly reach for the `_tuned` variant and pass
  a query count; the unsafe choice requires an unmistakable, named call.
- `programs/riverrun-m31-verifier/tests/cu.rs` documents, in its own
  comments, exactly which query count was used for which measurement and
  why, so a reduced-security number is never presented without that context
  attached.
- This pattern (production function delegates to a `_tuned` variant with the
  real parameter hardcoded, not the reverse) is the template for any future
  case in this codebase where a measurement or demo needs a different point
  on a security/performance tradeoff than what ships.
