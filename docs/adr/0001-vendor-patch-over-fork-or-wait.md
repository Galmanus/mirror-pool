# ADR-0001: Vendor-patch third-party crates for SBF toolchain gaps, rather than fork or wait

**Status:** accepted
**Date:** 2026-07-28

## Context

Porting `riverrun-m31` (a Plonky3-based Circle-STARK, MIT/Apache-2.0
dependencies, no vendored code until this decision) to Solana's SBF target
hit two real, separately diagnosed compiler/linker walls, neither caused by
riverrun's own code:

1. `p3-util` 0.6.2 calls `[MaybeUninit<u8>]::assume_init_ref`, the unstable
   Rust feature `maybe_uninit_slice`. Stable on this machine's host rustc
   (1.97.0); still unstable on Solana's currently pinned SBF compiler
   (rustc 1.89.0, `platform-tools v1.54`). Checked before deciding anything:
   `v1.54` (2026-03-06) is the newest platform-tools release available (via
   the `anza-xyz/platform-tools` GitHub releases API), so waiting for a newer
   pinned rustc was not an available option today.
2. `p3-mersenne-31` 0.6.2 unconditionally bundles a legacy Poseidon1 + MDS
   implementation riverrun-m31 never calls, with no Cargo feature to opt out.
   Left compiled, several of those unused functions overflow SBF's 4096-byte
   per-function stack limit at *load* time (not build time), which pure
   dead-code-elimination did not reliably strip.

## Decision

For each, vendor a full, unmodified copy of the exact upstream crate version
into `crates/riverrun-m31/vendor/<crate>-<version>-sbf-patch/`, apply the
smallest possible change, and wire it in via `[patch.crates-io]`. Each patch
carries its own `PATCH.md`: why it exists, exactly what changed, and what
would make it deletable. Both are checked-in, MIT/Apache-2.0-licensed,
attributed, byte-for-byte upstream except the documented change:

- `p3-util`: one function rewritten to use only stable APIs
  (`core::slice::from_raw_parts` over a raw pointer, same safety invariant).
- `p3-mersenne-31`: `p3-poseidon1`/`p3-mds` made optional dependencies behind
  a `poseidon1` feature, default-on for anyone else depending on this
  vendored copy unmodified, off in riverrun-m31's own manifest.

## Alternatives considered

- **Wait for Solana to ship a newer pinned rustc.** Checked and rejected:
  `v1.54` is already the newest platform-tools release; there is nothing to
  wait for today, and no visibility into when a fix would land upstream.
- **File upstream issues against Plonky3 and wait.** Legitimate for the
  `p3-mersenne-31` feature-split (worth doing regardless, noted in that
  patch's `PATCH.md`), but leaves riverrun blocked indefinitely on a
  timeline this project does not control.
- **Fork the whole crate and diverge.** Rejected: this is a much larger
  maintenance surface and invites drift from upstream's own fixes and
  security patches, for a change that is genuinely one function or one
  feature flag.
- **Give up on SBF entirely, stay verify-only-natively.** Rejected as
  premature: the actual blockers turned out to be shallow (a stable-API
  rewrite, a feature flag), not fundamental incompatibilities with the
  underlying cryptography.
- **Silently monkey-patch via build.rs/sed on `cargo build`.** Rejected:
  invisible, unreviewable, and breaks the moment upstream ships a new patch
  version. An explicit `[patch.crates-io]` entry is visible in the manifest
  and diffable in review.

## Consequences

- Two small, auditable, documented patches instead of one large fork.
- Both patches are explicitly framed as temporary: named in their own
  `PATCH.md` as "delete when Solana or Plonky3 close the gap," so this ADR's
  status should be revisited (not silently ignored) once either happens.
- `[patch.crates-io]` does not propagate automatically to a downstream crate
  that consumes `riverrun-m31` as a path dependency (Cargo only reads
  `[patch]` from whatever manifest is the current build root); every crate
  that builds standalone against SBF (today: `riverrun-m31` itself and
  `programs/riverrun-m31-verifier`) must repeat the same `[patch.crates-io]`
  block. This is a real, ongoing maintenance cost this ADR accepts rather
  than hides.
- Neither patch touches the actual cryptographic logic (the field, the
  permutation, FRI, the constraint system) at all; both are pure toolchain-
  compatibility changes to non-cryptographic utility code.
