# Why this vendored copy of `p3-util` 0.6.2 exists

This is a full copy of the upstream `p3-util` 0.6.2 source
(MIT OR Apache-2.0, `https://github.com/Plonky3/Plonky3`), patched in exactly
one place, to work around a Solana toolchain limitation, not to change any
behavior or claim any originality over upstream's work.

## The problem

`riverrun-m31` compiles cleanly for `sbpf-solana-solana` (Solana's on-chain
program target) with every dependency except this one. `p3-util::apply_to_chunks`
calls `[MaybeUninit<u8>]::assume_init_ref()`, which is the unstable Rust library
feature `maybe_uninit_slice` (tracking issue rust-lang/rust#63569). It compiles
fine on a recent stable host toolchain (this machine: rustc 1.97.0, where the
feature has since stabilized), but Solana's SBF target is pinned to a specific,
older compiler bundled with `platform-tools`: **rustc 1.89.0** as of
`platform-tools v1.54` (2026-03-06, the newest release available as of this
patch, checked via the `anza-xyz/platform-tools` GitHub releases API before
patching anything). On 1.89.0 that API is still unstable, and
`RUSTC_BOOTSTRAP=1` does not help, because `p3-util`'s own source never
declares `#![feature(maybe_uninit_slice)]`; it simply assumes the API is
already stable, which is only true on a newer compiler than Solana currently
ships.

## The fix

One function, `apply_to_chunks` in `src/lib.rs`, rewritten to produce the exact
same `&[u8]` from the exact same initialized bytes, using only stable APIs
(`core::slice::from_raw_parts` over a raw pointer cast) instead of the unstable
trait method. Same safety invariant, same behavior, zero functional change:
`iter_next_chunk_erased` (unchanged, already stable) guarantees the first `n`
elements of `buf` are initialized before this function ever runs; the patch
only changes how that already-established fact is turned into a `&[u8]`.

## Everything else

Untouched, byte-for-byte upstream 0.6.2. This is not a fork we intend to
diverge on, add features to, or maintain independently: it exists to be
deleted the moment either (a) Solana's platform-tools ships a newer pinned
rustc where `maybe_uninit_slice` is stable, or (b) upstream Plonky3 ships a
release that avoids the unstable API itself. Check for either before assuming
this patch is still needed.
