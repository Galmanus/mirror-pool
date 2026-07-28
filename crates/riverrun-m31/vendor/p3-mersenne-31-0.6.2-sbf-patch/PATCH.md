# Why this vendored copy of `p3-mersenne-31` 0.6.2 exists

Same category of patch as the sibling `p3-util-0.6.2-sbf-patch/`: a
Solana-SBF-toolchain compatibility workaround, not a fork we intend to
diverge on or add anything to. Full upstream source
(MIT OR Apache-2.0, `https://github.com/Plonky3/Plonky3`), one change.

## The problem

`p3-mersenne-31` unconditionally bundles TWO permutation implementations:
Poseidon2 (what `riverrun-m31` actually uses, throughout `binding.rs`,
`membership.rs`, `permutation.rs`) and the legacy Poseidon1 + its MDS matrix
(`mds.rs`, `poseidon1.rs`), which riverrun-m31 never calls, anywhere. There is
no upstream Cargo feature to opt out of the unused half; both are hard,
unconditional dependencies (`p3-poseidon1`, `p3-mds`) with no `[features]`
section in the original manifest.

That would be a non-issue on a normal target: dead code elimination should
just drop unreferenced public functions from a `cdylib`'s final binary. On
Solana's SBF target it is not a non-issue, because the SBF loader's bytecode
verifier checks every function's stack-frame size (a hard 4096-byte-per-
function limit) against **whatever ends up in the compiled binary**, and this
build's DCE/LTO did not fully strip the unused Poseidon1/MDS functions before
that check runs: several of them (`Poseidon1Constants::to_optimized`,
`MdsMatrixMersenne31::permute`, `default_mersenne31_poseidon1_32`, and
related `p3_poseidon1::utils::*` helpers) have large stack-allocated matrices
and blow well past 4096 bytes. The build-time linker printed these as
warnings and still produced a `.so`; the SBF runtime's own loader
(`LiteSVM::add_program_from_file`, and by extension any real Solana cluster)
rejected that `.so` with `InvalidAccountData` when actually loading it. Build
succeeding is not the same guarantee as load succeeding, on this target.

## The fix

`p3-poseidon1` and `p3-mds` are made `optional = true` dependencies, gated
behind a new `poseidon1` feature (`default = ["poseidon1"]`, so anyone else
depending on this vendored copy unmodified sees no behavior change).
`riverrun-m31` depends on it with `default-features = false`, which excludes
`mod mds;` / `mod poseidon1;` and their `pub use` re-exports from `lib.rs`
entirely, so the offending functions are never compiled in the first place,
not merely hoped to be stripped after the fact.

## Everything else

Untouched, byte-for-byte upstream 0.6.2, same as the `p3-util` patch. Not
maintained independently; delete this the moment either Solana's SBF loader
handles this case differently, or upstream Plonky3 ships an optional-feature
split of its own (worth filing upstream, not done as part of this patch).
