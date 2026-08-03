# Local patch over p3-circle 0.6.2

Pristine source: crates.io `p3-circle 0.6.2` (`Cargo.toml.orig` is the original
manifest). Not a fork we intend to diverge on; drop each item the moment
upstream closes the gap.

## 1. `cu-trace` feature (measurement only)

`Cargo.toml` adds a `cu-trace` feature and a Solana-only `solana-program`
dependency. `src/verifier.rs` gains three
`#[cfg(all(target_os = "solana", feature = "cu-trace"))]
sol_log_compute_units()` probes inside the per-query loop (before/after
`open_input`, after `verify_query`). Zero semantic change; off by default.

## 2. Visibility: `CircleDomain::points`, `CircleDomain::vanishing_poly`, `cfft_permute_slice` are `pub`

Upstream both are `pub(crate)`. riverrun-m31's ZK wrapper (`src/zk.rs`,
`HidingCirclePcs`) blinds a committed trace as `T' = T + Z_D · R`: it needs
`Z_D` evaluated at concrete circle points of the doubled commitment domain.
The public `PolynomialSpace` surface exposes vanishing polynomials only at
projective-line inputs, which cannot address individual twin-coset points, so
these two methods are made `pub`. No behavior change — visibility only, each
marked with a doc comment pointing here.
