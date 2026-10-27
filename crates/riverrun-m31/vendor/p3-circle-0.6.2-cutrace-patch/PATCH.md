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

## 3. `[staged-patch]`: the PCS verifier split at its Fiat-Shamir seam

Why: a production crowd proof's verification does not fit one Solana
transaction (1.4M CU), so `programs/riverrun-m31-verifier` runs it across
several. That is only possible if the verifier can stop after deriving its
challenges and resume per query, so `CirclePcs::verify` is split, with no
change to what it accepts:

- `verifier::verify_setup` is upstream FRI `verify` up to and including the
  last `sample_bits`. Upstream interleaves index sampling with the per-query
  work, but `open_input`/`verify_query` never touch the challenger, so sampling
  every index first is the identical transcript. It returns `FriSetup` (betas,
  `log_max_height`, all indices).
- `verifier::verify_one_query` is one iteration of upstream's query loop, plus
  that query's shape checks (opening count, arity). Upstream checks every
  query's arity schedule against query 0's before the loop; Circle PCS only
  folds by 2 (`verify_query` asserts it), so the only schedule it can accept is
  all ones, which is what each query is now checked against. Same accepted set.
  The `cu-trace` probes of item 1 moved here with the loop body.
- `CirclePcs::verify_staged_setup` / `verify_staged_query` are the PCS-level
  halves (evaluation observation, batch alpha, bivariate beta and the height
  guard, then `verify_setup`; and the `open_input` body, moved verbatim into
  `open_input_at`, then `verify_one_query`). `CircleAlphaTables` holds the
  alpha powers upstream computed once before its loop.
- `CirclePcs::verify` (the `Pcs` impl) is now `verify_staged_setup` followed by
  `verify_staged_query` for every query: the monolithic and staged paths run
  the same code.
- Upstream's original bodies are kept verbatim as `#[doc(hidden)]`
  `CirclePcs::verify_upstream_reference` and
  `verifier::verify_upstream_reference`, used only by riverrun-m31's
  `staged_tests::the_split_verifier_agrees_with_the_upstream_reference`, which
  runs both on honest and byte-flipped proofs.
- `FriSetup` is re-exported from the crate root.

## 4. `[staged-patch]`: the DEEP input reduction, rearranged exactly for SBF cost

Measured with the `cu-trace` probes, upstream's `open_input` spent ~840K CU of
one crowd-binding query on Solana SBF (a whole transaction is 1.4M), mostly
in 22 extension-field inversions and 958 extension-by-extension products.
`open_input_at` now computes the same reduced openings with:

- `sum_k alpha^k (p_x[k] - p_zeta[k])` as `B - S`: `B = sum_k alpha^k p_x[k]`
  once per matrix (extension-by-base products, `alpha^k` split as
  `alpha^(8a+b)` so the tables are 8 + width/8 powers, not `width`), and
  `S = sum_k alpha^k p_zeta[k]` once per claim in `verify_staged_setup`
  (`CircleStagedSetup::claim_sums`), not once per query;
- each claim's opening point lifted to the circle once per distinct point
  (`CircleAlphaTables`), not once per matrix, point and query;
- every vanishing-part denominator of a query inverted in one batch; a zero
  denominator, where upstream's division panics, is an error.

Field identities only: each reduced opening is the same element.
`compare_open_input` runs this and the verbatim upstream body
(`open_input_at_reference`) side by side; riverrun-m31's
`the_cost_rearrangements_compute_the_same_field_elements` asserts equal values
on every query of both crowd proofs. Measured after: ~355K CU per binding query.
