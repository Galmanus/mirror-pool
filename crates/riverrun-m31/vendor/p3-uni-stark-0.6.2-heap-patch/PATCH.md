# Why this vendored copy of `p3-uni-stark` 0.6.2 exists

Same category as the sibling `p3-util-0.6.2-sbf-patch/` and
`p3-mersenne-31-0.6.2-sbf-patch/`: a Solana-runtime-constraint workaround on
full upstream source (MIT OR Apache-2.0, `https://github.com/Plonky3/Plonky3`),
not a fork we intend to diverge on. One change, additive, in `src/verifier.rs`.

## The problem, measured

`verify_with_preprocessed` begins by symbolically re-evaluating the entire AIR
(`get_log_num_quotient_chunks` → `get_all_symbolic_constraints`) to derive a
single `usize`: the log of the quotient-chunk count. For a Poseidon2 AIR that
symbolic pass materializes a transient `SymbolicExpr` tree that peaks at
**~440 KB of live heap** (measured natively with a tracking allocator against
`riverrun-m31`'s `BindingAir`: 452,760 B peak live at 4 FRI queries, of which
the numeric verification itself accounts for ~38 KB). Solana caps a
transaction's heap at 256 KB (`MAX_HEAP_FRAME_BYTES`, a hard runtime ceiling),
so on-chain the verifier OOMs inside `verify()` before reaching any
cryptography — the exact failure `programs/riverrun-m31-verifier` documented
as an open question before this patch existed.

The number that pass derives is a compile-time fact for a fixed AIR. An
on-chain verifier's AIR is fixed by definition.

## The change

`verify_with_preprocessed` is split, behavior-preserving:

- `verify_with_preprocessed` (unchanged signature and semantics) computes
  `log_num_quotient_chunks` via the symbolic pass exactly as before, then
  delegates.
- **`verify_with_known_quotient_chunks`** (new, public) is the untouched
  remainder of the verification body, taking `log_num_quotient_chunks` as a
  parameter. Its `A` bound drops `Air<SymbolicAirBuilder<…>>`, keeping only
  the numeric `for<'a> Air<VerifierConstraintFolder<'a, SC>>`.

A caller with a fixed AIR pins the value as a constant (riverrun-m31:
`binding::LOG_NUM_QUOTIENT_CHUNKS`, guarded by a native test that recomputes
it through the symbolic pass and fails on drift) and calls the new entry
point. Native re-measurement after the switch: peak live heap 37,664 B at 4
queries, 109,376 B at the production 40 queries — under the 256 KB ceiling
even with the on-chain LIFO-bump allocator's reclaim semantics (171,736 B
watermark at 40 queries).

## Soundness

A wrong `log_num_quotient_chunks` cannot weaken verification: the value fixes
the expected proof shape (`num_quotient_chunks`) and the quotient-domain
split, so a mismatch makes honest proofs fail shape validation or the final
quotient check — it rejects, it does not accept. The parameter is a program
constant on-chain, not attacker-controlled input.

## Second, diagnostic-only addition: the `cu-trace` feature

Three `sol_log_compute_units()` calls in `verify_with_known_quotient_chunks`
(before/after `pcs.verify`, before `verify_constraints`), gated behind
`#[cfg(all(target_os = "solana", feature = "cu-trace"))]` — **off by default,
zero behavioral difference unless explicitly enabled**. They exist so the
on-chain CU cost can be attributed per phase reproducibly (measured 2026-07-29,
4 FRI queries, opt-level 3: pre-PCS ~220k CU, `pcs.verify` ~1.67M CU,
quotient recompose ~97k CU, `verify_constraints` ~398k CU, total 2,384,277 CU).
The `[target.'cfg(target_os = "solana")'.dependencies]` on `solana-program`
exists only for these calls.

## Exit condition

Remove this vendored copy when upstream Plonky3 exposes an equivalent entry
point that takes the quotient-degree (or the full symbolic summary) as a
precomputed input instead of recomputing it inside `verify`.
