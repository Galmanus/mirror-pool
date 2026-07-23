# 1c — Binding the nullifier into the membership AIR (implementation blueprint)

Status: **implemented, tests pass, unaudited** — `crates/riverrun-stark/src/bound_air.rs`
and `bound_prover.rs`, wired into `riverrun-pool-zk`. Two deviations from the plan
below, both found while implementing:

1. **The carry must not be constant.** The plan said "held constant for the whole
   trace". A constant trace column has a *constant* low-degree extension, so every
   FRI query opening returns the secret verbatim: measured at 20 leaked proofs out
   of 20 before the fix, against 0 out of 20 for the unbound prover. The carry is
   now held only across cycle 0 (a `carry_hold` mask over rows 0..6) and zeroed
   afterwards, which is exactly as long as it is load-bearing. 0 out of 20 after.
   Winterfell 0.13 has no witness randomization, so "not verbatim on the wire" is
   the honest claim; formal zero-knowledge is not.
2. **The public-input negative tests are not the soundness gate.** Tests 2 and 3
   below only vary what the verifier is told, and the boundary assertions alone
   make them pass — they would pass with no start-tie at all. The gate is a forged
   *trace* (hash secret A, carry member B), in `riverrun-stark`'s
   `a_trace_that_hashes_one_secret_and_carries_another_yields_no_accepted_proof`.
   Deleting the start-tie was checked to make that test fail (the forged proof
   verifies), so it is load-bearing rather than decorative.

The original plan follows. It is the de-risked plan
for audit-critical #1c. It is deliberately detailed so the implementation is a
careful mechanical exercise, not a research gamble — because a subtly-wrong AIR
here is *false soundness* (the proof appears to bind the nullifier but doesn't),
which is worse than the current honest gap.

## Goal

One STARK proof that witnesses, for a single secret `v = (v0, v1)`:
- **membership:** `Rescue(v)` is a leaf under the public root `R` (already done,
  `air.rs`/`prover.rs`); and
- **nullifier binding:** `n = Rescue(v0, v1, round)` for the public `round`,
  exposing `n` as a public output.

Public inputs: `{ root R, nullifier n, round }`. Private: `v`, leaf index, path.

The load-bearing property: the *same* `v` feeds both hashes. Miss the constraint
that ties them and a member can prove membership of leaf B while presenting the
nullifier of an unrelated value A → they double-act with a fresh A each round.
That tie (the "start-tie" below) is the soundness crux.

## Trace layout

Width **9** (was 7). Columns:

| col | meaning |
|---|---|
| 0..5 | Rescue state (STATE_WIDTH=6: rate [0..3], capacity [4,5]) |
| 6 | Merkle index bit |
| 7, 8 | **carry**: `v0, v1`, held constant for the whole trace |

Cycles of `HASH_CYCLE_LEN = 8` steps. Total = `(d + 2)` cycles for tree depth `d`
(one nullifier cycle + `d+1` Merkle cycles). Trace length must be a power of two
⇒ `d + 2 ∈ {2,4,8,16}` ⇒ **valid tree depths d ∈ {2, 6, 14}** (sizes 4, 64, 16384).
(`riverrun-pool-zk::VALID_WIDTHS` must switch to `{4, 64, 16384}` for the bound
scheme.)

### Cycle 0 — nullifier hash (rows 0..7)
- Row 0 init: `[v0, v1, round, 0, 0, 0, bit, v0, v1]`.
- Rows 0..6: 7 Rescue rounds on `[0..5]` (same `enforce_round`/`apply_round`).
- Row 7 (`hash_flag=0`, the "insertion" row): after the rounds, `[0,1]` holds
  `n = Rescue(v0,v1,round)`. The transition **loads the Merkle-leaf init** for the
  next cycle: `next[0]=cur[7] (=v0)`, `next[1]=cur[8] (=v1)`, `next[2..5]=0`.

### Cycles 1..d+1 — Merkle path (rows 8..end)
Identical to the current `air.rs`/`prover.rs` Merkle logic (leaf hash of `v` in
cycle 1, then sibling insertion + hash up to `R`).

## Periodic columns

1. `hash_flag` — period 8, `[1,1,1,1,1,1,1,0]` (existing). Gates Rescue rounds.
2. `start_mask` — length = trace_length, `1` at row 0 only. Gates the start-tie.
3. `null_ins_mask` — length = trace_length, `1` at row 7 only. Gates cycle-0's
   load-merkle-init (distinguishes it from Merkle insertion rows 15, 23, …).
4. Rescue round constants (existing).

`start_mask` and `null_ins_mask` are one-shot masks: build them in
`get_periodic_column_values()` as vectors of `self.trace_length()` with a single
`ONE`. Their period equals the trace length (they appear once).

## Transition constraints

Let `hash_flag`, `start`, `null_ins` be the periodic values.

1. **Rescue rounds** (existing): `enforce_round(result[0..6], cur[0..6],
   next[0..6], ark, hash_flag)`. Degree 5, cycle 8.
2. **Carry constant** (every row): `are_equal(next[7], cur[7])`,
   `are_equal(next[8], cur[8])`. Degree 1.
3. **Start-tie** (row 0, the soundness crux): `start * are_equal(cur[0], cur[7])`
   and `start * are_equal(cur[1], cur[8])`. Ties the nullifier-hash input to the
   carried value that the Merkle path will hash. Degree 1 × (mask of period
   trace_len).
4. **Cycle-0 load** (row 7): gated by `null_ins`:
   `next[0]=cur[7]`, `next[1]=cur[8]`, `next[2]=next[3]=next[4]=next[5]=0`.
5. **Merkle insertion** (rows 15,23,…): gated by `hash_flag_init AND NOT null_ins`
   i.e. `(not(hash_flag)) * (1 - null_ins)` — the existing bit-based placement +
   capacity reset.
6. **Index bit binary** (existing): `is_binary(cur[6])`.

Note the split of the old "insertion" constraint (which used `not(hash_flag)`)
into (4) for cycle 0 and (5) for Merkle cycles, selected by `null_ins`.

## Boundary assertions

- Public: `col0 @ last = R[0]`, `col1 @ last = R[1]` (existing).
- Public: `col0 @ step 7 = n[0]`, `col1 @ step 7 = n[1]` (the nullifier digest,
  read *before* the row-7 load transition overwrites `[0,1]`).
- Public: `col2 @ step 0 = round`.
- `col3 @ 0 = col4 @ 0 = col5 @ 0 = 0` (nullifier-hash padding + capacity).
- Periodic capacity resets `col4, col5 = 0` at each cycle start (existing).

No public assertion on `v0, v1` (private) — they are tied via constraint (3).

## Constraint-degree accounting (the fiddly part)

`AirContext::new(trace_info, degrees, num_assertions, options)`. `num_assertions`
grows from 4 to ~7. Each masked constraint's `TransitionConstraintDegree` must
declare the periodic columns it multiplies:
- Rescue rounds: `with_cycles(5, vec![8])` (existing).
- Carry: `new(1)`.
- Start-tie: `with_cycles(1, vec![trace_len])` — mask period = trace length.
- Cycle-0 load: `with_cycles(1, vec![trace_len])`.
- Merkle insertion: `with_cycles(1, vec![8, trace_len])` (masked by both).
- Bit binary: `new(2)`.

Getting these wrong yields a Winterfell "constraint degree" panic at prove time —
loud, not silent, so it fails safe.

## Prover (`build_trace`) changes

Width 9, `trace_length = (branch.len() + 1) * 8` (extra nullifier cycle).
- `init`: `[v0, v1, round, 0,0,0, bit, v0, v1]`.
- step closure: cycle 0 rows 0..6 → `apply_round`; row 7 → load `[v0,v1,0,0,0,0]`
  from carry; cycles 1..d+1 → existing Merkle logic (offset by one cycle).
- Keep `trace.set(6, 1, ONE)` degree-stabilizer trick.
- Carry: write `state[7]=v0, state[8]=v1` and never mutate them.

## Tests — the gate (a passing happy path is NOT enough)

1. `bound_membership_proves_and_verifies` — valid `(v, index, round)` → prove +
   verify OK, and the exposed `n` equals `Rescue(v0,v1,round)`.
2. **SOUNDNESS (the real gate)** `wrong_nullifier_is_rejected` — take a valid
   proof, verify against a **different** public `n'` → must FAIL. This is what
   proves the binding exists. Without this passing, 1c is not done.
3. **SOUNDNESS** `nullifier_for_other_secret_is_rejected` — prove membership of
   member A but claim `n` derived from member B's secret → must FAIL (exercises
   the start-tie).
4. `wrong_root_rejected`, `wrong_round_rejected`.

## Wiring (only after all soundness tests pass)

- `riverrun-stark`: new `prove_bound(set, v, index, round) -> Vec<u8>` and
  `verify_bound(root, nullifier, round, proof) -> bool`.
- `riverrun-pool-zk`: `Execution` unchanged in shape, but the proof now *binds*
  the nullifier; drop the module note about the unbound nullifier; switch
  `VALID_WIDTHS` to `{4,64,16384}`.
- Then, and only then, update the README Security status: audit-critical #1 is
  closed off-chain (secret off the wire **and** nullifier bound); on-chain
  verification (step 2, trusted-relayer model) remains.

## Honest note

Even when tests 1–4 pass, a hand-rolled AIR deserves independent review before any
production claim — a passing negative test is necessary, not sufficient, for
soundness. Until reviewed, describe 1c as "implemented, tests pass, unaudited".
