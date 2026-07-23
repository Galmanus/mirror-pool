//! The **nullifier-binding** membership AIR (audit-critical #1c).
//!
//! Extends the Merkle-path AIR (`air.rs`, adapted from the Winterfell v0.13
//! `merkle` example, MIT) with one extra hash cycle that computes the per-round
//! nullifier `n = Rescue(v0, v1, round)` from the *same* secret `v` whose leaf
//! `Rescue(v0, v1, a0, a1)` the Merkle path then resolves to the public root.
//!
//! The leaf commits to the **action** as well as the secret, which is what makes
//! this "Tornado for behaviour" rather than an anonymous nullifier set: a member
//! commits an intent and can later execute *that* intent, not any intent. The
//! action is public, so the AIR pins it directly as a constant when the Merkle
//! leaf preimage is loaded.
//!
//! Public inputs: `{root, nullifier, round, action}`. Private: `v`, leaf index,
//! path.
//!
//! Layout (trace width 9, cycles of 8 steps, `d` = tree depth):
//!
//! | col | meaning |
//! |---|---|
//! | 0..5 | Rescue state (rate `[0..3]`, capacity `[4,5]`) |
//! | 6 | Merkle index bit |
//! | 7, 8 | carry: `v0, v1`, held only across cycle 0, then zeroed |
//!
//! The carry is deliberately **not** constant for the whole trace. A column that
//! is constant has a constant low-degree extension, so every FRI query opening
//! would hand the verifier the secret verbatim — measured, before this was fixed,
//! at 20 leaks out of 20 proofs. Confining the carry to the eight rows where it is
//! load-bearing keeps the column non-constant (0 out of 20). This is "the witness
//! is not verbatim on the wire", not a formal zero-knowledge guarantee: Winterfell
//! 0.13 has no witness randomization.
//!
//! - cycle 0 (rows 0..7): `[v0, v1, round, 0, 0, 0]` → 7 Rescue rounds → row 7
//!   holds `n` in `[0,1]`. The row-7 transition then loads the Merkle leaf
//!   preimage: `next[0,1] = cur[7,8]` (the carried secret) and
//!   `next[2,3] = action` (public), `next[4,5] = 0`.
//! - cycles 1..d+1: the existing Merkle logic (leaf hash, then path merges).
//!
//! The soundness crux is the *start-tie*: at row 0, `cur[0] == cur[7]` and
//! `cur[1] == cur[8]`. Without it a prover could hash secret A into the nullifier
//! while carrying member B into the Merkle path — proving membership under one
//! secret and acting under another's nullifier. See
//! `docs/1c-nullifier-binding-design.md`.

use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use crate::{
    rescue, BaseElement, FieldElement, BOUND_TRACE_WIDTH, CARRY_0, CARRY_1, HASH_CYCLE_LEN,
    HASH_STATE_WIDTH, NUM_HASH_ROUNDS,
};

/// Row at which the nullifier digest is readable in columns `[0, 1]` — after the
/// seven Rescue rounds of cycle 0, before the row-7 transition overwrites them.
pub const NULLIFIER_STEP: usize = NUM_HASH_ROUNDS;

pub struct BoundPublicInputs {
    pub tree_root: [BaseElement; 2],
    pub nullifier: [BaseElement; 2],
    pub round: BaseElement,
    pub action: [BaseElement; 2],
}

impl ToElements<BaseElement> for BoundPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.tree_root[0],
            self.tree_root[1],
            self.nullifier[0],
            self.nullifier[1],
            self.round,
            self.action[0],
            self.action[1],
        ]
    }
}

pub struct BoundMerkleAir {
    context: AirContext<BaseElement>,
    tree_root: [BaseElement; 2],
    nullifier: [BaseElement; 2],
    round: BaseElement,
    action: [BaseElement; 2],
}

impl Air for BoundMerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = BoundPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: BoundPublicInputs, options: ProofOptions) -> Self {
        let trace_len = trace_info.length();
        // Columns 0..5 aggregate three families of terms: the Rescue rounds
        // (degree 5, cycle 8), the Merkle insertion (degree 2, cycles 8 and
        // trace_len) and the cycle-0 load (degree 1, cycle trace_len). The Rescue
        // family dominates, so its degree bounds the slot.
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            // index bit is binary
            TransitionConstraintDegree::new(2),
            // carry columns: held across cycle 0 (degree 1) plus the start-tie,
            // both masked by columns whose period is the whole trace length.
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
        ];
        assert_eq!(BOUND_TRACE_WIDTH, trace_info.width());
        BoundMerkleAir {
            context: AirContext::new(trace_info, degrees, 8, options),
            tree_root: pub_inputs.tree_root,
            nullifier: pub_inputs.nullifier,
            round: pub_inputs.round,
            action: pub_inputs.action,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        debug_assert_eq!(BOUND_TRACE_WIDTH, current.len());
        debug_assert_eq!(BOUND_TRACE_WIDTH, next.len());

        let hash_flag = periodic_values[0];
        let start = periodic_values[1];
        let null_ins = periodic_values[2];
        let carry_hold = periodic_values[3];
        let ark = &periodic_values[4..];

        // when hash_flag = 1, constraints for a Rescue round are enforced
        rescue::enforce_round(
            result,
            &current[..HASH_STATE_WIDTH],
            &next[..HASH_STATE_WIDTH],
            ark,
            hash_flag,
        );

        let hash_init_flag = not(hash_flag);
        // cycle boundaries split in two: row 7 loads the Merkle leaf preimage from
        // the carry (the nullifier cycle just ended), every later boundary inserts
        // the next path node.
        let merkle_ins = hash_init_flag * not(null_ins);

        // Merkle insertion: when the index bit is 0 the accumulated hash stays in
        // registers [0, 1] and the sibling goes into [2, 3]; when it is 1 they swap.
        let bit = next[6];
        let not_bit = not(bit);
        result.agg_constraint(0, merkle_ins, not_bit * are_equal(current[0], next[0]));
        result.agg_constraint(1, merkle_ins, not_bit * are_equal(current[1], next[1]));
        result.agg_constraint(2, merkle_ins, bit * are_equal(current[0], next[2]));
        result.agg_constraint(3, merkle_ins, bit * are_equal(current[1], next[3]));

        // cycle-0 load: the leaf preimage is the carried secret followed by the
        // public action, so the leaf the Merkle path resolves commits to both.
        result.agg_constraint(0, null_ins, are_equal(next[0], current[CARRY_0]));
        result.agg_constraint(1, null_ins, are_equal(next[1], current[CARRY_1]));
        result.agg_constraint(2, null_ins, are_equal(next[2], E::from(self.action[0])));
        result.agg_constraint(3, null_ins, are_equal(next[3], E::from(self.action[1])));

        // capacity registers are reset to zero at every cycle boundary, of either kind
        result.agg_constraint(4, hash_init_flag, is_zero(next[4]));
        result.agg_constraint(5, hash_init_flag, is_zero(next[5]));

        // the index bit register must be binary
        result[6] = is_binary(current[6]);

        // the carry holds the secret unchanged across cycle 0, which is exactly as
        // long as it is needed: row 0 ties it to the nullifier input, row 7 loads it
        // into the Merkle path. Past that it is free (and the prover zeroes it, so
        // the column is not constant — see the module note on FRI openings).
        result.agg_constraint(7, carry_hold, are_equal(next[CARRY_0], current[CARRY_0]));
        result.agg_constraint(8, carry_hold, are_equal(next[CARRY_1], current[CARRY_1]));
        // ...and at row 0 it is tied to the input of the nullifier hash. This is
        // what makes one secret serve both halves of the statement.
        result.agg_constraint(7, start, are_equal(current[0], current[CARRY_0]));
        result.agg_constraint(8, start, are_equal(current[1], current[CARRY_1]));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            // the Merkle path resolves to the public root
            Assertion::single(0, last_step, self.tree_root[0]),
            Assertion::single(1, last_step, self.tree_root[1]),
            // cycle 0 produced the public nullifier
            Assertion::single(0, NULLIFIER_STEP, self.nullifier[0]),
            Assertion::single(1, NULLIFIER_STEP, self.nullifier[1]),
            // ...from the public round, absorbed as the third rate element
            Assertion::single(2, 0, self.round),
            Assertion::single(3, 0, BaseElement::ZERO),
            // hash capacity registers are zero at every cycle start
            Assertion::periodic(4, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(5, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let trace_len = self.trace_length();

        // one-shot masks: they fire exactly once, so their period is the whole trace
        let mut start_mask = vec![BaseElement::ZERO; trace_len];
        start_mask[0] = BaseElement::ONE;
        let mut null_ins_mask = vec![BaseElement::ZERO; trace_len];
        null_ins_mask[NULLIFIER_STEP] = BaseElement::ONE;

        // holds the carry constant across cycle 0 only: transitions out of rows
        // 0..NULLIFIER_STEP-1, so rows 1..NULLIFIER_STEP equal row 0
        let mut carry_hold_mask = vec![BaseElement::ZERO; trace_len];
        carry_hold_mask[..NULLIFIER_STEP].fill(BaseElement::ONE);

        let mut result =
            vec![HASH_CYCLE_MASK.to_vec(), start_mask, null_ins_mask, carry_hold_mask];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

// MASKS
// ================================================================================================
const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];
