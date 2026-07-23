//! One round, one proof: the batched membership AIR.
//!
//! riverrun's thesis is a *synchronized round* — k members performing the same
//! action at the same time — and that is exactly the structure that batches.
//! Proving each member separately costs k proofs and k verifications. Laying the
//! k sub-traces end to end in one trace costs one of each.
//!
//! Each sub-trace is the bound AIR from `bound_air.rs`, unchanged: a nullifier
//! cycle, then the Merkle path to the root, with the action pinned at the load
//! row. Three things generalise:
//!
//! 1. **The one-shot masks become periodic.** `start`, `null_ins` and
//!    `carry_hold` had the trace length as their period; here their period is the
//!    sub-trace length `L`, so they fire once per member instead of once.
//! 2. **A seam mask.** Row `L-1` of a sub-trace sits at `hash_flag = 0`, so
//!    without gating, the Merkle-insertion constraint would try to carry the last
//!    row of one member into the first row of the next. `seam` switches it off at
//!    exactly those rows.
//! 3. **Assertions repeat per member.** Each sub-trace asserts its own nullifier
//!    at its row 7 and the shared root at its last row.
//!
//! ## Who can use this, and who cannot
//!
//! A batched proof is produced by **one prover that holds every member's
//! secret**. For a crowd of independent users that is not privacy, it is a
//! custodian, and batching there needs distributed proving. For an operator who
//! controls k identities — an agent fleet, a market maker running many wallets,
//! exactly the audience the brief names — it is one prover and a 24.6x saving at
//! k=64.
//!
//! It is also *slower* to prove: 2.57 s for 64 members against 339 ms for 64
//! separate proofs, because the trace is 64x longer and the FFT is n log n. The
//! trade is prover time for proof size and verification count.
//!
//! This module deliberately mirrors `bound_air.rs` rather than abstracting over
//! it. The single-member path is shipped, tested and wired into the pool; the
//! honest move four days from a deadline is to leave it alone and duplicate,
//! with unification noted rather than attempted.

use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use crate::{
    rescue, BaseElement, FieldElement, BOUND_TRACE_WIDTH, CARRY_0, CARRY_1, HASH_CYCLE_LEN,
    HASH_STATE_WIDTH, NUM_HASH_ROUNDS,
};

/// Everything a settled round publishes.
pub struct RoundPublicInputs {
    pub tree_root: [BaseElement; 2],
    pub round: BaseElement,
    pub action: [BaseElement; 2],
    /// One per member, in sub-trace order.
    pub nullifiers: Vec<[BaseElement; 2]>,
}

impl ToElements<BaseElement> for RoundPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = vec![
            self.tree_root[0],
            self.tree_root[1],
            self.round,
            self.action[0],
            self.action[1],
        ];
        for n in &self.nullifiers {
            v.push(n[0]);
            v.push(n[1]);
        }
        v
    }
}

pub struct RoundAir {
    context: AirContext<BaseElement>,
    tree_root: [BaseElement; 2],
    round: BaseElement,
    action: [BaseElement; 2],
    nullifiers: Vec<[BaseElement; 2]>,
    /// Rows per member.
    sub_len: usize,
}

impl Air for RoundAir {
    type BaseField = BaseElement;
    type PublicInputs = RoundPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: RoundPublicInputs, options: ProofOptions) -> Self {
        let members = pub_inputs.nullifiers.len();
        assert!(members > 0, "a round needs at least one member");
        assert_eq!(
            trace_info.length() % members,
            0,
            "the trace must divide evenly into one sub-trace per member"
        );
        let sub_len = trace_info.length() / members;

        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::with_cycles(1, vec![sub_len]),
            TransitionConstraintDegree::with_cycles(1, vec![sub_len]),
        ];
        assert_eq!(BOUND_TRACE_WIDTH, trace_info.width());

        // 6 per member (nullifier x2, root x2, round, padding) + 2 periodic
        let num_assertions = members * 6 + 2;
        RoundAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            tree_root: pub_inputs.tree_root,
            round: pub_inputs.round,
            action: pub_inputs.action,
            nullifiers: pub_inputs.nullifiers,
            sub_len,
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

        let hash_flag = periodic_values[0];
        let start = periodic_values[1];
        let null_ins = periodic_values[2];
        let carry_hold = periodic_values[3];
        let seam = periodic_values[4];
        let ark = &periodic_values[5..];

        rescue::enforce_round(
            result,
            &current[..HASH_STATE_WIDTH],
            &next[..HASH_STATE_WIDTH],
            ark,
            hash_flag,
        );

        let hash_init_flag = not(hash_flag);
        // A cycle boundary is one of three things: the row-7 load, a Merkle
        // insertion, or the seam between two members — where nothing carries over.
        let merkle_ins = hash_init_flag * not(null_ins) * not(seam);

        let bit = next[6];
        let not_bit = not(bit);
        result.agg_constraint(0, merkle_ins, not_bit * are_equal(current[0], next[0]));
        result.agg_constraint(1, merkle_ins, not_bit * are_equal(current[1], next[1]));
        result.agg_constraint(2, merkle_ins, bit * are_equal(current[0], next[2]));
        result.agg_constraint(3, merkle_ins, bit * are_equal(current[1], next[3]));

        let load = null_ins * not(seam);
        result.agg_constraint(0, load, are_equal(next[0], current[CARRY_0]));
        result.agg_constraint(1, load, are_equal(next[1], current[CARRY_1]));
        result.agg_constraint(2, load, are_equal(next[2], E::from(self.action[0])));
        result.agg_constraint(3, load, are_equal(next[3], E::from(self.action[1])));

        // Capacity is zero at every cycle start, including the first row of each
        // sub-trace, so this needs no seam gating.
        result.agg_constraint(4, hash_init_flag, is_zero(next[4]));
        result.agg_constraint(5, hash_init_flag, is_zero(next[5]));

        result[6] = is_binary(current[6]);

        result.agg_constraint(7, carry_hold, are_equal(next[CARRY_0], current[CARRY_0]));
        result.agg_constraint(8, carry_hold, are_equal(next[CARRY_1], current[CARRY_1]));
        result.agg_constraint(7, start, are_equal(current[0], current[CARRY_0]));
        result.agg_constraint(8, start, are_equal(current[1], current[CARRY_1]));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut out = Vec::with_capacity(self.nullifiers.len() * 6 + 2);
        for (i, n) in self.nullifiers.iter().enumerate() {
            let base = i * self.sub_len;
            // this member's nullifier, read before the load row overwrites it
            out.push(Assertion::single(0, base + NUM_HASH_ROUNDS, n[0]));
            out.push(Assertion::single(1, base + NUM_HASH_ROUNDS, n[1]));
            // ...and this member's Merkle path resolving to the shared root
            let last = base + self.sub_len - 1;
            out.push(Assertion::single(0, last, self.tree_root[0]));
            out.push(Assertion::single(1, last, self.tree_root[1]));
            // the round absorbed by the nullifier hash, and its padding
            out.push(Assertion::single(2, base, self.round));
            out.push(Assertion::single(3, base, BaseElement::ZERO));
        }
        out.push(Assertion::periodic(4, 0, HASH_CYCLE_LEN, BaseElement::ZERO));
        out.push(Assertion::periodic(5, 0, HASH_CYCLE_LEN, BaseElement::ZERO));
        out
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let l = self.sub_len;
        let one_at = |idx: &[usize]| {
            let mut v = vec![BaseElement::ZERO; l];
            for &i in idx {
                v[i] = BaseElement::ONE;
            }
            v
        };
        let start = one_at(&[0]);
        let null_ins = one_at(&[NUM_HASH_ROUNDS]);
        let carry_hold = one_at(&(0..NUM_HASH_ROUNDS).collect::<Vec<_>>());
        let seam = one_at(&[l - 1]);

        let mut result = vec![
            HASH_CYCLE_MASK.to_vec(),
            start,
            null_ins,
            carry_hold,
            seam,
        ];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

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
