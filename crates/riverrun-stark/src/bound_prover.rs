//! Prover for the nullifier-binding AIR (see `bound_air.rs`).
//!
//! Adapted from the Winterfell v0.13 `merkle` example prover (MIT), with the
//! nullifier cycle prepended and the two carry columns added.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use crate::bound_air::NULLIFIER_STEP;
use crate::{
    rescue, BaseElement, BoundMerkleAir, BoundPublicInputs, DefaultRandomCoin, ElementHasher,
    FieldElement, PhantomData, ProofOptions, Prover, BOUND_TRACE_WIDTH, CARRY_0, CARRY_1,
    HASH_CYCLE_LEN, HASH_STATE_WIDTH, NUM_HASH_ROUNDS,
};

pub struct BoundMerkleProver<H: ElementHasher> {
    options: ProofOptions,
    /// Overrides the action published with the proof, instead of reading it back
    /// out of the trace. Only the soundness tests set this: it is how a dishonest
    /// prover would hash one action into their leaf and announce another.
    declared_action: Option<[BaseElement; 2]>,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> BoundMerkleProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, declared_action: None, _hasher: PhantomData }
    }

    #[cfg(test)]
    pub(crate) fn declaring_action(options: ProofOptions, action: [BaseElement; 2]) -> Self {
        Self { options, declared_action: Some(action), _hasher: PhantomData }
    }

    /// Build the execution trace for `value` at `index` under `branch` (the leaf
    /// digest followed by the sibling path), binding the nullifier for `round`.
    pub fn build_trace(
        &self,
        value: [BaseElement; 2],
        branch: &[rescue::Hash],
        index: usize,
        round: BaseElement,
        action: [BaseElement; 2],
    ) -> TraceTable<BaseElement> {
        self.build_trace_with_carry(value, value, branch, index, round, action)
    }

    /// The same trace, but with the value that feeds the **nullifier hash**
    /// (`hashed`) separated from the one that feeds the **Merkle path** (`carried`).
    ///
    /// An honest prover always passes the same secret for both; the separation
    /// exists so the soundness tests can attempt the attack the start-tie is meant
    /// to stop — proving membership of one member while presenting another's
    /// nullifier — and observe that no accepted proof comes out.
    pub(crate) fn build_trace_with_carry(
        &self,
        hashed: [BaseElement; 2],
        carried: [BaseElement; 2],
        branch: &[rescue::Hash],
        index: usize,
        round: BaseElement,
        action: [BaseElement; 2],
    ) -> TraceTable<BaseElement> {
        // one cycle for the nullifier hash, one for the leaf hash, one per path node
        let trace_length = (branch.len() + 1) * HASH_CYCLE_LEN;
        assert!(
            trace_length.is_power_of_two(),
            "the bound scheme spends an extra hash cycle, so the anonymity set must have \
             4, 64 or 16384 leaves (tree depth 2, 6 or 14); this branch implies a trace \
             length of {trace_length}, which is not a power of two"
        );
        let mut trace = TraceTable::new(BOUND_TRACE_WIDTH, trace_length);

        // skip the first node of the branch: the leaf is computed in the trace as hash(value)
        let branch = &branch[1..];

        trace.fill(
            |state| {
                // cycle 0 absorbs (v0, v1, round) — exactly what `nullifier()` hashes
                state[0] = hashed[0];
                state[1] = hashed[1];
                state[2] = round;
                state[3..].fill(BaseElement::ZERO);
                state[CARRY_0] = carried[0];
                state[CARRY_1] = carried[1];
            },
            |step, state| {
                let cycle_num = step / HASH_CYCLE_LEN;
                let cycle_pos = step % HASH_CYCLE_LEN;

                if cycle_pos < NUM_HASH_ROUNDS {
                    rescue::apply_round(&mut state[..HASH_STATE_WIDTH], step);
                } else if cycle_num == 0 {
                    // the nullifier is now in [0, 1] (read as a boundary assertion at
                    // step NULLIFIER_STEP); reload the state with the carried secret
                    // so the Merkle path hashes the same value
                    state[0] = state[CARRY_0];
                    state[1] = state[CARRY_1];
                    // the leaf commits to the action too: Rescue(v0, v1, a0, a1)
                    state[2] = action[0];
                    state[3] = action[1];
                    state[4] = BaseElement::ZERO;
                    state[5] = BaseElement::ZERO;
                    // the carry has done its job; clear it so the column is not
                    // constant (a constant column has a constant low-degree
                    // extension, which would put the secret in every FRI opening)
                    state[CARRY_0] = BaseElement::ZERO;
                    state[CARRY_1] = BaseElement::ZERO;
                } else {
                    // insert the next branch node in the position given by the index bit
                    let branch_node = branch[cycle_num - 1].to_elements();
                    let index_bit = BaseElement::new(((index >> (cycle_num - 1)) & 1) as u128);
                    if index_bit == BaseElement::ZERO {
                        state[2] = branch_node[0];
                        state[3] = branch_node[1];
                    } else {
                        state[2] = state[0];
                        state[3] = state[1];
                        state[0] = branch_node[0];
                        state[1] = branch_node[1];
                    }
                    state[4] = BaseElement::ZERO;
                    state[5] = BaseElement::ZERO;
                    state[6] = index_bit;
                }
            },
        );

        // same degree stabilizer as the unbound AIR: keep the index bit register
        // free of repeating patterns (real bits only enter after step 7)
        trace.set(6, 1, FieldElement::ONE);

        trace
    }
}

impl<H: ElementHasher> Prover for BoundMerkleProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = BoundMerkleAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BoundPublicInputs {
        let last_step = trace.length() - 1;
        BoundPublicInputs {
            tree_root: [trace.get(0, last_step), trace.get(1, last_step)],
            nullifier: [trace.get(0, NULLIFIER_STEP), trace.get(1, NULLIFIER_STEP)],
            round: trace.get(2, 0),
            action: self
                .declared_action
                .unwrap_or([trace.get(2, HASH_CYCLE_LEN), trace.get(3, HASH_CYCLE_LEN)]),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}
