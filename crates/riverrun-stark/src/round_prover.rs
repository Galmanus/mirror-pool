//! Prover for the batched round AIR (see `round_air.rs`).
//!
//! Fills one sub-trace per member, back to back. The only thing the step
//! function does differently from the single-member prover is re-initialise the
//! state at each seam, which is what makes the sub-traces independent.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use crate::{
    rescue, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData, ProofOptions,
    Prover, RoundAir, RoundPublicInputs, BOUND_TRACE_WIDTH, CARRY_0, CARRY_1, HASH_CYCLE_LEN,
    HASH_STATE_WIDTH, NUM_HASH_ROUNDS,
};

/// One member's witness for the round.
pub struct MemberWitness {
    pub secret: [BaseElement; 2],
    pub index: usize,
    /// Leaf digest followed by the sibling path.
    pub branch: Vec<rescue::Hash>,
}

pub struct RoundProver<H: ElementHasher> {
    options: ProofOptions,
    round: BaseElement,
    action: [BaseElement; 2],
    members: usize,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RoundProver<H> {
    pub fn new(
        options: ProofOptions,
        round: BaseElement,
        action: [BaseElement; 2],
        members: usize,
    ) -> Self {
        Self { options, round, action, members, _hasher: PhantomData }
    }

    pub fn build_trace(&self, members: &[MemberWitness]) -> TraceTable<BaseElement> {
        assert!(!members.is_empty(), "a round needs at least one member");
        let sub_len = (members[0].branch.len() + 1) * HASH_CYCLE_LEN;
        let trace_length = sub_len * members.len();
        assert!(
            trace_length.is_power_of_two(),
            "sub-trace length {sub_len} times {} members gives {trace_length} rows, \
             which is not a power of two",
            members.len()
        );
        let mut trace = TraceTable::new(BOUND_TRACE_WIDTH, trace_length);

        let round = self.round;
        let action = self.action;

        // Initialise state for member `m`: the nullifier hash absorbs
        // (secret, round), and the carry holds the secret for the load row.
        let init_member = |state: &mut [BaseElement], m: &MemberWitness| {
            state[0] = m.secret[0];
            state[1] = m.secret[1];
            state[2] = round;
            state[3] = BaseElement::ZERO;
            state[4] = BaseElement::ZERO;
            state[5] = BaseElement::ZERO;
            state[6] = BaseElement::ZERO;
            state[CARRY_0] = m.secret[0];
            state[CARRY_1] = m.secret[1];
        };

        trace.fill(
            |state| init_member(state, &members[0]),
            |step, state| {
                let next_row = step + 1;
                // seam: the next row starts a new member
                if next_row % sub_len == 0 {
                    let m = next_row / sub_len;
                    if m < members.len() {
                        init_member(state, &members[m]);
                    }
                    return;
                }

                let within = step % sub_len;
                let cycle_num = within / HASH_CYCLE_LEN;
                let cycle_pos = within % HASH_CYCLE_LEN;
                let member = &members[step / sub_len];

                if cycle_pos < NUM_HASH_ROUNDS {
                    rescue::apply_round(&mut state[..HASH_STATE_WIDTH], within);
                } else if cycle_num == 0 {
                    // the nullifier is readable at row 7; reload with the carried
                    // secret and the public action to form the Merkle leaf
                    state[0] = state[CARRY_0];
                    state[1] = state[CARRY_1];
                    state[2] = action[0];
                    state[3] = action[1];
                    state[4] = BaseElement::ZERO;
                    state[5] = BaseElement::ZERO;
                    state[CARRY_0] = BaseElement::ZERO;
                    state[CARRY_1] = BaseElement::ZERO;
                } else {
                    let branch = &member.branch[1..];
                    let node = branch[cycle_num - 1].to_elements();
                    let bit = BaseElement::new(((member.index >> (cycle_num - 1)) & 1) as u128);
                    if bit == BaseElement::ZERO {
                        state[2] = node[0];
                        state[3] = node[1];
                    } else {
                        state[2] = state[0];
                        state[3] = state[1];
                        state[0] = node[0];
                        state[1] = node[1];
                    }
                    state[4] = BaseElement::ZERO;
                    state[5] = BaseElement::ZERO;
                    state[6] = bit;
                }
            },
        );

        // the same degree stabiliser as the single-member prover, once per member
        for m in 0..members.len() {
            trace.set(6, m * sub_len + 1, FieldElement::ONE);
        }

        trace
    }
}

impl<H: ElementHasher> Prover for RoundProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = RoundAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> RoundPublicInputs {
        let last = trace.length() - 1;
        let members = self.members;
        let sub_len = trace.length() / members;
        let nullifiers = (0..members)
            .map(|i| {
                let at = i * sub_len + NUM_HASH_ROUNDS;
                [trace.get(0, at), trace.get(1, at)]
            })
            .collect();
        RoundPublicInputs {
            tree_root: [trace.get(0, last), trace.get(1, last)],
            round: trace.get(2, 0),
            action: self.action,
            nullifiers,
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
