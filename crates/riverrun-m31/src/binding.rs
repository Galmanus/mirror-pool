//! Prove, as one Circle-STARK proof, that a leaf and a nullifier are bound to
//! the SAME secret: `leaf = Poseidon2(secret ‖ action)` and
//! `nullifier = Poseidon2(secret ‖ round)`, two permutation calls sharing one
//! private witness. This is riverrun's §1a + §1c relation
//! (`docs/M31_CIRCLE_STARK.md`): the constraint whose deletion must break a
//! test, carried over in intent from `riverrun-stark`'s f128 `bound_nullifier`
//! test. A prover cannot present one member's leaf bound to a different
//! member's nullifier, because both permutations read the same private
//! `secret` cells the trace commits to.
//!
//! Both permutations live in the SAME row via `p3_poseidon2_air`'s
//! `VectorizedPoseidon2Air` (`VECTOR_LEN = 2`), not two separate rows: the
//! shared-secret constraint is then a same-row equality between the two
//! blocks' input cells, needing no cross-row (`next_slice`) machinery at all.
//!
//! **Not yet built, named honestly:** §1b, the variable-depth Merkle-
//! membership fold that binds `leaf` under a public root. This module proves
//! secret-sharing between exactly two permutation calls; membership under a
//! root is real, separate, unstarted work layered on top, not implied here.
//!
//! **Provisional, not a settled security decision:** the 8-limb secret / 8-limb
//! context split of the 16-M31-element input is a concrete choice made to have
//! something real to prove against, not a reviewed sponge-capacity argument.
//! Revisit before this is treated as production-ready.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_mersenne_31::{
    GenericPoseidon2LinearLayersMersenne31, Mersenne31, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL, MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{generate_vectorized_trace_rows, num_cols, Poseidon2Cols, RoundConstants, VectorizedPoseidon2Air};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

use crate::permutation::{permute, WIDTH};

/// Two permutations packed per row: block 0 is the leaf, block 1 the nullifier.
const VECTOR_LEN: usize = 2;
/// Input cells `[0..SECRET_LEN)` are the shared, private secret.
pub const SECRET_LEN: usize = 8;
/// Input cells `[SECRET_LEN..WIDTH)` are the block's public context (`action`
/// for the leaf block, `round` for the nullifier block).
pub const CONTEXT_LEN: usize = WIDTH - SECRET_LEN;

const SBOX_DEGREE: u64 = 5;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 14;

type Val = Mersenne31;
type LinearLayers = GenericPoseidon2LinearLayersMersenne31;
type InnerAir = VectorizedPoseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;
type Cols<T> =
    Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

type Challenge = BinomialExtensionField<Val, 3>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// riverrun's binding AIR: internal correctness of both permutations (from
/// `VectorizedPoseidon2Air`), plus riverrun's own constraints: each block's
/// context input and output are bound to public values, AND block 0's secret
/// cells equal block 1's secret cells. That last equality is the whole point:
/// it is the only thing that makes this "the same member's leaf and nullifier"
/// rather than two unrelated permutation calls.
struct BindingAir {
    inner: InnerAir,
}

impl BindingAir {
    fn new() -> Self {
        let constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
            RoundConstants::new(
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
                MERSENNE31_POSEIDON2_RC_16_INTERNAL,
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
            );
        Self { inner: InnerAir::new(constants) }
    }
}

impl BaseAir<Val> for BindingAir {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn num_public_values(&self) -> usize {
        2 * CONTEXT_LEN + 2 * WIDTH
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for BindingAir {
    fn eval(&self, builder: &mut AB) {
        // Everything VectorizedPoseidon2Air already proves: both permutations
        // in this row are internally consistent executions.
        self.inner.eval(builder);

        let main = builder.main();
        let full = main.current_slice();
        let single_width =
            num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        let block0: &Cols<AB::Var> = full[..single_width].borrow();
        let block1: &Cols<AB::Var> = full[single_width..2 * single_width].borrow();

        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        // pis layout: action(CONTEXT_LEN) | round(CONTEXT_LEN) | leaf(WIDTH) | nullifier(WIDTH)
        let action = &pis[0..CONTEXT_LEN];
        let round = &pis[CONTEXT_LEN..2 * CONTEXT_LEN];
        let leaf = &pis[2 * CONTEXT_LEN..2 * CONTEXT_LEN + WIDTH];
        let nullifier = &pis[2 * CONTEXT_LEN + WIDTH..2 * CONTEXT_LEN + 2 * WIDTH];

        let block0_output = &block0.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
        let block1_output = &block1.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        for i in 0..CONTEXT_LEN {
            builder.assert_eq(block0.inputs[SECRET_LEN + i].into(), action[i].into());
            builder.assert_eq(block1.inputs[SECRET_LEN + i].into(), round[i].into());
        }
        for i in 0..WIDTH {
            builder.assert_eq(block0_output[i].into(), leaf[i].into());
            builder.assert_eq(block1_output[i].into(), nullifier[i].into());
        }
        // The binding: both blocks' secret cells must be the same private
        // witness. This is the constraint that, deleted, would let a prover
        // mix one member's leaf with a different member's nullifier.
        for i in 0..SECRET_LEN {
            builder.assert_eq(block0.inputs[i].into(), block1.inputs[i].into());
        }
    }
}

/// Production security level: 40 FRI queries. Use [`make_config_tuned`]
/// directly only for parameter-sweep measurement, never to ship a weaker
/// proof under this name.
fn make_config() -> Config {
    make_config_tuned(40)
}

/// Same construction as [`make_config`], with the FRI query count exposed.
/// Not a way to weaken production proofs: `prove_binding`/`verify_binding`
/// always call [`make_config`] with the real parameter. This exists so a
/// caller who explicitly wants a different point on the size/security
/// tradeoff (e.g. measuring on-chain verification cost at a proof size that
/// fits a transaction's message-size limit) can ask for it by name, and the
/// reduced-security choice is visible at every call site, not hidden.
pub fn make_config_tuned(num_queries: usize) -> Config {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs { mmcs: val_mmcs, fri_params, _phantom: PhantomData };
    let challenger = Challenger::from_hasher(Vec::new(), byte_hash);
    Config::new(pcs, challenger)
}

fn to_field(input: [u64; WIDTH]) -> [Val; WIDTH] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

fn ctx_to_field(input: [u64; CONTEXT_LEN]) -> [Val; CONTEXT_LEN] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

/// Pack a secret and a context (action or round) into one permutation input.
fn pack(secret: [u64; SECRET_LEN], context: [u64; CONTEXT_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..SECRET_LEN].copy_from_slice(&secret);
    out[SECRET_LEN..].copy_from_slice(&context);
    out
}

/// A real Circle-STARK proof that a leaf and a nullifier share one secret.
pub struct BindingProof {
    inner: Proof<Config>,
}

impl BindingProof {
    /// Serialize to bytes (`bincode`, over `Proof`'s own `serde` impl), the
    /// wire format an on-chain verifier reads from instruction data.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof<Config> is always serializable")
    }

    /// Deserialize from bytes produced by [`BindingProof::to_bytes`]. `None`
    /// on malformed input; callers on-chain treat that as proof rejection.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }
}

/// Prove that `leaf = permute(secret ‖ action)` and
/// `nullifier = permute(secret ‖ round)` for one shared `secret`, returning the
/// proof and both public outputs. Production security level (40 FRI queries).
pub fn prove_binding(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
) -> (BindingProof, [u64; WIDTH], [u64; WIDTH]) {
    prove_binding_tuned(secret, action, round, 40)
}

/// Same as [`prove_binding`], with the FRI query count exposed. See
/// [`make_config_tuned`]'s doc: not a way to ship a weaker proof under the
/// production name, a way to measure a different, explicit point on the
/// size/security tradeoff (e.g. a proof small enough to fit a transaction's
/// message-size limit, for on-chain verification-cost measurement).
pub fn prove_binding_tuned(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
) -> (BindingProof, [u64; WIDTH], [u64; WIDTH]) {
    let leaf_input = pack(secret, action);
    let nullifier_input = pack(secret, round);
    let leaf_output = permute(leaf_input);
    let nullifier_output = permute(nullifier_input);

    let air = BindingAir::new();
    // 8 permutation inputs / VECTOR_LEN=2 => 4 rows, the (leaf, nullifier)
    // pair repeated to satisfy CirclePcs's minimum committable domain size,
    // the same repeated-statement pattern `permutation.rs` already uses.
    let inputs: Vec<[Val; WIDTH]> = vec![
        to_field(leaf_input),
        to_field(nullifier_input),
        to_field(leaf_input),
        to_field(nullifier_input),
        to_field(leaf_input),
        to_field(nullifier_input),
        to_field(leaf_input),
        to_field(nullifier_input),
    ];
    let constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
        RoundConstants::new(
            MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            MERSENNE31_POSEIDON2_RC_16_INTERNAL,
            MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
    let trace: RowMajorMatrix<Val> = generate_vectorized_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
        VECTOR_LEN,
    >(inputs, &constants, 0);

    let pis = public_values(action, round, leaf_output, nullifier_output);
    let config = make_config_tuned(num_queries);
    let proof = prove(&config, &air, trace, &pis);
    (BindingProof { inner: proof }, leaf_output, nullifier_output)
}

fn public_values(
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; WIDTH],
    nullifier: [u64; WIDTH],
) -> Vec<Val> {
    let mut pis = Vec::with_capacity(2 * CONTEXT_LEN + 2 * WIDTH);
    pis.extend_from_slice(&ctx_to_field(action));
    pis.extend_from_slice(&ctx_to_field(round));
    pis.extend_from_slice(&to_field(leaf));
    pis.extend_from_slice(&to_field(nullifier));
    pis
}

/// Verify a [`BindingProof`] against claimed `action`, `round`, `leaf`, and
/// `nullifier` public values. `true` only if the proof is well-formed and
/// verifies exactly against this tuple, including the shared-secret binding.
pub fn verify_binding(
    proof: &BindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; WIDTH],
    nullifier: [u64; WIDTH],
) -> bool {
    verify_binding_tuned(proof, action, round, leaf, nullifier, 40)
}

/// Same as [`verify_binding`], with the FRI query count exposed; must match
/// whatever count the proof was produced with ([`prove_binding_tuned`]).
pub fn verify_binding_tuned(
    proof: &BindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; WIDTH],
    nullifier: [u64; WIDTH],
    num_queries: usize,
) -> bool {
    let air = BindingAir::new();
    let config = make_config_tuned(num_queries);
    let pis = public_values(action, round, leaf, nullifier);
    verify(&config, &air, &proof.inner, &pis).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u64) -> [u64; SECRET_LEN] {
        core::array::from_fn(|i| byte * 1000 + i as u64)
    }

    fn context(byte: u64) -> [u64; CONTEXT_LEN] {
        core::array::from_fn(|i| byte * 2000 + i as u64)
    }

    #[test]
    fn a_genuine_shared_secret_binding_proves_and_verifies() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) = prove_binding(s, action, round);
        assert!(
            verify_binding(&proof, action, round, leaf, nullifier),
            "a genuine leaf+nullifier pair sharing one secret must verify"
        );
    }

    #[test]
    fn a_leaf_output_does_not_verify_if_tampered() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) = prove_binding(s, action, round);
        let mut wrong_leaf = leaf;
        wrong_leaf[0] ^= 1;
        assert!(
            !verify_binding(&proof, action, round, wrong_leaf, nullifier),
            "a proof must not verify against a tampered leaf"
        );
    }

    #[test]
    fn a_nullifier_output_does_not_verify_if_tampered() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) = prove_binding(s, action, round);
        let mut wrong_nullifier = nullifier;
        wrong_nullifier[0] ^= 1;
        assert!(
            !verify_binding(&proof, action, round, leaf, wrong_nullifier),
            "a proof must not verify against a tampered nullifier"
        );
    }

    #[test]
    fn swapping_in_a_different_members_nullifier_output_fails() {
        // Alice's own proof (her leaf bound to her nullifier) must not verify
        // against Bob's nullifier output, even though Bob's nullifier is a
        // perfectly real, independently valid output for SOME proof (his
        // own). This is the outward-facing check that a leaf cannot be
        // paired with a stranger's nullifier and still verify.
        let alice = secret(1);
        let bob = secret(2);
        let action = context(1);
        let round = context(2);
        let (alice_proof, alice_leaf, _alice_nullifier) = prove_binding(alice, action, round);
        let (_bob_proof, _bob_leaf, bob_nullifier) = prove_binding(bob, action, round);
        assert!(
            !verify_binding(&alice_proof, action, round, alice_leaf, bob_nullifier),
            "alice's proof must not verify against bob's nullifier"
        );
    }

    #[test]
    #[should_panic]
    fn a_trace_built_from_two_different_secrets_cannot_even_be_proved() {
        // The strongest form of the soundness claim: attempting to build a
        // trace where the leaf block and the nullifier block use DIFFERENT
        // secrets does not merely fail verification later, it fails to
        // produce a satisfying trace at all (the shared-secret constraint is
        // violated at proving time). Mirrors `permutation.rs`'s own
        // documented behavior ("Panics if input does not actually..."):
        // Plonky3's prover panics on an unsatisfiable constraint set rather
        // than silently emitting a broken proof.
        let alice = secret(1);
        let bob = secret(2);
        let action = context(1);
        let round = context(2);

        let leaf_input = pack(alice, action);
        let nullifier_input = pack(bob, round); // deliberately the WRONG secret
        let leaf_output = permute(leaf_input);
        let nullifier_output = permute(nullifier_input);

        let air = BindingAir::new();
        let inputs: Vec<[Val; WIDTH]> = vec![
            to_field(leaf_input),
            to_field(nullifier_input),
            to_field(leaf_input),
            to_field(nullifier_input),
            to_field(leaf_input),
            to_field(nullifier_input),
            to_field(leaf_input),
            to_field(nullifier_input),
        ];
        let constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
            RoundConstants::new(
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
                MERSENNE31_POSEIDON2_RC_16_INTERNAL,
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
            );
        let trace: RowMajorMatrix<Val> = generate_vectorized_trace_rows::<
            Val,
            LinearLayers,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
            VECTOR_LEN,
        >(inputs, &constants, 0);
        let pis = public_values(action, round, leaf_output, nullifier_output);
        let config = make_config();
        // Expected to panic: the shared-secret constraint is violated.
        let _ = prove(&config, &air, trace, &pis);
    }

    #[test]
    fn a_proof_survives_a_byte_round_trip() {
        // The wire format an on-chain verifier actually reads: serialize,
        // deserialize, and confirm the round-tripped proof still verifies
        // against the same public values, exactly as the original did.
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) = prove_binding(s, action, round);
        let bytes = proof.to_bytes();
        eprintln!("BindingProof serialized size: {} bytes", bytes.len());
        let round_tripped = BindingProof::from_bytes(&bytes).expect("valid bytes must deserialize");
        assert!(
            verify_binding(&round_tripped, action, round, leaf, nullifier),
            "a proof must still verify after a to_bytes/from_bytes round trip"
        );
    }

    #[test]
    fn garbage_bytes_do_not_deserialize_into_a_proof() {
        let garbage = [0xFFu8; 64];
        assert!(BindingProof::from_bytes(&garbage).is_none(), "malformed bytes must not parse as a proof");
    }
}
