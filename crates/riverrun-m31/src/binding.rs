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
use p3_matrix::dense::RowMajorMatrix;
use p3_mersenne_31::{
    GenericPoseidon2LinearLayersMersenne31, Mersenne31, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL, MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{generate_vectorized_trace_rows, num_cols, Poseidon2Cols, RoundConstants, VectorizedPoseidon2Air};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig};

use crate::permutation::{permute, WIDTH};

/// Two permutations packed per row: block 0 is the leaf, block 1 the nullifier.
const VECTOR_LEN: usize = 2;

/// log2 of the number of quotient chunks for [`BindingAir`], pinned as a
/// constant so the verifier never runs `p3_uni_stark`'s symbolic-builder pass.
/// That pass exists only to derive this one number, and its transient
/// `SymbolicExpr` tree peaks at ~440 KB of live heap for this AIR (measured;
/// see `docs/M31_CIRCLE_STARK.md`), which is what overran Solana's 256 KB
/// heap ceiling. The AIR is fixed, so the value is a compile-time fact; the
/// test `the_pinned_quotient_chunk_count_matches_the_symbolic_pass` recomputes
/// it via the symbolic pass natively and fails if this constant ever drifts.
/// A wrong value cannot weaken soundness (it changes the expected proof shape,
/// so honest proofs would fail loudly, not forged ones pass).
pub const LOG_NUM_QUOTIENT_CHUNKS: usize = 2;
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
/// Re-export for the hiding-cost instrument, which builds the same trace.
pub(crate) type LinearLayersPub = GenericPoseidon2LinearLayersMersenne31;
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
type ByteHash = crate::keccak::SolKeccak256;
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
pub(crate) struct BindingAir {
    inner: InnerAir,
}

impl BindingAir {
    pub(crate) fn new() -> Self {
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
    /// log2 of the committed trace height, as recorded in the proof. Exposed
    /// for the privacy audit: it is the polynomial degree bound the FRI query
    /// openings have to beat for the witness to stay hidden.
    pub fn degree_bits(&self) -> usize {
        self.inner.degree_bits
    }

    /// Serialize to bytes (`bincode`, over `Proof`'s own `serde` impl), the
    /// wire format an on-chain verifier reads from instruction data.
    #[cfg(feature = "wire")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof<Config> is always serializable")
    }

    /// Deserialize from bytes produced by [`BindingProof::to_bytes`]. `None`
    /// on malformed input; callers on-chain treat that as proof rejection.
    #[cfg(feature = "wire")]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }

    /// Serialize to bytes with `postcard`, the no_std wire format a bare-wasm
    /// verifier (Soroban) reads from its host boundary. Not interchangeable
    /// with the bincode format of [`BindingProof::to_bytes`].
    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof<Config> is always serializable")
    }

    /// Deserialize from bytes produced by [`BindingProof::to_postcard`].
    /// `None` on malformed input; callers on-chain treat that as rejection.
    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
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
/// MEASUREMENT ONLY: the same statement proved over a taller trace, by
/// repeating the (leaf, nullifier) pair `2^(log_rows - 1)` times.
///
/// This is **not** a zero-knowledge variant and must never be presented as
/// one: repeated identical rows carry no entropy and hide nothing. It exists
/// to price the trace height that a hiding configuration would need. A
/// non-hiding commitment publishes enough FRI query openings to interpolate a
/// trace of 4 rows (see `examples/privacy_audit.rs`); hiding requires the
/// committed polynomial to carry more random degrees of freedom than the
/// verifier opens, i.e. a trace taller than the query count. Verification
/// cost at that height is a fact worth measuring before anyone plans on it.
pub fn prove_binding_tuned_rows(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
    log_rows: usize,
) -> (BindingProof, [u64; WIDTH], [u64; WIDTH]) {
    assert!(log_rows >= 2, "CirclePcs needs at least 4 rows");
    // Each row holds VECTOR_LEN = 2 permutations, and each repeat contributes
    // one (leaf, nullifier) pair, so rows == repeats.
    prove_binding_inner(secret, action, round, num_queries, 1 << log_rows)
}

pub fn prove_binding_tuned(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
) -> (BindingProof, [u64; WIDTH], [u64; WIDTH]) {
    // 4 repeats of the (leaf, nullifier) pair => 8 permutation inputs => 4 rows.
    prove_binding_inner(secret, action, round, num_queries, 4)
}

fn prove_binding_inner(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
    repeats: usize,
) -> (BindingProof, [u64; WIDTH], [u64; WIDTH]) {
    let leaf_input = pack(secret, action);
    let nullifier_input = pack(secret, round);
    let leaf_output = permute(leaf_input);
    let nullifier_output = permute(nullifier_input);

    let air = BindingAir::new();
    // `repeats` (leaf, nullifier) pairs / VECTOR_LEN=2 => `repeats` rows. The
    // default 4 is CirclePcs's minimum committable domain size, the same
    // repeated-statement pattern `permutation.rs` already uses; taller traces
    // exist only to price a hiding configuration (prove_binding_tuned_rows).
    let mut inputs: Vec<[Val; WIDTH]> = Vec::with_capacity(2 * repeats);
    for _ in 0..repeats {
        inputs.push(to_field(leaf_input));
        inputs.push(to_field(nullifier_input));
    }
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

pub(crate) fn public_values_for_hiding(
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; WIDTH],
    nullifier: [u64; WIDTH],
) -> Vec<Val> {
    public_values(action, round, leaf, nullifier)
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
    verify_binding_tuned_checkpointed(proof, action, round, leaf, nullifier, num_queries, || {})
}

/// Same as [`verify_binding_tuned`], calling `checkpoint` once config
/// construction is done, right before the actual `verify()` call. Exists to
/// let a caller measure/log memory usage at that exact boundary (e.g. an
/// on-chain program bisecting where its heap runs out); the no-op default
/// via [`verify_binding_tuned`] costs nothing extra.
pub fn verify_binding_tuned_checkpointed(
    proof: &BindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; WIDTH],
    nullifier: [u64; WIDTH],
    num_queries: usize,
    checkpoint: impl FnOnce(),
) -> bool {
    let air = BindingAir::new();
    let config = make_config_tuned(num_queries);
    let pis = public_values(action, round, leaf, nullifier);
    checkpoint();
    verify_with_known_quotient_chunks(
        &config,
        &air,
        &proof.inner,
        &pis,
        None,
        LOG_NUM_QUOTIENT_CHUNKS,
    )
    .is_ok()
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

    /// Records the AIR's trace width, because width is what drives on-chain
    /// verification cost. Per-query CU attribution (2026-07-29, LiteSVM, the
    /// `cu-trace` feature): of ~297k CU per FRI query, `open_input` is 296,927
    /// and the whole FRI fold chain is 5,285 — 98% vs 2%. `open_input`'s work
    /// is one MMCS Merkle opening plus a DEEP-quotient dot product over every
    /// trace column, in the degree-3 extension field, so cost tracks WIDTH,
    /// not rows and not query count per se. This test prints the number so a
    /// future width change shows up as a cost change, not a surprise.
    #[test]
    fn the_trace_width_that_drives_on_chain_cost_is_recorded() {
        let air = BindingAir::new();
        let width = BaseAir::<Val>::width(&air);
        let single =
            num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        println!("BindingAir trace width: {width} columns ({single} per Poseidon2 block x {VECTOR_LEN} blocks)");
        assert_eq!(
            width,
            single * VECTOR_LEN,
            "the vectorized AIR's width must be exactly VECTOR_LEN blocks wide"
        );
    }

    #[test]
    fn the_pinned_quotient_chunk_count_matches_the_symbolic_pass() {
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = BindingAir::new();
        let config = make_config_tuned(4);
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, BindingAir>(&air, layout, config.is_zk());
        assert_eq!(
            LOG_NUM_QUOTIENT_CHUNKS, recomputed,
            "the pinned constant must equal what the symbolic pass derives for this exact AIR; \
             if the AIR changed, re-pin the constant to the recomputed value"
        );
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
    fn a_trace_built_from_two_different_secrets_cannot_yield_a_verifying_proof() {
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

        // Plonky3 runs `check_constraints` inside `prove` only under
        // `debug_assertions` (p3-uni-stark 0.6.2, prover.rs:39). In debug it
        // panics on this trace; in RELEASE it does not, and emits a proof.
        // This test used to assert only the panic, which made it vacuous in
        // the profile that actually ships. The claim that holds in both
        // profiles, and the only one soundness rests on, is that no such
        // proof verifies — so that is what is asserted here.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &pis)
        }));
        match attempt {
            Err(_) => { /* debug: the prover refused to build it at all */ }
            Ok(proof) => assert!(
                !verify_binding(
                    &BindingProof { inner: proof },
                    action,
                    round,
                    leaf_output,
                    nullifier_output
                ),
                "a trace whose two blocks use DIFFERENT secrets produced a proof \
                 that verified: the shared-secret constraint is not binding"
            ),
        }
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
