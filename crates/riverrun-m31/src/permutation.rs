//! Prove and verify knowledge of a Poseidon2-M31 permutation preimage, as a real
//! Circle-STARK proof. `Poseidon2Air` (from `p3-poseidon2-air`) is the vetted,
//! upstream AIR for the permutation's internal consistency; this module adds one
//! thin layer riverrun needs (binding the permutation's output to a public value,
//! which `Poseidon2Air` alone does not do) and wires the result into a working
//! prover/verifier over the circle domain (`p3-circle` + `p3-fri`), the same
//! recipe Plonky3's own test suite uses for a toy AIR (`p3-uni-stark`'s
//! `fib_air.rs`, `circle_compat_case`).
//!
//! The round constants are Plonky3's canonical, Grain-LFSR-generated Mersenne-31
//! parameters (`R_F = 8`, `R_P = 14`, `alpha = 5`), the exact ones
//! `default_mersenne31_poseidon2_16` uses for the permutation itself, so the trace
//! this module proves is consistent with what `permute` actually computes. No
//! invented or randomly-sampled constants.

extern crate alloc;

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
    default_mersenne31_poseidon2_16, GenericPoseidon2LinearLayersMersenne31, Mersenne31,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, Permutation, SerializingHasher};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig};

/// Poseidon2 state width for this instantiation: Plonky3's standard width-16
/// permutation for a 31-bit field, matching the canonical constants below.
pub const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 5;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 14;

type Val = Mersenne31;
type LinearLayers = GenericPoseidon2LinearLayersMersenne31;
type InnerAir = Poseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
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

/// riverrun's own AIR: everything `Poseidon2Air` already proves about one
/// permutation's internal consistency, plus the one constraint riverrun needs and
/// `Poseidon2Air` does not provide: the permutation's OUTPUT (the last ending full
/// round's post-state) equals the proof's public values. The INPUT is not
/// constrained to anything public, which is exactly a preimage statement: "I know
/// an input whose image under this permutation is this public output."
struct PreimageAir {
    inner: InnerAir,
    // `Poseidon2Air::constants` is `pub(crate)` to its own crate, not visible here,
    // so riverrun keeps its own copy: the exact same canonical constants, needed to
    // generate a trace consistent with `inner`'s constraints.
    constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

impl PreimageAir {
    fn new() -> Self {
        let constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
            RoundConstants::new(
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
                MERSENNE31_POSEIDON2_RC_16_INTERNAL,
                MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
            );
        Self { inner: InnerAir::new(constants.clone()), constants }
    }
}

impl BaseAir<Val> for PreimageAir {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn num_public_values(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PreimageAir {
    fn eval(&self, builder: &mut AB) {
        // Everything Poseidon2Air already proves: the trace is an internally
        // consistent execution of the permutation (every round's S-box and linear
        // layer computed correctly from the row before it).
        self.inner.eval(builder);

        // riverrun's one addition: bind the output to the public values.
        let main = builder.main();
        let local: &Cols<AB::Var> = main.current_slice().borrow();
        let output = &local.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        for i in 0..WIDTH {
            builder.assert_eq(output[i].into(), pis[i].into());
        }
    }
}

fn make_config() -> Config {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 40,
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

fn from_field(input: [Val; WIDTH]) -> [u64; WIDTH] {
    use p3_field::PrimeField64;
    core::array::from_fn(|i| input[i].as_canonical_u64())
}

/// Run the real Poseidon2-M31 permutation on `input`, the same function the
/// prover's trace is built from, so a caller can compute the public output to
/// prove a preimage of. Uses Plonky3's canonical, Grain-LFSR-generated round
/// constants, not invented ones.
pub fn permute(input: [u64; WIDTH]) -> [u64; WIDTH] {
    let perm = default_mersenne31_poseidon2_16();
    let out = perm.permute(to_field(input));
    from_field(out)
}

/// A real Circle-STARK proof that the prover knows a preimage of the public
/// output under the Poseidon2-M31 permutation.
pub struct PreimageProof {
    inner: Proof<Config>,
}

impl PreimageProof {
    /// Serialize to bytes (`bincode`, over `Proof`'s own `serde` impl). Same
    /// wire format convention as `binding::BindingProof::to_bytes`, added
    /// while diagnosing riverrun-m31-verifier's on-chain memory ceiling: this
    /// lets a single-block preimage proof (this AIR) be compared on-chain
    /// against a two-block vectorized one (`BindingAir`) to isolate whether
    /// peak `verify()` memory scales with AIR width/complexity.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof<Config> is always serializable")
    }

    /// Deserialize from bytes produced by [`PreimageProof::to_bytes`]. `None`
    /// on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }
}

/// Prove knowledge of `input` such that `permute(input) == output`, as a
/// single-row Circle-STARK trace. `output` becomes the proof's public values.
/// Panics if `input` does not actually permute to `output` (the trace generator
/// would produce an unsatisfiable constraint set; callers must supply a genuine
/// preimage, exactly as `permute(input)` would compute).
pub fn prove_preimage(input: [u64; WIDTH]) -> (PreimageProof, [u64; WIDTH]) {
    let air = PreimageAir::new();
    let field_input = to_field(input);
    // CirclePcs needs at least 4 rows to commit to. Every row independently proves
    // the same preimage (the public-value constraint applies row-wise), so padding
    // with repeats of the one real input keeps the statement's meaning intact: a
    // wrong row would fail its own output == public-values check just the same.
    let trace: RowMajorMatrix<Val> = generate_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(alloc::vec![field_input; 4], &air.constants, 0);
    let output = permute(input);
    let pis: Vec<Val> = to_field(output).to_vec();
    let config = make_config();
    let proof = prove(&config, &air, trace, &pis);
    (PreimageProof { inner: proof }, output)
}

/// Verify a `PreimageProof` against the claimed public output. `true` only if
/// the proof is well-formed and verifies against exactly these public values.
pub fn verify_preimage(proof: &PreimageProof, output: [u64; WIDTH]) -> bool {
    let air = PreimageAir::new();
    let config = make_config();
    let pis: Vec<Val> = to_field(output).to_vec();
    verify_with_known_quotient_chunks(&config, &air, &proof.inner, &pis, None, LOG_NUM_QUOTIENT_CHUNKS)
        .is_ok()
}

/// log2 of the number of quotient chunks for [`PreimageAir`], pinned for the
/// same reason and under the same drift-guard discipline as
/// `binding::LOG_NUM_QUOTIENT_CHUNKS` (see that constant's doc): the symbolic
/// pass that derives it is what overran Solana's 256 KB heap ceiling, and for
/// a fixed AIR the value is a compile-time fact.
pub const LOG_NUM_QUOTIENT_CHUNKS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_quotient_chunk_count_matches_the_symbolic_pass() {
        use p3_air::BaseAir;
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = PreimageAir::new();
        let config = make_config();
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, PreimageAir>(&air, layout, config.is_zk());
        assert_eq!(
            LOG_NUM_QUOTIENT_CHUNKS, recomputed,
            "the pinned constant must equal what the symbolic pass derives for this exact AIR; \
             if the AIR changed, re-pin the constant to the recomputed value"
        );
    }

    fn sample_input() -> [u64; WIDTH] {
        core::array::from_fn(|i| (i as u64) * 7 + 3)
    }

    #[test]
    fn permute_is_deterministic() {
        let a = permute(sample_input());
        let b = permute(sample_input());
        assert_eq!(a, b);
    }

    #[test]
    fn a_genuine_preimage_proves_and_verifies() {
        let input = sample_input();
        let (proof, output) = prove_preimage(input);
        assert_eq!(output, permute(input), "the claimed output must be the real permutation image");
        assert!(verify_preimage(&proof, output), "a genuine preimage must verify");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_output() {
        let input = sample_input();
        let (proof, output) = prove_preimage(input);
        let mut wrong = output;
        wrong[0] ^= 1;
        assert!(
            !verify_preimage(&proof, wrong),
            "a proof for one output must not verify against a different one"
        );
    }
}
