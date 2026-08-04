//! Pricing witness-hiding for the binding relation, with the parts that can
//! be built correctly today actually built.
//!
//! `docs/PRIVACY.md` in riverrun-soroban establishes the problem: `CirclePcs`
//! is a non-hiding commitment, so the query openings of a 4-row trace
//! interpolate the witness straight back. Plonky3 ships the cure only for
//! two-adic fields (`HidingFriPcs` wraps `TwoAdicFriPcs`), which Mersenne-31
//! cannot use.
//!
//! A hiding configuration for this relation needs four things:
//!
//! 1. a **salted MMCS**, so an opened Merkle leaf commits to nothing an
//!    adversary can test guesses against;
//! 2. a **trace taller than the query count**, so the openings cannot pin the
//!    polynomial down;
//! 3. **random rows/columns** carrying the entropy that blinds those openings;
//! 4. the **interleaving composition** that makes the random rows part of the
//!    committed polynomial while keeping constraints on the real rows only,
//!    plus the randomization-polynomial commitment the ZK prover path opens.
//!
//! This module builds 1, 2 and 3 for real: the config below swaps in
//! `MerkleTreeHidingMmcs` with 4 Mersenne-31 salt elements per leaf (124 bits),
//! proves over a caller-chosen trace height, and pads the trace with random
//! columns. What it does NOT build is 4, and that omission is the difference
//! between a cost model and a private proof.
//!
//! **So this is not a hiding proof and must never be presented as one.** It is
//! an instrument for one question the roadmap depends on: does the verification
//! cost of the hiding machinery fit in a single Stellar transaction? Items 1-3
//! are where that cost lives (bigger leaves to hash, taller trees to walk,
//! wider rows to open); item 4 adds one more commitment and its openings.
//!
//! Why 4 is not attempted here: the interleaving trick in `HidingFriPcs` puts
//! the real trace on the even indices of a doubled domain, which works because
//! the even powers of a multiplicative group of order `2h` are a subgroup of
//! order `h`. Circle domains do not decompose that way under natural order,
//! so porting it is a design question about circle-domain structure, not a
//! transcription. Shipping a "hiding" mode whose hiding argument had not been
//! worked out would be worse than shipping none.

extern crate alloc;

use alloc::vec::Vec;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mersenne_31::Mersenne31;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_air::{generate_vectorized_trace_rows, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig};
/// A tiny SplitMix64 the salted MMCS can own. p3-merkle-tree needs an RNG
/// that is `Rng + Clone + Send` in rand 0.10's traits; rand's own generators
/// arrive either behind std features or without `Clone`, and this instrument
/// only needs salts whose cost is representative and whose measurements
/// reproduce. It is deliberately NOT cryptographic: a real hiding deployment
/// must seed a CSPRNG from system entropy, since these salts are what stop an
/// adversary from testing guesses against an opened leaf.
#[derive(Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub const fn seed_from_u64(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

impl rand10::TryRng for SplitMix64 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

use crate::binding::{
    public_values_for_hiding, BindingAir, CONTEXT_LEN, LOG_NUM_QUOTIENT_CHUNKS, SECRET_LEN,
};
use crate::membership::DIGEST_LEN;
use crate::permutation::{permute, WIDTH};

type Val = Mersenne31;
type Challenge = BinomialExtensionField<Val, 3>;
type ByteHash = crate::keccak::SolKeccak256;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

/// Salt elements per Merkle leaf. Four Mersenne-31 elements carry 124 bits,
/// the usual target for a commitment salt.
const SALT_ELEMS: usize = 4;

type HidingValMmcs =
    MerkleTreeHidingMmcs<<Val as p3_field::Field>::Packing, u8, FieldHash, Compress, SplitMix64, 2, 32, SALT_ELEMS>;
type HidingChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type HidingPcs = CirclePcs<Val, HidingValMmcs, HidingChallengeMmcs>;
type HidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

/// A proof carrying the hiding machinery's cost: salted Merkle leaves over a
/// caller-chosen trace height. Not a hiding proof (see the module doc).
pub struct HidingCostProof {
    inner: Proof<HidingConfig>,
}

impl HidingCostProof {
    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof<HidingConfig> is always serializable")
    }

    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
    }

    pub fn degree_bits(&self) -> usize {
        self.inner.degree_bits
    }
}

/// The salted-MMCS counterpart of `binding::make_config_tuned`. The RNG seeds
/// the leaf salts on the prover; the verifier constructs the same type and
/// never draws from it, so a fixed seed here is not a security parameter.
fn make_hiding_config(num_queries: usize) -> HidingConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = HidingValMmcs::new(field_hash, compress, 0, SplitMix64::seed_from_u64(0));
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let pcs = HidingPcs {
        mmcs: val_mmcs,
        fri_params,
        _phantom: core::marker::PhantomData,
    };
    StarkConfig::new(pcs, Challenger::from_hasher(Vec::new(), byte_hash))
}

/// Prove the binding relation with the hiding machinery's costs in place:
/// salted Merkle leaves, a trace of `2^log_rows` rows, and `random_cols`
/// random columns appended to every row.
///
/// The random columns are unconstrained by `BindingAir` (its constraints
/// address named columns), so they cost what blinding columns would cost
/// without pretending to blind anything on their own.
pub fn prove_binding_hiding_cost(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
    log_rows: usize,
    random_cols: usize,
) -> (HidingCostProof, [u64; DIGEST_LEN], [u64; DIGEST_LEN]) {
    assert!(log_rows >= 2, "CirclePcs cannot commit to fewer than 4 rows");
    let leaf_input = pack(secret, action);
    let nullifier_input = pack(secret, round);
    // Truncated to digests: the full permutation state IS the witness once
    // pi is inverted, and the context is public beside it.
    let leaf_full = permute(leaf_input);
    let nullifier_full = permute(nullifier_input);
    let leaf_output: [u64; DIGEST_LEN] = core::array::from_fn(|i| leaf_full[i]);
    let nullifier_output: [u64; DIGEST_LEN] = core::array::from_fn(|i| nullifier_full[i]);

    let repeats = 1usize << log_rows;
    let mut inputs: Vec<[Val; WIDTH]> = Vec::with_capacity(2 * repeats);
    for _ in 0..repeats {
        inputs.push(to_field(leaf_input));
        inputs.push(to_field(nullifier_input));
    }
    let constants: RoundConstants<Val, WIDTH, 4, 14> = RoundConstants::new(
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_INTERNAL,
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    );
    let trace: RowMajorMatrix<Val> =
        generate_vectorized_trace_rows::<Val, crate::binding::LinearLayersPub, WIDTH, 5, 0, 4, 14, 2>(
            inputs,
            &constants,
            0,
        );
    let trace = append_random_cols(trace, random_cols);

    let air = BindingAir::new();
    let pis = public_values_for_hiding(action, round, leaf_output, nullifier_output);
    let config = make_hiding_config(num_queries);
    let proof = prove(&config, &air, trace, &pis);
    (HidingCostProof { inner: proof }, leaf_output, nullifier_output)
}

/// Verify a [`HidingCostProof`]. Same statement, same public values, same
/// query count as the production verifier; only the commitment machinery
/// differs, which is exactly what this measures.
pub fn verify_binding_hiding_cost(
    proof: &HidingCostProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; DIGEST_LEN],
    nullifier: [u64; DIGEST_LEN],
    num_queries: usize,
) -> bool {
    let air = BindingAir::new();
    let config = make_hiding_config(num_queries);
    let pis = public_values_for_hiding(action, round, leaf, nullifier);
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

/// Append `n` pseudorandom columns to every row. Deterministic from a fixed
/// seed: this is a cost instrument, and reproducible measurements matter more
/// here than unpredictable padding would.
fn append_random_cols(trace: RowMajorMatrix<Val>, n: usize) -> RowMajorMatrix<Val> {
    if n == 0 {
        return trace;
    }
    let (h, w) = (trace.height(), trace.width());
    let mut out = Vec::with_capacity(h * (w + n));
    let mut state = 0x9E3779B97F4A7C15u64;
    for r in 0..h {
        for c in 0..w {
            out.push(trace.get(r, c).unwrap());
        }
        for _ in 0..n {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            out.push(Val::from_u64((state >> 33) % ((1u64 << 31) - 1)));
        }
    }
    RowMajorMatrix::new(out, w + n)
}

fn to_field(input: [u64; WIDTH]) -> [Val; WIDTH] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

fn pack(secret: [u64; SECRET_LEN], context: [u64; CONTEXT_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..SECRET_LEN].copy_from_slice(&secret);
    out[SECRET_LEN..].copy_from_slice(&context);
    out
}
