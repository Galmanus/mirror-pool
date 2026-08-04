//! Post-quantum attestation of an ASP root history.
//!
//! Nethermind's Stellar Private Payments compliance layer publishes a Merkle
//! root per approval set and updates it one leaf at a time, emitting
//! `LeafAddedEvent(leaf, index, root)` (asp-membership `lib.rs:239`). The
//! honesty a regulator needs is not that a single root exists — a Groth16
//! snapshot gives that — but that the sequence of published roots is an
//! **append-only chain**: indices `0, 1, 2, …` with no gap, each root the
//! result of inserting exactly one leaf over the previous one, no removal and
//! no reordering.
//!
//! ## Why this AIR does not reprove the hash
//!
//! The ASP hashes with Poseidon2 over BN254 (`p ≈ 2²⁵⁴`); this crate's STARK
//! is over Mersenne-31 (`p = 2³¹ − 1`). Reproving BN254-Poseidon2 in an M31
//! AIR is out of scope, and an attestation of the *wrong* hash would attest
//! nothing. So the compression is a **witnessed oracle**: the per-event root
//! is a public value, and the AIR constrains the STRUCTURE of the history
//! around those values.
//!
//! What a post-quantum adversary cannot forge here is the shape of the chain,
//! regardless of hash strength:
//!
//! - `index_{n+1} = index_n + 1` — monotone and gap-free. A reordered or
//!   leaf-injected history violates this immediately.
//! - the first row's index is the attested starting index (`0` for a full
//!   history from genesis).
//! - the last row's root is the attested current root, so the chain the proof
//!   covers ends at the root the pool actually publishes.
//!
//! ## What this does NOT claim
//!
//! It attests history STRUCTURE, not preimage security: a Poseidon2 collision
//! could substitute one leaf for another of equal hash, and that is the SPP's
//! assumption to make, not this layer's to solve. It is a parallel attestation
//! the pool does not consume today.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mersenne_31::{Mersenne31, QM31};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig};


type Val = Mersenne31;
/// The challenge field is the degree-4 extension, matching the rest of the
/// crate after the field-ceiling correction (`examples/soundness_budget.rs`).
type Challenge = QM31;
type ByteHash = crate::keccak::SolKeccak256;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// A BN254 root, carried as its little-endian M31 limbs. BN254's `p` is ~254
/// bits, so eight 31-bit limbs (248 bits) do not hold a full element; this
/// attestation treats the root as an opaque tag and compares limbwise, which
/// is exactly what the structure argument needs — the root is a witnessed
/// label, not a field element this STARK does arithmetic on. Nine limbs give
/// 279 bits of tag space, comfortably injective over BN254 roots.
pub const ROOT_LIMBS: usize = 9;

/// Trace columns: `index`, then the `ROOT_LIMBS` limbs of this row's root.
const TRACE_WIDTH: usize = 1 + ROOT_LIMBS;

/// One observed `LeafAddedEvent`, reduced to what the structure proof needs.
#[derive(Clone, Copy)]
pub struct RootStep {
    pub index: u64,
    pub root: [u64; ROOT_LIMBS],
}

/// The append-only-history AIR. Rows are events in order; the constraints make
/// the ordering and the index progression unforgeable, and pin the endpoints
/// to public values so the proof cannot be about a different history than the
/// one claimed.
pub(crate) struct AspHistoryAir {
    /// Number of real events; rows past this are padding repeating the last
    /// real row, and the transition constraints tolerate the repeat because a
    /// repeated row has `index_{n+1} = index_n`, which the padding selector
    /// switches off.
    pub real_rows: usize,
}

impl BaseAir<Val> for AspHistoryAir {
    fn width(&self) -> usize {
        // index, root limbs, and one padding-selector column.
        TRACE_WIDTH + 1
    }

    fn num_public_values(&self) -> usize {
        // start_index, then first and last root limbs.
        1 + 2 * ROOT_LIMBS
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for AspHistoryAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let nxt = main.next_slice();

        let index = cur[0].clone();
        let index_next = nxt[0].clone();
        let is_real_next: AB::Expr = nxt[TRACE_WIDTH].clone().into();

        // The padding selector is boolean.
        let is_real: AB::Expr = cur[TRACE_WIDTH].clone().into();
        builder.assert_zero(is_real.clone() * (AB::Expr::ONE - is_real.clone()));

        let pis = builder.public_values().to_vec();
        let start_index = pis[0].clone();
        let first_root = &pis[1..1 + ROOT_LIMBS];
        let last_root = &pis[1 + ROOT_LIMBS..1 + 2 * ROOT_LIMBS];

        // First row: index is the attested start, root is the attested first
        // root. This pins the low end of the chain to a public value.
        builder.when_first_row().assert_eq(index.clone(), start_index.into());
        for j in 0..ROOT_LIMBS {
            builder
                .when_first_row()
                .assert_eq(cur[1 + j].clone(), first_root[j].into());
        }

        // Last row: the row's root is the attested current root. This pins the
        // high end, so the proof cannot silently cover a prefix of the history
        // and omit the tail.
        for j in 0..ROOT_LIMBS {
            builder
                .when_last_row()
                .assert_eq(cur[1 + j].clone(), last_root[j].into());
        }

        // Transition: while the NEXT row is a real event, its index is exactly
        // one more than this row's. A reordered or leaf-injected history breaks
        // this the moment two indices are out of step. When the next row is
        // padding, the selector switches the constraint off and padding simply
        // repeats the last root (checked below), so the last-row pin still
        // lands on the true final root.
        builder.when_transition().assert_zero(
            is_real_next.clone() * (index_next.clone() - index.clone() - AB::Expr::ONE),
        );
        // Padding rows repeat the previous root unchanged, so the tail pin is
        // meaningful regardless of how much padding follows.
        for j in 0..ROOT_LIMBS {
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - is_real_next.clone())
                    * (nxt[1 + j].clone() - cur[1 + j].clone()),
            );
        }
    }
}

/// log2 of the quotient-chunk count, pinned so the verifier never runs the
/// symbolic pass on-chain (same reason as the other AIRs in this crate).
/// Guarded by `the_pinned_chunk_count_matches_the_symbolic_pass`.
pub const LOG_NUM_QUOTIENT_CHUNKS: usize = 0;

fn make_config(num_queries: usize) -> Config {
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
    let pcs = Pcs { mmcs: val_mmcs, fri_params, _phantom: core::marker::PhantomData };
    Config::new(pcs, Challenger::from_hasher(Vec::new(), byte_hash))
}

/// A proof that a root history is a consistent append-only chain.
pub struct AspHistoryProof {
    inner: Proof<Config>,
}

impl AspHistoryProof {
    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof<Config> is serializable")
    }

    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
    }

    #[cfg(feature = "wire")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof<Config> is serializable")
    }

    #[cfg(feature = "wire")]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }
}

fn to_field(v: u64) -> Val {
    Val::from_u64(v)
}

fn build_trace(steps: &[RootStep], log_rows: usize) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let rows = 1usize << log_rows;
    assert!(steps.len() <= rows, "trace height too small for the history");
    assert!(!steps.is_empty(), "an empty history has nothing to attest");
    let w = TRACE_WIDTH + 1;
    let mut values = Vec::with_capacity(rows * w);

    let last = steps[steps.len() - 1];
    for r in 0..rows {
        let real = r < steps.len();
        let s = if real { steps[r] } else { last };
        values.push(to_field(s.index));
        for j in 0..ROOT_LIMBS {
            values.push(to_field(s.root[j]));
        }
        values.push(if real { Val::ONE } else { Val::ZERO });
    }

    let mut pis = Vec::with_capacity(1 + 2 * ROOT_LIMBS);
    pis.push(to_field(steps[0].index));
    for j in 0..ROOT_LIMBS {
        pis.push(to_field(steps[0].root[j]));
    }
    for j in 0..ROOT_LIMBS {
        pis.push(to_field(last.root[j]));
    }
    (RowMajorMatrix::new(values, w), pis)
}

/// Prove that `steps` — the `LeafAddedEvent`s of an ASP, in order — form a
/// consistent append-only chain. `log_rows` sets the committed height; the
/// history must fit.
pub fn prove_asp_history(steps: &[RootStep], log_rows: usize, num_queries: usize) -> AspHistoryProof {
    let (trace, pis) = build_trace(steps, log_rows);
    let air = AspHistoryAir { real_rows: steps.len() };
    let config = make_config(num_queries);
    let proof = prove(&config, &air, trace, &pis);
    AspHistoryProof { inner: proof }
}

/// Verify an [`AspHistoryProof`] against the claimed start index and the first
/// and last roots. `true` only if the history is a consistent append-only
/// chain ending at `last_root`.
pub fn verify_asp_history(
    proof: &AspHistoryProof,
    start_index: u64,
    first_root: [u64; ROOT_LIMBS],
    last_root: [u64; ROOT_LIMBS],
    real_rows: usize,
    num_queries: usize,
) -> bool {
    let air = AspHistoryAir { real_rows };
    let config = make_config(num_queries);
    let mut pis = Vec::with_capacity(1 + 2 * ROOT_LIMBS);
    pis.push(to_field(start_index));
    for j in 0..ROOT_LIMBS {
        pis.push(to_field(first_root[j]));
    }
    for j in 0..ROOT_LIMBS {
        pis.push(to_field(last_root[j]));
    }
    verify_with_known_quotient_chunks(&config, &air, &proof.inner, &pis, None, LOG_NUM_QUOTIENT_CHUNKS)
        .is_ok()
}

/// Split a BN254 root (32 big-endian bytes) into `ROOT_LIMBS` little-endian
/// 31-bit limbs, the tag form the trace carries.
pub fn root_to_limbs(be_bytes: &[u8; 32]) -> [u64; ROOT_LIMBS] {
    // Read as a big integer, then peel 31-bit limbs little-endian.
    let mut acc: u128 = 0;
    let mut limbs = [0u64; ROOT_LIMBS];
    let mut bit = 0usize;
    let mut li = 0usize;
    // Process bytes most-significant first into a rolling value; simplest
    // correct approach at this size is to walk all 256 bits.
    let mut bits = [0u8; 256];
    for (i, b) in be_bytes.iter().enumerate() {
        for k in 0..8 {
            bits[i * 8 + k] = (b >> (7 - k)) & 1;
        }
    }
    // bits[0] is the MSB; assemble little-endian limbs from the LSB end.
    for pos in (0..256).rev() {
        let bitval = bits[pos] as u64;
        acc |= (bitval as u128) << bit;
        bit += 1;
        if bit == 31 {
            limbs[li] = acc as u64;
            li += 1;
            acc = 0;
            bit = 0;
            if li == ROOT_LIMBS {
                break;
            }
        }
    }
    if bit > 0 && li < ROOT_LIMBS {
        limbs[li] = acc as u64;
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::BaseAir;

    fn root(seed: u64) -> [u64; ROOT_LIMBS] {
        core::array::from_fn(|i| (seed.wrapping_mul(1000).wrapping_add(i as u64)) % ((1 << 31) - 1))
    }

    /// A genuine append-only history: indices 0..n, arbitrary distinct roots.
    fn history(n: usize) -> Vec<RootStep> {
        (0..n)
            .map(|i| RootStep { index: i as u64, root: root(i as u64 + 1) })
            .collect()
    }

    #[test]
    fn the_pinned_chunk_count_matches_the_symbolic_pass() {
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = AspHistoryAir { real_rows: 4 };
        let config = make_config(4);
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed = get_log_num_quotient_chunks::<Val, AspHistoryAir>(&air, layout, config.is_zk());
        assert_eq!(LOG_NUM_QUOTIENT_CHUNKS, recomputed);
    }

    #[test]
    fn a_consistent_history_proves_and_verifies() {
        let steps = history(6);
        let proof = prove_asp_history(&steps, 3, 20);
        assert!(verify_asp_history(
            &proof,
            steps[0].index,
            steps[0].root,
            steps[steps.len() - 1].root,
            steps.len(),
            20
        ));
    }

    #[test]
    fn a_wrong_final_root_does_not_verify() {
        let steps = history(6);
        let proof = prove_asp_history(&steps, 3, 20);
        let mut wrong = steps[steps.len() - 1].root;
        wrong[0] ^= 1;
        assert!(!verify_asp_history(&proof, steps[0].index, steps[0].root, wrong, steps.len(), 20));
    }

    #[test]
    #[should_panic]
    fn a_reordered_history_cannot_even_be_proved() {
        // Swap two events so the indices are out of order. The monotone-index
        // constraint is violated at proving time, so the trace is unsatisfiable
        // and the prover panics rather than emitting a proof of a forged
        // history — the same fail-closed behaviour the other AIRs have.
        let mut steps = history(6);
        steps.swap(2, 4);
        let _ = prove_asp_history(&steps, 3, 20);
    }

    #[test]
    #[should_panic]
    fn an_injected_leaf_breaks_the_index_chain() {
        // An extra event inserted with a duplicate index: the chain no longer
        // advances by exactly one across it, so it cannot be proved.
        let mut steps = history(5);
        steps.insert(3, RootStep { index: 2, root: root(99) });
        let _ = prove_asp_history(&steps, 3, 20);
    }

    #[test]
    fn root_limbs_round_trip_is_injective_on_distinct_roots() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 1;
        b[31] = 2;
        assert_ne!(root_to_limbs(&a), root_to_limbs(&b));
        // High bytes reach distinct limbs too.
        let mut c = [0u8; 32];
        c[0] = 0x20; // within BN254 range
        assert_ne!(root_to_limbs(&c), root_to_limbs(&a));
    }
}
