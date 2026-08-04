//! Prove, as one Circle-STARK proof, that a leaf digest sits under a public
//! Merkle root. This is riverrun's §1b relation
//! (`docs/M31_CIRCLE_STARK.md`): a Poseidon2 compression function folded
//! `DEPTH` times, each level's node fed into the next, with a per-level bit
//! choosing left/right order.
//!
//! **The path is out of the PUBLIC INPUTS, which is not the same as hidden.**
//! `prove_membership` commits with a non-hiding MMCS over `CirclePcs`, whose
//! `ZK` flag is `false`. The siblings and the direction bits are trace cells,
//! and the FRI openings at 40 queries over a short trace interpolate that
//! trace — the same measurement `examples/privacy_audit.rs` makes for the
//! binding relation applies here. An observer who reads the proof recovers the
//! path.
//!
//! Only [`prove_membership_zk`] and the crowd variants in `crowd.rs` actually
//! hide it, by committing under `HidingCirclePcs`. This distinction was
//! documented backwards until an adversarial audit caught it
//! (`docs/AUDIT-2026-08-03.md`, M5), and the wording here is the correction,
//! not a softening: a reader who took "the authentication path stays hidden"
//! at face value for this function was misled.
//!
//! **Not yet fused with §1a/§1c** (`binding.rs`): this proves membership of a
//! given leaf digest independently. Combining "the leaf comes from this
//! secret" (binding.rs) with "this leaf sits under this root" (this module)
//! into one proof is real, separate integration work, not done here.
//!
//! **`DEPTH = 4` (a 16-leaf tree) is a small, concrete, provisional choice**,
//! picked because it is exactly CirclePcs's minimum committable row count
//! (no padding needed), not a production tree size. Scaling `DEPTH` up is
//! mechanical (more rows), not a design change.
//!
//! Digests here are 8 M31 elements (not the full `WIDTH = 16`), a compression
//! convention: `compress(left, right) = permute(left ‖ right)[0..8]`, the
//! standard "half the permutation's output is the digest" truncation. This is
//! a concrete choice, not a reviewed security argument, same honesty note as
//! `binding.rs`'s secret/context split.

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
    GenericPoseidon2LinearLayersMersenne31, Mersenne31, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL, MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig, SubAirBuilder};

use crate::permutation::{permute, WIDTH};

/// Digest width: half a permutation's output, the compression convention.
pub const DIGEST_LEN: usize = 8;
/// Tree depth this module proves against. See module docs: provisional, not
/// a production size, chosen to be CirclePcs's minimum row count exactly.
pub const DEPTH: usize = 4;

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

fn constants() -> RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        MERSENNE31_POSEIDON2_RC_16_INTERNAL,
        MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

fn single_width() -> usize {
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
}

/// riverrun's Merkle-fold AIR: internal correctness of each row's Poseidon2
/// compression (delegated to `Poseidon2Air` via a column-windowed
/// `SubAirBuilder`, since this AIR's rows carry one extra `bit` column
/// `Poseidon2Air` does not know about), plus riverrun's own constraints: the
/// per-row left/right selection is a real bit, the first row's selected node
/// equals the public leaf, each row's output feeds the next row's selected
/// node, and the last row's output equals the public root.
struct MembershipAir {
    inner: InnerAir,
}

impl MembershipAir {
    fn new() -> Self {
        Self { inner: InnerAir::new(constants()) }
    }
}

impl BaseAir<Val> for MembershipAir {
    fn width(&self) -> usize {
        single_width() + 1
    }

    fn num_public_values(&self) -> usize {
        2 * DIGEST_LEN
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for MembershipAir {
    fn eval(&self, builder: &mut AB) {
        let width = single_width();

        // The inner Poseidon2 AIR only knows about its own `width` columns;
        // give it a windowed view so it never sees this AIR's extra `bit`
        // column tacked on at the end of each row.
        let mut sub: SubAirBuilder<AB, InnerAir, Val> = SubAirBuilder::new(builder, 0..width);
        self.inner.eval(&mut sub);

        let main = builder.main();
        let current = main.current_slice();
        let next = main.next_slice();

        let poseidon: &Cols<AB::Var> = current[..width].borrow();
        let poseidon_next: &Cols<AB::Var> = next[..width].borrow();
        let bit: AB::Expr = current[width].clone().into();
        let bit_next: AB::Expr = next[width].clone().into();

        // The selector must be boolean: bit * (1 - bit) == 0.
        builder.assert_zero(bit.clone() * (AB::Expr::ONE - bit.clone()));

        let output = &poseidon.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let leaf = &pis[0..DIGEST_LEN];
        let root = &pis[DIGEST_LEN..2 * DIGEST_LEN];

        // This row's canonical node: bit == 0 selects the left half of the
        // permutation input as the node (sibling on the right); bit == 1
        // selects the right half (sibling on the left).
        let selected_node = |cols: &Cols<AB::Var>, bit: AB::Expr| -> Vec<AB::Expr> {
            (0..DIGEST_LEN)
                .map(|j| {
                    let left: AB::Expr = cols.inputs[j].into();
                    let right: AB::Expr = cols.inputs[DIGEST_LEN + j].into();
                    (AB::Expr::ONE - bit.clone()) * left + bit.clone() * right
                })
                .collect()
        };

        let this_node = selected_node(poseidon, bit);

        // First row: the selected node is the public leaf.
        for j in 0..DIGEST_LEN {
            builder
                .when_first_row()
                .assert_eq(this_node[j].clone(), leaf[j].into());
        }

        // Transition: the NEXT row's selected node must equal THIS row's
        // output, the fold's continuity, the reason membership under the
        // root, not just one hop, is what gets proven.
        let next_node = selected_node(poseidon_next, bit_next);
        for j in 0..DIGEST_LEN {
            builder
                .when_transition()
                .assert_eq(next_node[j].clone(), output[j].into());
        }

        // Last row: this row's output is the public root.
        for j in 0..DIGEST_LEN {
            builder
                .when_last_row()
                .assert_eq(output[j].into(), root[j].into());
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

fn to_field8(input: [u64; DIGEST_LEN]) -> [Val; DIGEST_LEN] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

fn pack16(left: [u64; DIGEST_LEN], right: [u64; DIGEST_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..DIGEST_LEN].copy_from_slice(&left);
    out[DIGEST_LEN..].copy_from_slice(&right);
    out
}

fn truncate8(output: [u64; WIDTH]) -> [u64; DIGEST_LEN] {
    core::array::from_fn(|i| output[i])
}

/// `compress(left, right) = permute(left ‖ right)[0..DIGEST_LEN]`, riverrun's
/// M31 Merkle node combiner, built from the same permutation `binding.rs` and
/// `permutation.rs` use.
pub fn compress(left: [u64; DIGEST_LEN], right: [u64; DIGEST_LEN]) -> [u64; DIGEST_LEN] {
    truncate8(permute(pack16(left, right)))
}

/// One level of an authentication path: the sibling digest and whether the
/// leaf/current node is on the left (`false`) or right (`true`) at this level.
#[derive(Clone, Copy)]
pub struct PathStep {
    pub sibling: [u64; DIGEST_LEN],
    pub node_on_right: bool,
}

/// A real Circle-STARK proof that `leaf` sits under `root` via a private,
/// depth-`DEPTH` authentication path.
pub struct MembershipProof {
    inner: Proof<Config>,
}

impl MembershipProof {
    /// log2 of the committed trace height, as recorded in the proof. See
    /// [`crate::binding::BindingProof::degree_bits`].
    pub fn degree_bits(&self) -> usize {
        self.inner.degree_bits
    }

    /// Serialize with `postcard`, the no_std wire format a bare-wasm verifier
    /// (Soroban) reads from its host boundary. Same convention as
    /// [`crate::binding::BindingProof::to_postcard`].
    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof<Config> is always serializable")
    }

    /// Deserialize from bytes produced by [`MembershipProof::to_postcard`].
    /// `None` on malformed input; callers on-chain treat that as rejection.
    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
    }
}

/// Prove that `leaf` sits under `root` following `path` (exactly `DEPTH`
/// steps). Panics if `path` does not actually fold `leaf` to `root` (the
/// trace generator would produce an unsatisfiable constraint set; callers
/// must supply a genuine path, mirroring `permutation.rs`'s documented
/// preimage-proving behavior).
pub fn prove_membership(leaf: [u64; DIGEST_LEN], path: [PathStep; DEPTH]) -> (MembershipProof, [u64; DIGEST_LEN]) {
    let (inputs, bits, root) = build_rows(leaf, path);
    let air = MembershipAir::new();
    let poseidon_trace: RowMajorMatrix<Val> = generate_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants(), 0);
    let trace = append_bit_column(poseidon_trace, &bits);

    let pis = public_values(leaf, root);
    let config = make_config();
    let proof = prove(&config, &air, trace, &pis);
    (MembershipProof { inner: proof }, root)
}

/// log2 of the number of quotient chunks for [`MembershipAir`], pinned for the
/// same reason as `binding::LOG_NUM_QUOTIENT_CHUNKS`: the symbolic pass that
/// derives it peaks at hundreds of KB of transient heap, past Solana's 256 KB
/// ceiling, and for a fixed AIR the value is a compile-time fact. Guarded by
/// the test `the_pinned_quotient_chunk_count_matches_the_symbolic_pass` below;
/// a wrong value rejects honest proofs, it never accepts forged ones.
pub const LOG_NUM_QUOTIENT_CHUNKS: usize = 2;

/// Verify a [`MembershipProof`] against a claimed `leaf` and `root`.
pub fn verify_membership(proof: &MembershipProof, leaf: [u64; DIGEST_LEN], root: [u64; DIGEST_LEN]) -> bool {
    let air = MembershipAir::new();
    let config = make_config();
    let pis = public_values(leaf, root);
    verify_with_known_quotient_chunks(&config, &air, &proof.inner, &pis, None, LOG_NUM_QUOTIENT_CHUNKS)
        .is_ok()
}

fn public_values(leaf: [u64; DIGEST_LEN], root: [u64; DIGEST_LEN]) -> Vec<Val> {
    let mut pis = Vec::with_capacity(2 * DIGEST_LEN);
    pis.extend_from_slice(&to_field8(leaf));
    pis.extend_from_slice(&to_field8(root));
    pis
}

/// Fold `leaf` through `path`, returning each level's real permutation input
/// (already ordered by `node_on_right`), each level's bit, and the resulting
/// root, so both the prover and tests can build a genuine, consistent trace.
fn build_rows(
    leaf: [u64; DIGEST_LEN],
    path: [PathStep; DEPTH],
) -> (Vec<[Val; WIDTH]>, [bool; DEPTH], [u64; DIGEST_LEN]) {
    build_rows_depth::<DEPTH>(leaf, &path)
}

fn to_field(input: [u64; WIDTH]) -> [Val; WIDTH] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

fn append_bit_column(poseidon_trace: RowMajorMatrix<Val>, bits: &[bool; DEPTH]) -> RowMajorMatrix<Val> {
    append_bit_column_depth::<DEPTH>(poseidon_trace, bits)
}

// ---------------------------------------------------------------------------
// The hiding (ZK) membership variant.
// ---------------------------------------------------------------------------

/// Tree depth of the hiding membership proof: 32 levels, a 2^32-leaf tree.
///
/// Not arbitrary, and not just "production-sized": hiding requires the
/// committed trace to carry more random degrees of freedom than the verifier
/// opens. This AIR has transition constraints, so the trace is opened at
/// `zeta` AND `zeta_next` on top of the FRI query rows: `rows >= queries + 3`.
/// At 20 queries the minimum power of two is 32, and since every trace row of
/// this AIR is one real fold level, rows ARE the tree depth. The hiding
/// requirement and a realistic anonymity set (2^32 leaves) meet at the same
/// number. `DEPTH = 4` stays untouched for the non-hiding path and the
/// existing contracts.
pub const ZK_DEPTH: usize = 32;

/// log2 of the quotient-chunk count for [`MembershipAir`] under ZK, pinned
/// like [`LOG_NUM_QUOTIENT_CHUNKS`] (the ZK path raises the constraint degree
/// by one). Guarded by
/// `the_pinned_zk_quotient_chunk_count_matches_the_symbolic_pass`.
pub const LOG_NUM_QUOTIENT_CHUNKS_ZK: usize = 3;

/// A hiding Circle-STARK proof that `leaf` sits under `root` via a private
/// 32-level authentication path: blinded trace commitment (`T' = T + Z_D*R`),
/// salted MMCS, randomized quotient chunks, randomization-polynomial round.
/// Same construction and same honesty scope as `zk.rs` (statistical ZK; the
/// leaf itself is still public).
pub struct ZkMembershipProof {
    inner: Proof<crate::zk::ZkConfig>,
}

impl ZkMembershipProof {
    /// log2 of the committed (doubled) polynomial dimension.
    pub fn degree_bits(&self) -> usize {
        self.inner.degree_bits
    }

    #[cfg(feature = "wire")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof is always serializable")
    }

    #[cfg(feature = "wire")]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }

    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof is always serializable")
    }

    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
    }
}

/// Prove membership hiding, over a [`ZK_DEPTH`]-level path. Same trace
/// construction as [`prove_membership`], taller; the hiding lives entirely in
/// the PCS. `rng_seed` feeds all prover-side randomness; production callers
/// MUST derive it from system entropy.
///
/// # Panics
/// If the path does not fold `leaf` to a consistent root (unsatisfiable
/// trace), or if `ZK_DEPTH < num_queries + 3` (the hiding margin; see
/// [`ZK_DEPTH`]'s doc for the arithmetic).
pub fn prove_membership_zk(
    leaf: [u64; DIGEST_LEN],
    path: &[PathStep; ZK_DEPTH],
    num_queries: usize,
    log_blowup: usize,
    seed: crate::zk::Seed,
) -> (ZkMembershipProof, [u64; DIGEST_LEN]) {
    assert!(
        ZK_DEPTH >= num_queries + 3,
        "hiding needs more random degrees of freedom than opened evaluations \
         (queries + zeta + zeta_next): lower num_queries or raise ZK_DEPTH"
    );
    let (inputs, bits, root) = build_rows_depth::<ZK_DEPTH>(leaf, path);
    let air = MembershipAir::new();
    let poseidon_trace: RowMajorMatrix<Val> = generate_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants(), 0);
    let trace = append_bit_column_depth::<ZK_DEPTH>(poseidon_trace, &bits);

    let pis = public_values(leaf, root);
    let config = crate::zk::make_zk_config_tuned(num_queries, log_blowup, seed);
    let proof = prove(&config, &air, trace, &pis);
    (ZkMembershipProof { inner: proof }, root)
}

/// Verify a [`ZkMembershipProof`] against a claimed `leaf` and `root`.
pub fn verify_membership_zk(
    proof: &ZkMembershipProof,
    leaf: [u64; DIGEST_LEN],
    root: [u64; DIGEST_LEN],
    num_queries: usize,
    log_blowup: usize,
) -> bool {
    let air = MembershipAir::new();
    let config = crate::zk::make_zk_config_tuned(num_queries, log_blowup, crate::zk::Seed::reproducible(0));
    let pis = public_values(leaf, root);
    verify_with_known_quotient_chunks(
        &config,
        &air,
        &proof.inner,
        &pis,
        None,
        LOG_NUM_QUOTIENT_CHUNKS_ZK,
    )
    .is_ok()
}

/// [`build_rows`] generalized over the path depth; the `DEPTH = 4` original
/// delegates here.
fn build_rows_depth<const D: usize>(
    leaf: [u64; DIGEST_LEN],
    path: &[PathStep; D],
) -> (Vec<[Val; WIDTH]>, [bool; D], [u64; DIGEST_LEN]) {
    let mut node = leaf;
    let mut inputs = Vec::with_capacity(D);
    let mut bits = [false; D];
    for (i, step) in path.iter().enumerate() {
        let (left, right) =
            if step.node_on_right { (step.sibling, node) } else { (node, step.sibling) };
        inputs.push(to_field(pack16(left, right)));
        bits[i] = step.node_on_right;
        node = compress(left, right);
    }
    (inputs, bits, node)
}

fn append_bit_column_depth<const D: usize>(
    poseidon_trace: RowMajorMatrix<Val>,
    bits: &[bool; D],
) -> RowMajorMatrix<Val> {
    let width = poseidon_trace.width;
    let mut values = Vec::with_capacity((width + 1) * D);
    for (row, bit) in poseidon_trace.values.chunks(width).zip(bits.iter()) {
        values.extend_from_slice(row);
        values.push(if *bit { Val::ONE } else { Val::ZERO });
    }
    RowMajorMatrix::new(values, width + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::zk::Seed;

    #[test]
    fn the_pinned_quotient_chunk_count_matches_the_symbolic_pass() {
        use p3_air::BaseAir;
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = MembershipAir::new();
        let config = make_config();
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, MembershipAir>(&air, layout, config.is_zk());
        assert_eq!(
            LOG_NUM_QUOTIENT_CHUNKS, recomputed,
            "the pinned constant must equal what the symbolic pass derives for this exact AIR; \
             if the AIR changed, re-pin the constant to the recomputed value"
        );
    }

    fn leaf_value(byte: u64) -> [u64; DIGEST_LEN] {
        core::array::from_fn(|i| byte * 3000 + i as u64)
    }

    fn sibling(byte: u64) -> [u64; DIGEST_LEN] {
        core::array::from_fn(|i| byte * 4000 + i as u64)
    }

    /// Build a genuine depth-DEPTH path with concrete, distinct siblings and a
    /// mixed left/right pattern, and fold it by hand (via `compress`) to get
    /// the real root, so tests never assert against an invented root.
    fn sample_path_and_root(leaf: [u64; DIGEST_LEN]) -> ([PathStep; DEPTH], [u64; DIGEST_LEN]) {
        let path: [PathStep; DEPTH] = core::array::from_fn(|i| PathStep {
            sibling: sibling(i as u64 + 1),
            node_on_right: i % 2 == 1,
        });
        let mut node = leaf;
        for step in &path {
            node = if step.node_on_right {
                compress(step.sibling, node)
            } else {
                compress(node, step.sibling)
            };
        }
        (path, node)
    }

    #[test]
    fn a_genuine_path_proves_and_verifies() {
        let leaf = leaf_value(1);
        let (path, root) = sample_path_and_root(leaf);
        let (proof, proved_root) = prove_membership(leaf, path);
        assert_eq!(proved_root, root, "the prover's computed root must match the hand-folded one");
        assert!(verify_membership(&proof, leaf, root), "a genuine path must verify");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_root() {
        let leaf = leaf_value(1);
        let (path, root) = sample_path_and_root(leaf);
        let (proof, _) = prove_membership(leaf, path);
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(!verify_membership(&proof, leaf, wrong_root), "must not verify against a tampered root");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_leaf() {
        let leaf = leaf_value(1);
        let (path, root) = sample_path_and_root(leaf);
        let (proof, _) = prove_membership(leaf, path);
        let other_leaf = leaf_value(2);
        assert!(
            !verify_membership(&proof, other_leaf, root),
            "must not verify a different leaf against this root"
        );
    }

    /// A genuine ZK_DEPTH-level path with distinct siblings and a mixed
    /// left/right pattern, hand-folded to its real root.
    fn sample_zk_path_and_root(
        leaf: [u64; DIGEST_LEN],
    ) -> ([PathStep; ZK_DEPTH], [u64; DIGEST_LEN]) {
        let path: [PathStep; ZK_DEPTH] = core::array::from_fn(|i| PathStep {
            sibling: sibling(i as u64 + 1),
            node_on_right: i % 3 == 1,
        });
        let mut node = leaf;
        for step in &path {
            node = if step.node_on_right {
                compress(step.sibling, node)
            } else {
                compress(node, step.sibling)
            };
        }
        (path, node)
    }

    /// Fast-but-real hiding parameters: 20 queries at blowup 4 is the
    /// on-chain candidate; ZK_DEPTH = 32 >= 20 + 3 holds the hiding margin.
    const ZK_TEST_QUERIES: usize = 20;
    const ZK_TEST_LOG_BLOWUP: usize = 2;

    #[test]
    fn the_pinned_zk_quotient_chunk_count_matches_the_symbolic_pass() {
        use p3_air::BaseAir;
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = MembershipAir::new();
        let config = crate::zk::make_zk_config_tuned(4, 1, crate::zk::Seed::reproducible(0));
        assert_eq!(config.is_zk(), 1, "the hiding PCS must flip the ZK path on");
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, MembershipAir>(&air, layout, config.is_zk());
        assert_eq!(
            LOG_NUM_QUOTIENT_CHUNKS_ZK, recomputed,
            "the pinned ZK constant must equal what the symbolic pass derives; \
             if the AIR changed, re-pin it to the recomputed value"
        );
    }

    #[test]
    fn a_hiding_membership_proof_proves_and_verifies() {
        let leaf = leaf_value(1);
        let (path, root) = sample_zk_path_and_root(leaf);
        let (proof, proved_root) =
            prove_membership_zk(leaf, &path, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP, Seed::reproducible(42));
        assert_eq!(proved_root, root, "the prover's root must match the hand-folded one");
        assert!(
            verify_membership_zk(&proof, leaf, root, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP),
            "a genuine hiding membership proof must verify"
        );
    }

    #[test]
    fn a_hiding_membership_proof_rejects_a_tampered_root() {
        let leaf = leaf_value(1);
        let (path, root) = sample_zk_path_and_root(leaf);
        let (proof, _) =
            prove_membership_zk(leaf, &path, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP, Seed::reproducible(42));
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(
            !verify_membership_zk(&proof, leaf, wrong_root, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP),
            "soundness must survive the hiding machinery: tampered root rejected"
        );
    }

    #[test]
    fn two_hiding_membership_proofs_of_the_same_path_differ() {
        let leaf = leaf_value(1);
        let (path, root) = sample_zk_path_and_root(leaf);
        let (a, _) = prove_membership_zk(leaf, &path, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP, Seed::reproducible(1));
        let (b, _) = prove_membership_zk(leaf, &path, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP, Seed::reproducible(2));
        assert!(
            verify_membership_zk(&a, leaf, root, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP)
                && verify_membership_zk(&b, leaf, root, ZK_TEST_QUERIES, ZK_TEST_LOG_BLOWUP),
            "both seeded proofs must verify"
        );
        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "different blinding seeds must produce different proofs of the same path"
        );
    }

    #[test]
    fn a_path_that_does_not_fold_to_the_claimed_root_cannot_yield_a_verifying_proof() {
        // A malicious/broken path: reuse a genuine path's siblings and bits,
        // but for the WRONG leaf, so folding it does not actually reach the
        // root claimed to the prover. Mirrors permutation.rs's documented
        // "panics on an unsatisfiable trace" behavior.
        let leaf = leaf_value(1);
        let (path, root) = sample_path_and_root(leaf);
        let wrong_leaf = leaf_value(99);

        // Directly forge the trace: fold wrong_leaf through the path (so the
        // trace is internally consistent with itself) but claim the ORIGINAL
        // root as the public input, which this folding does not reach.
        let (inputs, bits, actual_root) = build_rows(wrong_leaf, path);
        assert_ne!(actual_root, root, "sanity: folding the wrong leaf must not reach the same root");

        let air = MembershipAir::new();
        let poseidon_trace: RowMajorMatrix<Val> = generate_trace_rows::<
            Val,
            LinearLayers,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(inputs, &constants(), 0);
        let trace = append_bit_column(poseidon_trace, &bits);
        let pis = public_values(wrong_leaf, root); // claims the ORIGINAL root
        let config = make_config();

        // `prove` runs `check_constraints` only under `debug_assertions`
        // (p3-uni-stark 0.6.2, prover.rs:39), so in RELEASE — the profile that
        // ships — it emits a proof for this unsatisfiable trace rather than
        // panicking. Asserting only the panic made this test vacuous exactly
        // where it mattered. The claim that holds in both profiles is that no
        // such proof verifies.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &pis)
        }));
        match attempt {
            Err(_) => { /* debug: the prover refused to build it at all */ }
            Ok(proof) => assert!(
                !verify_membership(&MembershipProof { inner: proof }, wrong_leaf, root),
                "a fold that does not reach the claimed root produced a proof that \
                 verified: the root constraint is not binding"
            ),
        }
    }
}
