//! Hidden in the crowd: the composition moves from the public leaf to a
//! commitment, and two uses of one credential stop being linkable.
//!
//! `docs/PRIVACY.md` (riverrun-soroban) has said from the start that
//! witness-hiding alone is half the fix: the binding and membership proofs
//! were composed by a PUBLIC leaf value, so an observer could link every use
//! of a credential through that value even once the witnesses were hidden.
//! This module is the second half. Both relations now publish
//!
//! ```text
//!     C = compress(leaf, blinder) = permute(leaf ‖ blinder)[0..8]
//! ```
//!
//! in place of the leaf, with a fresh random `blinder` per use, and the
//! composition compares commitments. The leaf appears in no public input of
//! either proof.
//!
//! ## How each relation grows a commitment
//!
//! **Binding** (`CrowdBindingAir`): the vectorized row gains a third
//! permutation block, `permute(leaf_out[0..8] ‖ blinder)`. Same-row equality
//! ties the block's first eight inputs to the leaf block's first eight
//! outputs, and the block's first eight outputs to the public `C`. The
//! blinder cells are private witness. Public inputs shrink from
//! `action ‖ round ‖ leaf(16) ‖ nullifier(16)` to
//! `action ‖ round ‖ C(8) ‖ nullifier(16)`: the nullifier stays public
//! because consensus burns it; the leaf is gone.
//!
//! **Membership** (`CrowdMembershipAir`): the commitment IS one `compress`,
//! which is exactly what every row of this AIR already computes. Row 0
//! becomes the commitment row: `permute(leaf ‖ blinder)` with its truncated
//! output constrained to the public `C`. A boolean `is_commit` column (1 on
//! row 0, forced 0 everywhere else by transition constraints) masks the fold
//! continuity constraint on the commitment row, and a first-row constraint
//! links the fold's start to the commitment row's own `inputs[0..8]`, the
//! private leaf. One commit row plus 31 fold levels fills the 32-row trace
//! exactly: a 2^31-leaf tree, and the hiding margin (`rows >= queries + 3`)
//! still holds at 20 queries.
//!
//! ## What "unlinkable" claims, exactly
//!
//! - `C` is binding up to collisions of the Poseidon2 compression and hiding
//!   under the usual random-oracle/PRF-style assumption on the permutation
//!   with a uniform 248-bit blinder. Neither property is information
//!   theoretic, and neither has a bespoke security proof here.
//! - Unlinkability is across USES (fresh blinder, fresh `C`). The nullifier
//!   is still linkable within a round by design; that is what prevents double
//!   spends.
//! - Both proofs of one use must share the same `(leaf, blinder)` pair, or
//!   their `C`s differ and [`verify_crowd`] rejects.
//! - The two relations remain two proofs composed by a shared public value
//!   (now `C` instead of the leaf), not one fused trace. On-chain they are
//!   two transactions whose public `C`s can be compared by anyone, including
//!   a pool contract.
//! - Everything inherits `zk.rs`'s hiding claims: statistical ZK, and the
//!   prover-side RNG in tests is NOT cryptographic (a production caller must
//!   seed blinder, blinding polynomials and salts from system entropy).

extern crate alloc;

use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use p3_mersenne_31::{
    GenericPoseidon2LinearLayersMersenne31, Mersenne31, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL, MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_air::{
    generate_trace_rows, generate_vectorized_trace_rows, num_cols, Poseidon2Air, Poseidon2Cols,
    RoundConstants, VectorizedPoseidon2Air,
};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, SubAirBuilder};

use crate::binding::{CONTEXT_LEN, SECRET_LEN};
use crate::membership::{compress, PathStep, DIGEST_LEN};
use crate::permutation::{permute, WIDTH};
use crate::zk::{make_zk_config_tuned, ZkConfig};

const SBOX_DEGREE: u64 = 5;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 14;

type Val = Mersenne31;
type LinearLayers = GenericPoseidon2LinearLayersMersenne31;
type Cols<T> =
    Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// Blinder width: 8 M31 limbs, 248 bits of commitment randomness.
pub const BLINDER_LEN: usize = DIGEST_LEN;

/// Tree depth of the crowd membership proof: 31 fold levels, because row 0 of
/// the 32-row trace is the commitment row. A 2^31-leaf tree.
pub const CROWD_DEPTH: usize = 31;

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

fn to_field(input: [u64; WIDTH]) -> [Val; WIDTH] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

// ---------------------------------------------------------------------------
// Binding with a committed leaf.
// ---------------------------------------------------------------------------

/// Three permutations per row: leaf, nullifier, commitment.
const CROWD_VECTOR_LEN: usize = 3;

type CrowdInnerAir = VectorizedPoseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    CROWD_VECTOR_LEN,
>;

/// The binding AIR with the leaf behind a commitment. Block 0 computes the
/// leaf, block 1 the nullifier (sharing block 0's secret cells, the binding),
/// block 2 the commitment `permute(leaf_out[0..8] ‖ blinder)`. Public inputs:
/// `action ‖ round ‖ C(8) ‖ nullifier(16)`. The leaf and the blinder are
/// private witness only.
struct CrowdBindingAir {
    inner: CrowdInnerAir,
}

impl CrowdBindingAir {
    fn new() -> Self {
        Self { inner: CrowdInnerAir::new(constants()) }
    }
}

impl BaseAir<Val> for CrowdBindingAir {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn num_public_values(&self) -> usize {
        2 * CONTEXT_LEN + DIGEST_LEN + WIDTH
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for CrowdBindingAir {
    fn eval(&self, builder: &mut AB) {
        self.inner.eval(builder);

        let main = builder.main();
        let full = main.current_slice();
        let w = single_width();
        let block0: &Cols<AB::Var> = full[..w].borrow();
        let block1: &Cols<AB::Var> = full[w..2 * w].borrow();
        let block2: &Cols<AB::Var> = full[2 * w..3 * w].borrow();

        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        // pis layout: action | round | C(8) | nullifier(16)
        let action = &pis[0..CONTEXT_LEN];
        let round = &pis[CONTEXT_LEN..2 * CONTEXT_LEN];
        let c = &pis[2 * CONTEXT_LEN..2 * CONTEXT_LEN + DIGEST_LEN];
        let nullifier = &pis[2 * CONTEXT_LEN + DIGEST_LEN..2 * CONTEXT_LEN + DIGEST_LEN + WIDTH];

        let block0_output = &block0.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
        let block1_output = &block1.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
        let block2_output = &block2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        for i in 0..CONTEXT_LEN {
            builder.assert_eq(block0.inputs[SECRET_LEN + i].into(), action[i].into());
            builder.assert_eq(block1.inputs[SECRET_LEN + i].into(), round[i].into());
        }
        // The binding: one secret drives both the leaf and the nullifier.
        for i in 0..SECRET_LEN {
            builder.assert_eq(block0.inputs[i].into(), block1.inputs[i].into());
        }
        // The nullifier stays public: consensus burns it.
        for i in 0..WIDTH {
            builder.assert_eq(block1_output[i].into(), nullifier[i].into());
        }
        // The commitment block: its input is the (private) leaf digest, its
        // truncated output is the public C. The blinder cells
        // (inputs[DIGEST_LEN..]) are deliberately unconstrained witness.
        for i in 0..DIGEST_LEN {
            builder.assert_eq(block2.inputs[i].into(), block0_output[i].into());
            builder.assert_eq(block2_output[i].into(), c[i].into());
        }
    }
}

/// log2 of the quotient-chunk count for [`CrowdBindingAir`] under ZK, pinned
/// like every other verifier constant in this crate (no symbolic pass in the
/// wasm verifier); guarded by
/// `the_pinned_crowd_chunk_counts_match_the_symbolic_pass`.
pub const CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS: usize = 3;

/// A hiding binding proof whose leaf is behind the commitment `C`.
pub struct CrowdBindingProof {
    inner: Proof<ZkConfig>,
}

impl CrowdBindingProof {
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

/// Prove the binding relation with the leaf committed: returns the proof, the
/// public commitment `C`, and the nullifier. The leaf digest itself is
/// returned too so the caller can feed the SAME `(leaf, blinder)` pair to
/// [`prove_membership_crowd`]; it appears in no public input.
///
/// # Panics
/// If `2^log_rows < num_queries + 2` (hiding margin, this AIR has no
/// transition constraints) or `log_rows < 2`.
#[allow(clippy::type_complexity)]
pub fn prove_binding_crowd(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    blinder: [u64; BLINDER_LEN],
    num_queries: usize,
    log_blowup: usize,
    log_rows: usize,
    rng_seed: u64,
) -> (CrowdBindingProof, [u64; DIGEST_LEN], [u64; DIGEST_LEN], [u64; WIDTH]) {
    assert!(log_rows >= 2, "CirclePcs cannot commit to fewer than 4 rows");
    assert!(
        (1usize << log_rows) >= num_queries + 2,
        "hiding needs more random degrees of freedom than opened evaluations"
    );
    let leaf_input = pack(secret, action);
    let nullifier_input = pack(secret, round);
    let leaf_output = permute(leaf_input);
    let leaf_digest: [u64; DIGEST_LEN] = core::array::from_fn(|i| leaf_output[i]);
    let nullifier_output = permute(nullifier_input);
    let commit_input = pack_digest(leaf_digest, blinder);
    let c = compress(leaf_digest, blinder);

    let rows = 1usize << log_rows;
    let mut inputs: Vec<[Val; WIDTH]> = Vec::with_capacity(CROWD_VECTOR_LEN * rows);
    for _ in 0..rows {
        inputs.push(to_field(leaf_input));
        inputs.push(to_field(nullifier_input));
        inputs.push(to_field(commit_input));
    }
    let trace: RowMajorMatrix<Val> = generate_vectorized_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
        CROWD_VECTOR_LEN,
    >(inputs, &constants(), 0);

    let air = CrowdBindingAir::new();
    let pis = binding_public_values(action, round, c, nullifier_output);
    let config = make_zk_config_tuned(num_queries, log_blowup, rng_seed);
    let proof = prove(&config, &air, trace, &pis);
    (CrowdBindingProof { inner: proof }, c, leaf_digest, nullifier_output)
}

/// Verify a [`CrowdBindingProof`] against `action`, `round`, the public
/// commitment `c`, and the public `nullifier`. No leaf anywhere.
pub fn verify_binding_crowd(
    proof: &CrowdBindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    c: [u64; DIGEST_LEN],
    nullifier: [u64; WIDTH],
    num_queries: usize,
    log_blowup: usize,
) -> bool {
    let air = CrowdBindingAir::new();
    let config = make_zk_config_tuned(num_queries, log_blowup, 0);
    let pis = binding_public_values(action, round, c, nullifier);
    verify_with_known_quotient_chunks(
        &config,
        &air,
        &proof.inner,
        &pis,
        None,
        CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS,
    )
    .is_ok()
}

fn binding_public_values(
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    c: [u64; DIGEST_LEN],
    nullifier: [u64; WIDTH],
) -> Vec<Val> {
    let mut pis = Vec::with_capacity(2 * CONTEXT_LEN + DIGEST_LEN + WIDTH);
    pis.extend((0..CONTEXT_LEN).map(|i| Val::from_u64(action[i])));
    pis.extend((0..CONTEXT_LEN).map(|i| Val::from_u64(round[i])));
    pis.extend((0..DIGEST_LEN).map(|i| Val::from_u64(c[i])));
    pis.extend((0..WIDTH).map(|i| Val::from_u64(nullifier[i])));
    pis
}

fn pack(secret: [u64; SECRET_LEN], context: [u64; CONTEXT_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..SECRET_LEN].copy_from_slice(&secret);
    out[SECRET_LEN..].copy_from_slice(&context);
    out
}

fn pack_digest(left: [u64; DIGEST_LEN], right: [u64; DIGEST_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..DIGEST_LEN].copy_from_slice(&left);
    out[DIGEST_LEN..].copy_from_slice(&right);
    out
}

// ---------------------------------------------------------------------------
// Membership with a committed leaf.
// ---------------------------------------------------------------------------

type MemInnerAir = Poseidon2Air<
    Val,
    LinearLayers,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// The membership AIR with the leaf behind a commitment. Row layout:
/// `[poseidon columns | bit | is_commit]`. Row 0 is the commitment row
/// (`is_commit = 1`, forced 0 on every other row by transition constraints):
/// it computes `permute(leaf ‖ blinder)`, its truncated output is the public
/// `C`, and its `inputs[0..8]` (the private leaf) seed the fold via a
/// first-row link to row 1's selected node. Rows 1..=CROWD_DEPTH fold to the
/// public root; the fold-continuity constraint is masked on the commitment
/// row by `(1 - is_commit)`.
struct CrowdMembershipAir {
    inner: MemInnerAir,
}

impl CrowdMembershipAir {
    fn new() -> Self {
        Self { inner: MemInnerAir::new(constants()) }
    }
}

impl BaseAir<Val> for CrowdMembershipAir {
    fn width(&self) -> usize {
        single_width() + 2
    }

    fn num_public_values(&self) -> usize {
        2 * DIGEST_LEN
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for CrowdMembershipAir {
    fn eval(&self, builder: &mut AB) {
        let w = single_width();

        let mut sub: SubAirBuilder<AB, MemInnerAir, Val> = SubAirBuilder::new(builder, 0..w);
        self.inner.eval(&mut sub);

        let main = builder.main();
        let current = main.current_slice();
        let next = main.next_slice();

        let poseidon: &Cols<AB::Var> = current[..w].borrow();
        let poseidon_next: &Cols<AB::Var> = next[..w].borrow();
        let bit: AB::Expr = current[w].clone().into();
        let bit_next: AB::Expr = next[w].clone().into();
        let is_commit: AB::Expr = current[w + 1].clone().into();
        let is_commit_next: AB::Expr = next[w + 1].clone().into();

        // Both selector columns are boolean.
        builder.assert_zero(bit.clone() * (AB::Expr::ONE - bit));
        builder.assert_zero(is_commit.clone() * (AB::Expr::ONE - is_commit.clone()));
        // is_commit is 1 exactly on row 0.
        builder.when_first_row().assert_eq(is_commit.clone(), AB::Expr::ONE);
        builder.when_transition().assert_zero(is_commit_next);

        let output = &poseidon.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = &pis[0..DIGEST_LEN];
        let root = &pis[DIGEST_LEN..2 * DIGEST_LEN];

        let selected_node = |cols: &Cols<AB::Var>, bit: AB::Expr| -> Vec<AB::Expr> {
            (0..DIGEST_LEN)
                .map(|j| {
                    let left: AB::Expr = cols.inputs[j].into();
                    let right: AB::Expr = cols.inputs[DIGEST_LEN + j].into();
                    (AB::Expr::ONE - bit.clone()) * left + bit.clone() * right
                })
                .collect()
        };
        let next_node = selected_node(poseidon_next, bit_next);

        // Commitment row: its truncated output is the public C, and its
        // inputs[0..8] (the private leaf; inputs[8..16] are the private
        // blinder, deliberately unconstrained) seed the fold on row 1.
        for j in 0..DIGEST_LEN {
            builder.when_first_row().assert_eq(output[j].into(), c[j].into());
            builder
                .when_first_row()
                .assert_eq(next_node[j].clone(), poseidon.inputs[j].into());
        }

        // Fold continuity everywhere except leaving the commitment row (that
        // hop is governed by the first-row link above).
        for j in 0..DIGEST_LEN {
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - is_commit.clone()) * (next_node[j].clone() - output[j].into()),
            );
        }

        // Last row: the fold reached the public root.
        for j in 0..DIGEST_LEN {
            builder.when_last_row().assert_eq(output[j].into(), root[j].into());
        }
    }
}

/// log2 of the quotient-chunk count for [`CrowdMembershipAir`] under ZK,
/// pinned and test-guarded like its siblings.
pub const CROWD_MEMBERSHIP_LOG_NUM_QUOTIENT_CHUNKS: usize = 3;

/// A hiding membership proof whose leaf is behind the commitment `C`.
pub struct CrowdMembershipProof {
    inner: Proof<ZkConfig>,
}

impl CrowdMembershipProof {
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

/// Prove membership with the leaf committed: `leaf` sits under the returned
/// root via the private `path`, and `C = compress(leaf, blinder)` is the only
/// leaf-derived public value. Feed the same `(leaf, blinder)` as
/// [`prove_binding_crowd`] so the two `C`s match.
///
/// # Panics
/// If the trace is unsatisfiable, or if the 32-row height violates the
/// hiding margin (`32 >= num_queries + 3`).
pub fn prove_membership_crowd(
    leaf: [u64; DIGEST_LEN],
    blinder: [u64; BLINDER_LEN],
    path: &[PathStep; CROWD_DEPTH],
    num_queries: usize,
    log_blowup: usize,
    rng_seed: u64,
) -> (CrowdMembershipProof, [u64; DIGEST_LEN], [u64; DIGEST_LEN]) {
    let rows = CROWD_DEPTH + 1;
    assert!(rows.is_power_of_two(), "commit row + CROWD_DEPTH fold rows must fill a power of two");
    assert!(
        rows >= num_queries + 3,
        "hiding needs more random degrees of freedom than opened evaluations \
         (queries + zeta + zeta_next)"
    );

    let c = compress(leaf, blinder);

    // Row 0: the commitment permutation. Rows 1..: the fold.
    let mut inputs: Vec<[Val; WIDTH]> = Vec::with_capacity(rows);
    let mut bits = Vec::with_capacity(rows);
    inputs.push(to_field(pack_digest(leaf, blinder)));
    bits.push(false);
    let mut node = leaf;
    for step in path.iter() {
        let (left, right) =
            if step.node_on_right { (step.sibling, node) } else { (node, step.sibling) };
        inputs.push(to_field(pack_digest(left, right)));
        bits.push(step.node_on_right);
        node = compress(left, right);
    }
    let root = node;

    let poseidon_trace: RowMajorMatrix<Val> = generate_trace_rows::<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants(), 0);
    let trace = append_selector_columns(poseidon_trace, &bits);

    let air = CrowdMembershipAir::new();
    let pis = membership_public_values(c, root);
    let config = make_zk_config_tuned(num_queries, log_blowup, rng_seed);
    let proof = prove(&config, &air, trace, &pis);
    (CrowdMembershipProof { inner: proof }, c, root)
}

/// Verify a [`CrowdMembershipProof`] against the public commitment `c` and
/// `root`. No leaf anywhere.
pub fn verify_membership_crowd(
    proof: &CrowdMembershipProof,
    c: [u64; DIGEST_LEN],
    root: [u64; DIGEST_LEN],
    num_queries: usize,
    log_blowup: usize,
) -> bool {
    let air = CrowdMembershipAir::new();
    let config = make_zk_config_tuned(num_queries, log_blowup, 0);
    let pis = membership_public_values(c, root);
    verify_with_known_quotient_chunks(
        &config,
        &air,
        &proof.inner,
        &pis,
        None,
        CROWD_MEMBERSHIP_LOG_NUM_QUOTIENT_CHUNKS,
    )
    .is_ok()
}

fn membership_public_values(c: [u64; DIGEST_LEN], root: [u64; DIGEST_LEN]) -> Vec<Val> {
    let mut pis = Vec::with_capacity(2 * DIGEST_LEN);
    pis.extend((0..DIGEST_LEN).map(|i| Val::from_u64(c[i])));
    pis.extend((0..DIGEST_LEN).map(|i| Val::from_u64(root[i])));
    pis
}

/// Append the `bit` and `is_commit` columns: `is_commit` is 1 on row 0 only.
fn append_selector_columns(
    poseidon_trace: RowMajorMatrix<Val>,
    bits: &[bool],
) -> RowMajorMatrix<Val> {
    let width = poseidon_trace.width;
    let rows = bits.len();
    let mut values = Vec::with_capacity((width + 2) * rows);
    for (i, (row, bit)) in poseidon_trace.values.chunks(width).zip(bits.iter()).enumerate() {
        values.extend_from_slice(row);
        values.push(if *bit { Val::ONE } else { Val::ZERO });
        values.push(if i == 0 { Val::ONE } else { Val::ZERO });
    }
    RowMajorMatrix::new(values, width + 2)
}

// ---------------------------------------------------------------------------
// The composition.
// ---------------------------------------------------------------------------

/// The full crowd statement, composed over the commitment: BOTH proofs verify
/// AND they publish the same `C`. An anonymous, unlinkable use of one
/// credential: "some member of the tree under `root` performed `action` in
/// `round`, and here is the nullifier consensus should burn" — with no
/// leaf-shaped value linking this use to any other.
#[allow(clippy::too_many_arguments)]
pub fn verify_crowd(
    binding: &CrowdBindingProof,
    membership: &CrowdMembershipProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    c: [u64; DIGEST_LEN],
    nullifier: [u64; WIDTH],
    root: [u64; DIGEST_LEN],
    num_queries: usize,
    log_blowup: usize,
) -> bool {
    verify_binding_crowd(binding, action, round, c, nullifier, num_queries, log_blowup)
        && verify_membership_crowd(membership, c, root, num_queries, log_blowup)
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: usize = 20;
    const LOG_B: usize = 2;
    const LOG_ROWS: usize = 5;

    fn secret(byte: u64) -> [u64; SECRET_LEN] {
        core::array::from_fn(|i| byte * 1000 + i as u64)
    }

    fn context(byte: u64) -> [u64; CONTEXT_LEN] {
        core::array::from_fn(|i| byte * 2000 + i as u64)
    }

    fn blinder(byte: u64) -> [u64; BLINDER_LEN] {
        core::array::from_fn(|i| byte * 7000 + i as u64)
    }

    fn sample_path(leaf: [u64; DIGEST_LEN]) -> ([PathStep; CROWD_DEPTH], [u64; DIGEST_LEN]) {
        let path: [PathStep; CROWD_DEPTH] = core::array::from_fn(|i| PathStep {
            sibling: core::array::from_fn(|j| (i as u64 + 1) * 4000 + j as u64),
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

    #[test]
    fn the_pinned_crowd_chunk_counts_match_the_symbolic_pass() {
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let config = make_zk_config_tuned(4, 1, 0);
        assert_eq!(config.is_zk(), 1);

        let air = CrowdBindingAir::new();
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, CrowdBindingAir>(&air, layout, config.is_zk());
        assert_eq!(CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS, recomputed);

        let air = CrowdMembershipAir::new();
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, CrowdMembershipAir>(&air, layout, config.is_zk());
        assert_eq!(CROWD_MEMBERSHIP_LOG_NUM_QUOTIENT_CHUNKS, recomputed);
    }

    #[test]
    fn the_full_crowd_statement_proves_and_verifies() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let b = blinder(1);
        let (bproof, c, leaf_digest, nullifier) =
            prove_binding_crowd(s, action, round, b, Q, LOG_B, LOG_ROWS, 42);
        let (path, _) = sample_path(leaf_digest);
        let (mproof, c2, root) = prove_membership_crowd(leaf_digest, b, &path, Q, LOG_B, 43);
        assert_eq!(c, c2, "same (leaf, blinder) must commit identically in both relations");
        assert!(
            verify_crowd(&bproof, &mproof, action, round, c, nullifier, root, Q, LOG_B),
            "the composed crowd statement must verify"
        );
    }

    #[test]
    fn a_tampered_commitment_is_rejected_by_both_relations() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let b = blinder(1);
        let (bproof, c, leaf_digest, nullifier) =
            prove_binding_crowd(s, action, round, b, Q, LOG_B, LOG_ROWS, 42);
        let (path, _) = sample_path(leaf_digest);
        let (mproof, _, root) = prove_membership_crowd(leaf_digest, b, &path, Q, LOG_B, 43);
        let mut wrong_c = c;
        wrong_c[0] ^= 1;
        assert!(!verify_binding_crowd(&bproof, action, round, wrong_c, nullifier, Q, LOG_B));
        assert!(!verify_membership_crowd(&mproof, wrong_c, root, Q, LOG_B));
    }

    #[test]
    fn different_blinders_break_the_composition_as_they_must() {
        // Two proofs about the same leaf but with different blinders publish
        // different Cs: the composition rejects, which is exactly the rule
        // that forces one (leaf, blinder) pair per use.
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (bproof, c_b, leaf_digest, nullifier) =
            prove_binding_crowd(s, action, round, blinder(1), Q, LOG_B, LOG_ROWS, 42);
        let (path, _) = sample_path(leaf_digest);
        let (mproof, c_m, root) =
            prove_membership_crowd(leaf_digest, blinder(2), &path, Q, LOG_B, 43);
        assert_ne!(c_b, c_m);
        assert!(
            !verify_crowd(&bproof, &mproof, action, round, c_b, nullifier, root, Q, LOG_B),
            "mismatched blinders must not compose"
        );
    }

    #[test]
    fn two_uses_of_one_credential_are_not_linkable_through_public_values() {
        // The unlinkability claim, stated as a test: the same member, two
        // uses (fresh blinder each), and the two binding proofs share NO
        // public value except action/round chosen by the protocol. The
        // commitments differ; the leaf appears nowhere.
        let s = secret(1);
        let action = context(1);
        let (b1, c1, _, n1) =
            prove_binding_crowd(s, action, context(10), blinder(1), Q, LOG_B, LOG_ROWS, 42);
        let (b2, c2, _, n2) =
            prove_binding_crowd(s, action, context(11), blinder(2), Q, LOG_B, LOG_ROWS, 43);
        assert_ne!(c1, c2, "fresh blinders must yield different commitments");
        assert_ne!(n1, n2, "different rounds must yield different nullifiers");
        assert!(verify_binding_crowd(&b1, action, context(10), c1, n1, Q, LOG_B));
        assert!(verify_binding_crowd(&b2, action, context(11), c2, n2, Q, LOG_B));
    }

    #[test]
    fn a_forged_membership_for_a_different_leaf_under_the_same_c_fails() {
        // The binding property of C, exercised end to end: a prover who knows
        // C (public) but not (leaf, blinder) cannot open it to a different
        // leaf. We simulate the strongest cheap attacker: reuse the real
        // blinder with a different leaf; the commitment row then computes a
        // different C and the proof verifies only against THAT C, not ours.
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let b = blinder(1);
        let (_, c, leaf_digest, _) =
            prove_binding_crowd(s, action, round, b, Q, LOG_B, LOG_ROWS, 42);
        let other_leaf: [u64; DIGEST_LEN] = core::array::from_fn(|i| 9000 + i as u64);
        assert_ne!(other_leaf, leaf_digest);
        let (path, _) = sample_path(other_leaf);
        let (forged, forged_c, forged_root) =
            prove_membership_crowd(other_leaf, b, &path, Q, LOG_B, 44);
        assert_ne!(forged_c, c);
        assert!(
            !verify_membership_crowd(&forged, c, forged_root, Q, LOG_B),
            "a membership proof for a different leaf must not verify against our C"
        );
    }
}
