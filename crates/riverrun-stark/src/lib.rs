//! # riverrun-stark
//!
//! A **transparent, post-quantum STARK proof of anonymous set membership**:
//! prove knowledge of a leaf preimage whose Rescue-Prime hash sits under a public
//! Merkle root — *without revealing which leaf*. Hash-based (Rescue-Prime over the
//! 128-bit field) and FRI-based, so post-quantum; no trusted setup, no ceremony.
//!
//! This is the succinct zero-knowledge upgrade of riverrun's membership seam. The
//! Rescue-Prime Merkle-path AIR (`air.rs`, `prover.rs`, `utils/`) is adapted from
//! the Winterfell v0.13 `merkle` example (MIT, Facebook/Meta); the public API and
//! tests here wrap it as a clean membership prover/verifier.
//!
//! Scope: this proves *set membership* (the core unlinkability primitive). Binding
//! the leaf to `commit(secret, action)` and the revealed `nullifier` inside the
//! same AIR — so the proof also witnesses the nullifier — is the next increment
//! (the relation is specified in `riverrun-core::membership::check_relation`).

// Used only by this module's public API.
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::MerkleTree;
use winterfell::{AcceptableOptions, BatchingMethod, FieldExtension, Proof, VerifierError};

mod air;
mod prover;
mod utils;

// Crate-root re-exports so the ported `air.rs` / `prover.rs` resolve their
// `crate::{...}` imports (they were `super::{...}` in the Winterfell example),
// and so this module can name them too.
pub(crate) use air::{MerkleAir, PublicInputs};
pub(crate) use core::marker::PhantomData;
pub(crate) use prover::MerkleProver;
pub(crate) use rescue::{
    CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS, STATE_WIDTH as HASH_STATE_WIDTH,
};
pub(crate) use utils::rescue;
pub(crate) use winterfell::crypto::{DefaultRandomCoin, ElementHasher};
pub(crate) use winterfell::math::{fields::f128::BaseElement, FieldElement};
pub(crate) use winterfell::{ProofOptions, Prover};

pub(crate) const TRACE_WIDTH: usize = 7;

/// The in-circuit Merkle hash is Rescue-Prime; re-exported for building trees.
pub use rescue::{Hash, Rescue128};

/// The STARK's own commitment / Fiat-Shamir hash (distinct from the in-circuit
/// Rescue). Any collision-resistant hash works; BLAKE3 keeps the whole stack
/// hash-based and post-quantum.
type StarkHash = Blake3_256<BaseElement>;

/// Proof options: 28 queries at blow-up factor 8 → ~128-bit conjectured security,
/// no field extension. Transparent (no setup).
fn proof_options() -> ProofOptions {
    ProofOptions::new(
        28,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Build a Rescue-Prime Merkle tree (the anonymity set) from its leaves.
pub fn build_tree(leaves: Vec<Hash>) -> MerkleTree<Rescue128> {
    MerkleTree::new(leaves).expect("power-of-two leaf count")
}

/// Prove, in zero knowledge, that `value` is the preimage of the leaf at `index`
/// of `tree` — i.e. that a member with this leaf is in the set with `tree`'s root.
/// The proof reveals only the root; `value` and `index` stay private.
pub fn prove_membership(
    tree: &MerkleTree<Rescue128>,
    value: [BaseElement; 2],
    index: usize,
) -> Proof {
    let (leaf, path) = tree.prove(index).expect("valid index");
    let mut branch = vec![leaf];
    branch.extend_from_slice(&path);
    let prover = MerkleProver::<StarkHash>::new(proof_options());
    let trace = prover.build_trace(value, &branch, index);
    prover.prove(trace).expect("prove membership")
}

/// Verify a membership proof against the public set root. Accepts iff the proof
/// witnesses some leaf preimage resolving to `root` — without learning which.
pub fn verify_membership(root: Hash, proof: Proof) -> Result<(), VerifierError> {
    let pub_inputs = PublicInputs { tree_root: root.to_elements() };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<MerkleAir, StarkHash, DefaultRandomCoin<StarkHash>, MerkleTree<StarkHash>>(
        proof,
        pub_inputs,
        &acceptable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an 8-leaf set with `value`'s digest planted at `index`.
    fn set_with(value: [BaseElement; 2], index: usize) -> MerkleTree<Rescue128> {
        let mut leaves: Vec<Hash> = (0..8u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        leaves[index] = Rescue128::digest(&value);
        build_tree(leaves)
    }

    #[test]
    fn membership_proves_and_verifies() {
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index = 5;
        let tree = set_with(value, index);
        let root = *tree.root();
        let proof = prove_membership(&tree, value, index);
        assert!(verify_membership(root, proof).is_ok(), "valid member must verify");
    }

    #[test]
    fn proof_against_wrong_root_is_rejected() {
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index = 3;
        let tree = set_with(value, index);
        let proof = prove_membership(&tree, value, index);
        // A different (swapped) root must not accept the proof.
        let real = tree.root().to_elements();
        let wrong = Hash::new(real[1], real[0]);
        assert!(verify_membership(wrong, proof).is_err(), "a wrong root must be rejected");
    }
}
