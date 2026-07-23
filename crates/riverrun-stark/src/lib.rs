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
pub(crate) use winterfell::math::FieldElement;
pub(crate) use winterfell::{ProofOptions, Prover};

/// The field over which the in-circuit Rescue hash and leaf preimages live.
pub use winterfell::math::fields::f128::BaseElement;

pub(crate) const TRACE_WIDTH: usize = 7;

/// The in-circuit Merkle hash is Rescue-Prime; re-exported for building trees.
pub use rescue::{Hash, Rescue128};

/// The STARK's own commitment / Fiat-Shamir hash (distinct from the in-circuit
/// Rescue). Any collision-resistant hash works; BLAKE3 keeps the whole stack
/// hash-based and post-quantum.
type StarkHash = Blake3_256<BaseElement>;

/// Proof options: 28 queries at blow-up factor 8, no grinding, no field extension
/// → only **~84 bits** of conjectured security (28 × log2(8)), NOT production
/// strength. A production deployment must raise this (more queries, grinding, or
/// a field extension) to ~128 bits, and use the full-round Rescue parameters.
/// These example-grade parameters are for demonstrating the proof end-to-end.
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

// --- High-level API: the transmitted proof carries no witness ----------------

/// An anonymity set backed by the Rescue-Prime Merkle tree, hiding the winterfell
/// types so a consumer (e.g. the pool) never touches them.
pub struct MembershipSet {
    tree: MerkleTree<Rescue128>,
}

impl MembershipSet {
    /// Build the set from its leaves (each a Rescue digest — see [`leaf_of`]).
    pub fn new(leaves: Vec<Hash>) -> Self {
        Self { tree: build_tree(leaves) }
    }

    /// The public set root.
    pub fn root(&self) -> Hash {
        *self.tree.root()
    }

    /// Prove membership of the leaf whose preimage is `value` at `index`, and
    /// return the proof **as opaque bytes**. Unlike a witness-carrying proof, the
    /// secret `value` and the leaf `index` are not serialized into these bytes.
    pub fn prove(&self, value: [BaseElement; 2], index: usize) -> Vec<u8> {
        prove_membership(&self.tree, value, index).to_bytes()
    }
}

/// The leaf (member commitment) for a preimage `value`: its Rescue digest.
pub fn leaf_of(value: [BaseElement; 2]) -> Hash {
    Rescue128::digest(&value)
}

/// The per-round nullifier for a secret: `Rescue(v0, v1, round)`. This is the
/// value that binding-into-the-AIR (audit-critical #1c, see
/// `docs/1c-nullifier-binding-design.md`) must reproduce in-circuit and expose as
/// a public output, so that one proof witnesses membership *and* this nullifier
/// from the same secret. Provided and tested here so the AIR has a reference to
/// match.
pub fn nullifier(secret: [BaseElement; 2], round: BaseElement) -> Hash {
    Rescue128::digest(&[secret[0], secret[1], round])
}

/// Verify an opaque membership-proof byte string against a public `root`.
pub fn verify_bytes(root: Hash, proof_bytes: &[u8]) -> bool {
    match Proof::from_bytes(proof_bytes) {
        Ok(proof) => verify_membership(root, proof).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::StarkField;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

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

    #[test]
    fn nullifier_is_deterministic_and_round_dependent() {
        let v = [BaseElement::new(11), BaseElement::new(22)];
        let r1 = BaseElement::new(1);
        let r2 = BaseElement::new(2);
        // deterministic per (secret, round)
        assert_eq!(nullifier(v, r1).to_bytes(), nullifier(v, r1).to_bytes());
        // different round → different nullifier (cross-round unlinkability)
        assert_ne!(nullifier(v, r1).to_bytes(), nullifier(v, r2).to_bytes());
        // different secret → different nullifier
        let w = [BaseElement::new(33), BaseElement::new(22)];
        assert_ne!(nullifier(v, r1).to_bytes(), nullifier(w, r1).to_bytes());
        // and it is distinct from the leaf commitment of the same secret
        assert_ne!(nullifier(v, r1).to_bytes(), leaf_of(v).to_bytes());
    }

    #[test]
    fn transmitted_proof_does_not_carry_the_secret_verbatim() {
        // The whole point vs the reference proof: the opaque proof bytes must not
        // contain the secret preimage verbatim (the reference proof serialized
        // exactly that). This is a smoke test for "witness not on the wire", not
        // a formal zero-knowledge guarantee.
        let value = [BaseElement::new(0xDEAD_BEEF_1234), BaseElement::new(0xC0FFEE_5678)];
        let index = 2;
        let mut leaves: Vec<Hash> = (100..108u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        leaves[index] = leaf_of(value);
        let set = MembershipSet::new(leaves);
        let root = set.root();

        let proof = set.prove(value, index);
        assert!(verify_bytes(root, &proof), "opaque proof must verify against the root");

        // The 32 raw bytes of the secret preimage (two f128 elements, LE).
        let secret_bytes: Vec<u8> =
            value.iter().flat_map(|e| e.as_int().to_le_bytes()).collect();
        assert!(
            !contains(&proof, &secret_bytes),
            "the secret preimage must not appear verbatim in the transmitted proof"
        );
    }
}
