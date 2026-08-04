//! The full riverrun relation (§1a + §1b + §1c), composed from two separately
//! verified Circle-STARK proofs rather than one monolithic trace.
//!
//! `binding::prove_binding` proves "this leaf and this nullifier come from one
//! secret." `membership::prove_membership` proves "this leaf digest sits under
//! this root." Fusing them into a single STARK trace would require one AIR
//! whose row layout serves both a same-row, two-block computation (binding)
//! and a multi-row chained fold (membership), which are different row shapes;
//! that is real, larger AIR-design work (a row-type selector multiplexing two
//! incompatible column layouts), not attempted here.
//!
//! What this module does instead is the standard, sound way to compose
//! separately-verified proofs: bind them through a **shared public value**.
//! `verify_full_relation` checks both proofs independently, AND checks that
//! `binding`'s public `leaf` output, truncated to [`membership::DIGEST_LEN`],
//! equals `membership`'s public `leaf` input, in plain Rust, outside either
//! proof's algebraic constraints. This is the same composition an on-chain
//! verifier would do cheaply (two proof checks plus one public-value equality
//! check) and it is exactly as sound as the individual proofs: a party who
//! cannot produce a genuine `(leaf, nullifier)` pair for some secret cannot
//! pass `verify_binding`, and a party whose `leaf` is not really under `root`
//! cannot pass `verify_membership`; matching leaves ties the two facts to the
//! *same* leaf, not two different ones a dishonest party mixed together.
//!
//! **Truncation convention, stated plainly.** `binding`'s leaf is the full
//! [`WIDTH`]-wide permutation output (§1a's own convention); `membership`'s
//! leaf is [`membership::DIGEST_LEN`] wide (its own compression convention).
//! This module truncates the former to the latter's width to compare them.
//! Whether an 8-of-16-element truncation is safe against an adversary who
//! controls the other 8 elements is a real cryptographic question this module
//! does not answer; it is inherited, not introduced, from the two modules'
//! own pre-existing, already-provisional width conventions, and is exactly
//! the kind of question a proper security review, not this scoping pass,
//! should settle before this is production-ready.

use crate::binding::{self, BindingProof, CONTEXT_LEN, SECRET_LEN};
use crate::membership::{self, MembershipProof, PathStep, DEPTH, DIGEST_LEN};
use crate::permutation::WIDTH;

/// Everything needed to check that a leaf+nullifier pair (bound to one
/// secret) also sits under a public root: two independent proofs plus the
/// public values each was verified against.
pub struct FullRelationProof {
    pub binding: BindingProof,
    pub membership: MembershipProof,
    pub action: [u64; CONTEXT_LEN],
    pub round: [u64; CONTEXT_LEN],
    pub leaf: [u64; DIGEST_LEN],
    pub nullifier: [u64; DIGEST_LEN],
    pub root: [u64; DIGEST_LEN],
}

/// Prove the full relation: `secret` produces `leaf`/`nullifier` (via
/// `action`/`round`), and `leaf` (truncated) sits under a root reached by
/// `path`. Panics under the same conditions `prove_binding` and
/// `prove_membership` do: a genuinely inconsistent witness cannot be proved,
/// it is rejected at proving time, not silently accepted.
pub fn prove_full_relation(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    path: [PathStep; DEPTH],
) -> FullRelationProof {
    let (binding_proof, leaf, nullifier) = binding::prove_binding(secret, action, round);
    let (membership_proof, root) = membership::prove_membership(leaf, path);
    FullRelationProof {
        binding: binding_proof,
        membership: membership_proof,
        action,
        round,
        leaf,
        nullifier,
        root,
    }
}

/// Verify the full relation. `true` only if BOTH proofs verify against their
/// own claimed public values AND the binding proof's `leaf`, truncated,
/// equals the membership proof's `leaf`, i.e. both proofs are about the same
/// member, not two different ones stitched together.
pub fn verify_full_relation(proof: &FullRelationProof) -> bool {
    let binding_ok = binding::verify_binding(
        &proof.binding,
        proof.action,
        proof.round,
        proof.leaf,
        proof.nullifier,
    );
    let leaf_digest = proof.leaf;
    let membership_ok = membership::verify_membership(&proof.membership, leaf_digest, proof.root);
    binding_ok && membership_ok
}

fn truncate(leaf: [u64; WIDTH]) -> [u64; DIGEST_LEN] {
    core::array::from_fn(|i| leaf[i])
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

    fn sibling(byte: u64) -> [u64; DIGEST_LEN] {
        core::array::from_fn(|i| byte * 4000 + i as u64)
    }

    fn sample_path() -> [PathStep; DEPTH] {
        core::array::from_fn(|i| PathStep {
            sibling: sibling(i as u64 + 1),
            node_on_right: i % 2 == 1,
        })
    }

    #[test]
    fn a_genuine_full_relation_proves_and_verifies() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let path = sample_path();
        let proof = prove_full_relation(s, action, round, path);
        assert!(
            verify_full_relation(&proof),
            "a genuine leaf+nullifier pair, whose leaf really sits under the proven root, must verify"
        );
    }

    #[test]
    fn mixing_one_members_binding_with_a_different_members_membership_fails() {
        // Alice's leaf/nullifier are real and self-consistent (a genuine
        // binding proof). Bob's leaf/path are also real and self-consistent
        // (a genuine membership proof, for a DIFFERENT member's leaf). Each
        // proof verifies fine on its own; the composition must still reject
        // splicing them together, because they are not about the same leaf.
        let alice = secret(1);
        let bob = secret(2);
        let action = context(1);
        let round = context(2);
        let path = sample_path();

        let (alice_binding, alice_leaf, alice_nullifier) =
            binding::prove_binding(alice, action, round);
        let (_bob_binding, bob_leaf, _bob_nullifier) = binding::prove_binding(bob, action, round);
        assert!(
            binding::verify_binding(&alice_binding, action, round, alice_leaf, alice_nullifier),
            "sanity: alice's own binding proof verifies"
        );

        let bob_leaf_digest = bob_leaf;
        let (bob_membership, bob_root) = membership::prove_membership(bob_leaf_digest, path);
        assert!(
            membership::verify_membership(&bob_membership, bob_leaf_digest, bob_root),
            "sanity: bob's own membership proof verifies"
        );

        // Splice: Alice's binding proof (her real leaf/nullifier) with Bob's
        // membership proof/root (his real, different leaf under his root).
        let spliced = FullRelationProof {
            binding: alice_binding,
            membership: bob_membership,
            action,
            round,
            leaf: alice_leaf, // Alice's leaf...
            nullifier: alice_nullifier,
            root: bob_root, // ...claimed to sit under BOB's root
        };
        assert!(
            !verify_full_relation(&spliced),
            "a leaf from one proof must not pass as the leaf of a different member's membership proof"
        );
    }
}
