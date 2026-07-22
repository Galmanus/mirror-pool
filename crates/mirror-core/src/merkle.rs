//! The anonymity set as a binary Merkle tree.
//!
//! Members' commitments are the leaves; the root identifies the set. An
//! inclusion proof witnesses "this commitment is a member" in `O(log n)` hashes.
//! The membership *proof* (see [`crate::membership`]) proves knowledge of such a
//! witness in zero knowledge, so the acting party never reveals which leaf.
//!
//! Hashing is domain-separated at both levels:
//!
//! ```text
//! leaf(c)        = H( MERKLE_LEAF_TAG ‖ c )
//! node(l, r)     = H( MERKLE_NODE_TAG ‖ l ‖ r )
//! ```
//!
//! Separating leaf and node hashing defends against second-preimage attacks
//! that would otherwise let an internal node be presented as a leaf.
//!
//! The tree is padded up to a power-of-two width with a fixed, publicly-known
//! empty-leaf value, so proof shape (depth) is uniform and does not leak the
//! exact member count beyond the padded width.

use crate::{commitment::Commitment, domain, tagged_hash, Hash};

/// The value used to pad the leaf layer up to a power of two. Public and fixed,
/// so it can never be mistaken for a real member commitment (a real commitment
/// would require a preimage under the commitment domain tag, which this is not).
pub const EMPTY_LEAF: Hash = [0u8; 32];

/// Errors from building or querying the tree.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MerkleError {
    #[error("cannot build a Merkle tree from an empty member set")]
    Empty,
    #[error("leaf index {index} out of range for a tree of {len} members")]
    IndexOutOfRange { index: usize, len: usize },
}

/// A witness that a particular leaf sits under a particular root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InclusionProof {
    /// The leaf's index in the (unpadded) member ordering.
    pub index: usize,
    /// Sibling hashes from the leaf level up to (but excluding) the root, one
    /// per level.
    pub siblings: Vec<Hash>,
}

/// A built anonymity set: the leaf layer plus the cached root.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Padded leaf layer (power-of-two length), each already leaf-hashed.
    leaves: Vec<Hash>,
    /// Number of real members (before padding).
    len: usize,
    root: Hash,
}

/// Hash a commitment into its leaf-layer digest.
fn hash_leaf(commitment: &Commitment) -> Hash {
    tagged_hash(domain::MERKLE_LEAF, &[commitment.as_bytes()])
}

/// Combine two child digests into their parent digest.
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    tagged_hash(domain::MERKLE_NODE, &[left, right])
}

impl MerkleTree {
    /// Build the tree from an ordered list of member commitments.
    ///
    /// The order defines each member's index; it must be stable between the
    /// prover (who builds an inclusion proof) and anyone who published the root.
    pub fn build(members: &[Commitment]) -> Result<Self, MerkleError> {
        if members.is_empty() {
            return Err(MerkleError::Empty);
        }
        let len = members.len();

        let mut leaves: Vec<Hash> = members.iter().map(hash_leaf).collect();
        let width = len.next_power_of_two();
        leaves.resize(width, EMPTY_LEAF);

        let root = Self::compute_root(&leaves);
        Ok(Self { leaves, len, root })
    }

    /// Fold a full (power-of-two) leaf layer up to the root.
    fn compute_root(leaves: &[Hash]) -> Hash {
        debug_assert!(leaves.len().is_power_of_two());
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = level
                .chunks_exact(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
        }
        level[0]
    }

    /// The set root — the public identifier of this anonymity set.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Number of real members (excluding padding).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the set has no real members (never true for a built tree, which
    /// rejects the empty case, but provided for lint-friendliness).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Produce an inclusion proof for the member at `index`.
    pub fn prove(&self, index: usize) -> Result<InclusionProof, MerkleError> {
        if index >= self.len {
            return Err(MerkleError::IndexOutOfRange {
                index,
                len: self.len,
            });
        }
        let mut siblings = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = index;
        while level.len() > 1 {
            let sibling = if idx % 2 == 0 {
                level[idx + 1]
            } else {
                level[idx - 1]
            };
            siblings.push(sibling);
            level = level
                .chunks_exact(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
            idx /= 2;
        }
        Ok(InclusionProof { index, siblings })
    }
}

/// Verify an inclusion proof: recompute the root from `commitment` and the
/// proof's sibling path, and check it matches `root`.
///
/// This is the cheap, standard membership check. It reveals `commitment` (and
/// hence which leaf), so it is used inside the zero-knowledge circuit — never
/// on its own when unlinkability is required.
pub fn verify(root: &Hash, commitment: &Commitment, proof: &InclusionProof) -> bool {
    let mut acc = hash_leaf(commitment);
    let mut idx = proof.index;
    for sibling in &proof.siblings {
        acc = if idx % 2 == 0 {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        idx /= 2;
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{commit, Secret};

    fn member(byte: u8) -> Commitment {
        commit(&Secret::from_bytes([byte; 32]), &[byte; 32])
    }

    fn members(n: usize) -> Vec<Commitment> {
        (0..n).map(|i| member(i as u8)).collect()
    }

    #[test]
    fn empty_set_is_rejected() {
        assert_eq!(MerkleTree::build(&[]).unwrap_err(), MerkleError::Empty);
    }

    #[test]
    fn every_member_has_a_valid_proof() {
        let ms = members(5); // non-power-of-two exercises padding
        let tree = MerkleTree::build(&ms).unwrap();
        let root = tree.root();
        for (i, m) in ms.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(verify(&root, m, &proof), "member {i} should verify");
        }
    }

    #[test]
    fn proof_for_wrong_commitment_fails() {
        let ms = members(4);
        let tree = MerkleTree::build(&ms).unwrap();
        let proof = tree.prove(0).unwrap();
        // A non-member commitment with member 0's path must not verify.
        assert!(!verify(&tree.root(), &member(200), &proof));
    }

    #[test]
    fn tampered_sibling_fails() {
        let ms = members(4);
        let tree = MerkleTree::build(&ms).unwrap();
        let mut proof = tree.prove(2).unwrap();
        proof.siblings[0][0] ^= 0x01;
        assert!(!verify(&tree.root(), &ms[2], &proof));
    }

    #[test]
    fn wrong_index_in_proof_fails() {
        let ms = members(4);
        let tree = MerkleTree::build(&ms).unwrap();
        let mut proof = tree.prove(1).unwrap();
        proof.index = 3; // path no longer matches the claimed position
        assert!(!verify(&tree.root(), &ms[1], &proof));
    }

    #[test]
    fn out_of_range_index_is_rejected() {
        let tree = MerkleTree::build(&members(3)).unwrap();
        assert_eq!(
            tree.prove(3).unwrap_err(),
            MerkleError::IndexOutOfRange { index: 3, len: 3 }
        );
    }

    #[test]
    fn single_member_tree_works() {
        let ms = members(1);
        let tree = MerkleTree::build(&ms).unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(verify(&tree.root(), &ms[0], &proof));
    }
}
