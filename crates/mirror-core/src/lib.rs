//! # mirror-core
//!
//! Hash-based, post-quantum anonymity-set primitives for `mirror-pool`.
//!
//! Every primitive here is built from a single collision-resistant hash
//! (BLAKE3), which is what makes the whole construction **post-quantum** (no
//! pairings, no discrete-log) and **transparent** (no trusted setup). The four
//! pieces:
//!
//! - [`commitment`] — a member joins the set by publishing `c = H(secret ‖ id)`.
//! - [`merkle`] — the anonymity set is a Merkle tree of commitments; its root
//!   identifies the set and inclusion proofs witness membership.
//! - [`nullifier`] — `n = H(secret ‖ round)` lets a member act at most once per
//!   round while staying unlinkable across rounds.
//! - [`membership`] — the zero-knowledge statement a participant proves: *"I
//!   know a `secret` whose commitment is in the set with root `R`, and my
//!   nullifier for this round is `n`"* — without revealing which leaf.
//!
//! All domain separation is explicit: each hash use is prefixed with a unique,
//! versioned tag so a value in one role can never be reinterpreted in another.

pub mod commitment;
pub mod membership;
pub mod merkle;
pub mod nullifier;
pub mod pool;

/// A 32-byte digest — the output of every hash in this crate.
pub type Hash = [u8; 32];

/// Domain-separation tags. Each distinct hash use gets its own versioned tag so
/// that, e.g., a commitment can never collide with or be reinterpreted as a
/// nullifier or a Merkle node.
pub(crate) mod domain {
    pub const COMMITMENT: &[u8] = b"mirror-pool/commitment/v1";
    pub const NULLIFIER: &[u8] = b"mirror-pool/nullifier/v1";
    pub const MERKLE_LEAF: &[u8] = b"mirror-pool/merkle-leaf/v1";
    pub const MERKLE_NODE: &[u8] = b"mirror-pool/merkle-node/v1";
}

/// Domain-separated hash of a sequence of byte slices.
///
/// The `tag` is absorbed first, then each part in order, so the result is
/// unambiguous with respect to both the role (`tag`) and the field boundaries
/// (the parts are absorbed as-is; callers pass fixed-width fields, so there is
/// no length-extension ambiguity between them).
pub(crate) fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
