//! # riverrun-core
//!
//! Hash-based, post-quantum anonymity-set primitives for `riverrun`.
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
//! - [`membership`] — the statement a participant must prove without revealing
//!   the witness: *"I know a `secret` whose commitment is in the set with root
//!   `R`, and my nullifier for this round is `n`"* — without revealing which
//!   leaf. (The relation only; whether the *backend* proof hides the witness
//!   formally is a property of that backend — see `riverrun-stark`, which is
//!   succinct and post-quantum but not formally zero-knowledge.)
//!
//! This crate is the **specification**, not the protocol: it defines the
//! primitives and the relation, and nothing here produces a proof. The pool that
//! actually runs commit → execute → settle lives in `riverrun-pool-zk`, driven by
//! the post-quantum STARK in `riverrun-stark`. There used to be a second pool
//! here backed by a "reference proof" that carried the witness in the clear; it
//! was useful to exercise the protocol before the STARK existed, and it is gone
//! now that the STARK does the job — shipping a non-hiding pool next to a hiding
//! one in a privacy repo is a footgun regardless of how loudly the README says
//! which is which.
//!
//! All domain separation is explicit: each hash use is prefixed with a unique,
//! versioned tag so a value in one role can never be reinterpreted in another.

pub mod commitment;
pub mod membership;
pub mod merkle;
pub mod nullifier;
pub mod rln;
pub mod rotatable;

/// A 32-byte digest — the output of every hash in this crate.
pub type Hash = [u8; 32];

/// Domain-separation tags. Each distinct hash use gets its own versioned tag so
/// that, e.g., a commitment can never collide with or be reinterpreted as a
/// nullifier or a Merkle node.
pub(crate) mod domain {
    pub const COMMITMENT: &[u8] = b"riverrun/commitment/v1";
    pub const NULLIFIER: &[u8] = b"riverrun/nullifier/v1";
    pub const MERKLE_LEAF: &[u8] = b"riverrun/merkle-leaf/v1";
    pub const MERKLE_NODE: &[u8] = b"riverrun/merkle-node/v1";
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
