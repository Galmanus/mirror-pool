//! riverrun's post-quantum M31 Circle-STARK path.
//!
//! Built entirely on the official Plonky3 crates (`p3-mersenne-31`, `p3-poseidon2`,
//! `p3-poseidon2-air`, `p3-circle`, `p3-fri`, `p3-uni-stark`), published on
//! crates.io under MIT OR Apache-2.0 by the Plonky3 project. This crate does not
//! vendor or copy any third-party source: it depends on these libraries the normal
//! way, the same as any other dependency in this workspace.
//!
//! `docs/M31_CIRCLE_STARK.md` calls for a Circle STARK over Mersenne-31 whose
//! membership proof verifies in a single Solana transaction. The heavy machinery
//! (the field, the permutation, FRI, the circle-domain PCS) is already built and
//! vetted upstream; what riverrun adds is its own relation on top. `permutation`
//! is the first real step: prove and verify, end to end with a genuine
//! Circle-STARK proof, knowledge of a Poseidon2-M31 preimage. `binding` is the
//! second: prove a leaf and a nullifier share one secret (§1a + §1c).
//! `membership` is the third: prove a leaf digest sits under a public root via
//! a private authentication path (§1b). `relation` is the fourth: compose
//! `binding` and `membership` into the full relation via a shared public leaf
//! value, real, verified end to end, though as two separately-verified proofs
//! rather than one monolithic trace (see `relation`'s module doc for exactly
//! what that does and does not claim). No on-chain (SBF) verification of any
//! of this exists yet.

// Bare-wasm targets (Soroban's `wasm32v1-none`) have no standard library at
// all, so the crate root must not pull one in. Every module here already runs
// on `core` + `alloc`; `test` keeps `std` because the test harness needs it.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod binding;
pub mod keccak;
pub mod hiding;
pub mod membership;
pub mod permutation;
pub mod relation;

pub use binding::{
    prove_binding, prove_binding_tuned, prove_binding_tuned_rows, verify_binding, verify_binding_tuned,
    verify_binding_tuned_checkpointed, BindingProof, CONTEXT_LEN, LOG_NUM_QUOTIENT_CHUNKS,
    SECRET_LEN,
};
pub use membership::{compress, prove_membership, verify_membership, MembershipProof, PathStep, DEPTH, DIGEST_LEN};
pub use permutation::{prove_preimage, verify_preimage, PreimageProof, WIDTH};
pub use relation::{prove_full_relation, verify_full_relation, FullRelationProof};
