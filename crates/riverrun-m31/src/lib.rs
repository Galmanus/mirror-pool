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
//! vetted upstream; what riverrun adds is its own relation on top. This module is
//! the first real step: prove and verify, end to end with a genuine Circle-STARK
//! proof, knowledge of a Poseidon2-M31 preimage. It is deliberately not yet the
//! full Merkle-membership relation (`docs/M31_CIRCLE_STARK.md`'s next milestone);
//! it validates the whole pipeline, wired correctly, before that relation is built
//! on top of it.

pub mod permutation;

pub use permutation::{prove_preimage, verify_preimage, PreimageProof, WIDTH};
