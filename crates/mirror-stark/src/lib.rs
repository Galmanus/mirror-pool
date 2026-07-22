//! # mirror-stark (research / paper track)
//!
//! Placeholder for the **post-quantum, transparent STARK** proof of anonymous
//! set membership that upgrades `mirror-pool`'s membership seam from a
//! transparent *reference* proof (which carries the witness) to a *succinct
//! zero-knowledge* one.
//!
//! The statement to prove is already specified and unit-tested in
//! [`mirror_core::membership::check_relation`]:
//!
//! > *"I know a `secret` and an `action` such that `commit(secret, action)` is a
//! > leaf under the public set root `R`, and my nullifier for this round is
//! > `n = nullifier(secret, round)`"* — revealing only `(R, round, n, action)`.
//!
//! The intended construction is a FRI-STARK over a hash-friendly field
//! (Rescue-Prime Merkle-path AIR, via Winterfell): hash-based, so post-quantum;
//! transparent, so no trusted setup or ceremony. This crate is deliberately
//! empty and excluded from the default workspace until that AIR is implemented,
//! so the repository builds fast and green.
//!
//! See the roadmap in the top-level `README.md`.
