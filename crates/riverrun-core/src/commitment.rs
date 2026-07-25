//! Member commitments.
//!
//! A participant joins the anonymity set by publishing a commitment
//!
//! ```text
//! c = H( COMMITMENT_TAG ‖ secret ‖ identity )
//! ```
//!
//! where `secret` is a 32-byte value known only to the member and `identity`
//! binds the commitment to a public handle (e.g. the member's public key), so
//! two members cannot publish the same commitment without sharing a secret.
//!
//! The commitment is *hiding* (given `c`, an observer learns nothing about
//! `secret`, since BLAKE3 is a PRF under an unknown input) and *binding* (a
//! member cannot later claim a different `secret` for the same `c` without a
//! hash collision).

use crate::{domain, tagged_hash, Hash};

/// A member's private witness. Never published; used to derive the commitment
/// and, per round, the nullifier. Losing it means losing the ability to act as
/// this member; leaking it lets someone else spend this member's per-round slot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secret(pub [u8; 32]);

impl Secret {
    /// Wrap 32 raw bytes as a secret.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Mint a fresh secret from the operating system's CSPRNG (256 bits of
    /// entropy). This is the only correct way to create a member secret: the
    /// commitment and every per-round nullifier are `H(secret ‖ …)`, so all of
    /// the scheme's post-quantum hiding rests on this secret being unguessable.
    /// A 256-bit secret costs a quantum adversary ~2^128 work under Grover — the
    /// standard post-quantum security level. A low-entropy secret is breakable
    /// regardless of the hash, which is why generation must not be left to the
    /// caller.
    ///
    /// Panics only if the OS entropy source is unavailable, which on a supported
    /// platform means the process cannot safely produce secrets at all.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS CSPRNG must be available to mint a member secret");
        Self(bytes)
    }
}

// Deliberately no Debug: a secret must never end up in a log line or panic
// message. Callers that need to inspect one do so through `as_bytes`.
impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A published commitment — one leaf of the anonymity-set Merkle tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment(pub Hash);

impl Commitment {
    pub const fn as_bytes(&self) -> &Hash {
        &self.0
    }
}

/// Derive a member's commitment from their secret and public identity.
///
/// `identity` is any fixed-width public handle for the member — typically a
/// 32-byte public key. Binding the commitment to it prevents a griefer from
/// re-publishing another member's commitment as their own.
pub fn commit(secret: &Secret, identity: &[u8; 32]) -> Commitment {
    Commitment(tagged_hash(
        domain::COMMITMENT,
        &[secret.as_bytes(), identity],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes([byte; 32])
    }

    #[test]
    fn commitment_is_deterministic() {
        let s = secret(1);
        let id = [9u8; 32];
        assert_eq!(commit(&s, &id), commit(&s, &id));
    }

    #[test]
    fn different_secret_gives_different_commitment() {
        let id = [9u8; 32];
        assert_ne!(commit(&secret(1), &id), commit(&secret(2), &id));
    }

    #[test]
    fn different_identity_gives_different_commitment() {
        let s = secret(1);
        assert_ne!(commit(&s, &[9u8; 32]), commit(&s, &[10u8; 32]));
    }

    #[test]
    fn commitment_does_not_leak_secret_bytes() {
        // The digest must not equal the raw secret (sanity: hashing happened).
        let s = secret(7);
        let c = commit(&s, &[0u8; 32]);
        assert_ne!(c.as_bytes(), s.as_bytes());
    }

    #[test]
    fn random_secret_is_high_entropy_and_unique() {
        // Two freshly minted secrets must differ (a fixed/constant generator
        // would collide), and a random secret must not be a degenerate
        // all-equal-byte value like the test vectors — a weak smoke test that
        // real OS entropy actually flowed into the 32 bytes.
        let a = Secret::random();
        let b = Secret::random();
        assert_ne!(a.as_bytes(), b.as_bytes(), "two OS-random secrets collided");
        let first = a.as_bytes()[0];
        assert!(
            a.as_bytes().iter().any(|&byte| byte != first),
            "random secret is a constant-byte value; entropy did not flow"
        );
    }
}
