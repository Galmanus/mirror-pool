//! Per-round nullifiers.
//!
//! To act in a round, a member reveals a nullifier
//!
//! ```text
//! n = H( NULLIFIER_TAG ‖ secret ‖ round_id )
//! ```
//!
//! Two properties matter, both from BLAKE3 being a PRF keyed by the secret:
//!
//! - **One action per member per round.** `n` is deterministic in
//!   `(secret, round_id)`, so a member who tries to act twice in the same round
//!   reveals the same `n` twice — the on-chain nullifier registry rejects the
//!   second. This is the Sybil / double-participation defense.
//! - **Unlinkable across rounds.** `n` for round `r` and `n'` for round `r'`
//!   are independent PRF outputs; an observer cannot tell they came from the
//!   same member. So participating in many rounds does not build a linkable
//!   trail — the property naive per-round schemes fail to provide.
//!
//! Crucially the nullifier is derived from the `secret` alone (not from the
//! commitment or any published value), so revealing `n` does not reveal *which*
//! commitment it corresponds to. Preserving that unlinkability against a party
//! that also sees the proof requires a formally zero-knowledge backend; the
//! shipped Winterfell STARK is succinct and post-quantum but not one (see
//! `riverrun-stark`). On-chain this is moot — only the nullifier is persisted,
//! and it is a PRF output — so the permanent record stays unlinkable regardless.

use crate::{commitment::Secret, domain, tagged_hash, Hash};

/// A round identifier. Any value both sides agree pins down "this round" — in
/// practice a hash of (set root, epoch/slot window, action parameters).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RoundId(pub [u8; 32]);

impl RoundId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A revealed nullifier — the on-chain registry stores the set of these that
/// have been spent, and rejects repeats within a round.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nullifier(pub Hash);

impl Nullifier {
    pub const fn as_bytes(&self) -> &Hash {
        &self.0
    }
}

/// Derive a member's nullifier for a given round from their secret.
pub fn nullifier(secret: &Secret, round: &RoundId) -> Nullifier {
    Nullifier(tagged_hash(
        domain::NULLIFIER,
        &[secret.as_bytes(), round.as_bytes()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes([byte; 32])
    }

    fn round(byte: u8) -> RoundId {
        RoundId::from_bytes([byte; 32])
    }

    #[test]
    fn nullifier_is_deterministic_per_member_and_round() {
        // Same member, same round → same nullifier (double-action is detectable).
        assert_eq!(
            nullifier(&secret(1), &round(5)),
            nullifier(&secret(1), &round(5))
        );
    }

    #[test]
    fn same_member_different_round_is_unlinkable() {
        // Different rounds → different nullifiers, with no visible relation.
        assert_ne!(
            nullifier(&secret(1), &round(5)),
            nullifier(&secret(1), &round(6))
        );
    }

    #[test]
    fn different_members_same_round_differ() {
        assert_ne!(
            nullifier(&secret(1), &round(5)),
            nullifier(&secret(2), &round(5))
        );
    }

    #[test]
    fn nullifier_is_domain_separated_from_commitment() {
        // A nullifier and a commitment built from the same 32-byte inputs must
        // not collide — the domain tags differ, so the digests differ.
        use crate::commitment::commit;
        let s = secret(3);
        let r = round(3);
        let n = nullifier(&s, &r);
        let c = commit(&s, r.as_bytes());
        assert_ne!(n.as_bytes(), c.as_bytes());
    }
}
