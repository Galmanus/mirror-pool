//! riverrun act: one secret, bound to the pool action.
//!
//! The unified derivation behind the `act()` flow (see
//! `docs/RIVERRUN_ACT_DESIGN.md`). From one [`Secret`], one `context`, one
//! `action`, and one `round`, derive the three things a member needs to act
//! unlinkably, all tied to the same secret:
//!
//! - the **identity** you present in this context (unlinkable to any other),
//! - the **commitment** (Merkle leaf) you publish to join the round, binding the
//!   secret to this exact context and action,
//! - the **nullifier** that spends your single action this round.
//!
//! This does not invent a parallel scheme. It composes the existing
//! [`commit`](crate::commitment::commit) and [`nullifier`](crate::nullifier::nullifier)
//! so the leaf and the nullifier are exactly the ones the membership relation and
//! the STARK prove; it only pins how `context` and `action` enter them. Everything
//! is domain-separated by context, so acting in one venue is unlinkable to another,
//! and a leak in one context does not cascade to the rest.

use crate::commitment::{commit, Commitment, Secret};
use crate::nullifier::{nullifier as core_nullifier, Nullifier, RoundId};
use crate::{tagged_hash, Hash};

// Domain-separated so a context+action handle can never be reinterpreted as a
// context+round handle, an identity, a commitment, or a nullifier.
const ACT_IDENTITY: &[u8] = b"riverrun/act-identity/v1";
const ACT_COMMIT: &[u8] = b"riverrun/act-commit/v1";
const ACT_NULL: &[u8] = b"riverrun/act-null/v1";

/// Everything a member needs to act unlinkably in one context and round, all
/// derived from a single secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ActBinding {
    /// The identity you present in this context. An independent PRF output per
    /// context, so it is unlinkable to your identity anywhere else.
    pub identity: Hash,
    /// The commitment (Merkle leaf) you publish to join the round. Binds the
    /// secret to this exact context and action, so you execute the intent you
    /// committed, not any intent.
    pub commitment: Commitment,
    /// The nullifier that spends your one action this round. Binds the secret to
    /// this context and round; revealed once, so no second action in the round.
    pub nullifier: Nullifier,
}

/// The per-context identity handle: who you are in `context`, unlinkable to who
/// you are anywhere else.
pub fn identity(secret: &Secret, context: &[u8]) -> Hash {
    tagged_hash(ACT_IDENTITY, &[secret.as_bytes(), context])
}

/// The commitment (Merkle leaf) you publish to join a round in `context` for
/// `action`. Depends on the secret, context, and action, but not the round, so
/// it can be computed and published *before* the round forms. It is the same leaf
/// the membership relation and the STARK prove; this only pins how context and
/// action enter it.
pub fn commitment(secret: &Secret, context: &[u8], action: &[u8]) -> Commitment {
    let handle = tagged_hash(ACT_COMMIT, &[context, action]);
    commit(secret, &handle)
}

/// The nullifier that spends your one action in `context` at `round`. Known only
/// once the round is fixed, so anti-replay is exactly per (secret, context,
/// round). Folded into the existing nullifier scheme.
pub fn nullifier(secret: &Secret, context: &[u8], round: &[u8]) -> Nullifier {
    let handle = tagged_hash(ACT_NULL, &[context, round]);
    core_nullifier(secret, &RoundId::from_bytes(handle))
}

/// Derive the full binding for `secret` acting with `action` in `context` at
/// `round`. All three fields come from the one secret.
pub fn bind(secret: &Secret, context: &[u8], action: &[u8], round: &[u8]) -> ActBinding {
    ActBinding {
        identity: identity(secret, context),
        commitment: commitment(secret, context, action),
        nullifier: nullifier(secret, context, round),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: u8) -> Secret {
        Secret::from_bytes([b; 32])
    }

    #[test]
    fn binding_is_deterministic() {
        let a = bind(&s(1), b"dao-vote", b"yes", b"round-7");
        let b = bind(&s(1), b"dao-vote", b"yes", b"round-7");
        assert_eq!(a, b, "same inputs must give the same binding");
    }

    #[test]
    fn contexts_are_unlinkable() {
        // The whole point: one secret, a different everything per context.
        let a = bind(&s(1), b"dao-vote", b"yes", b"round-7");
        let b = bind(&s(1), b"airdrop", b"yes", b"round-7");
        assert_ne!(a.identity, b.identity, "identity must differ across contexts");
        assert_ne!(a.commitment, b.commitment, "commitment must differ across contexts");
        assert_ne!(a.nullifier, b.nullifier, "nullifier must differ across contexts");
    }

    #[test]
    fn the_action_binds_the_commitment_and_not_the_rest() {
        // A different action is a different leaf, but your identity and your
        // one-per-round nullifier are stable, so you still act at most once.
        let a = bind(&s(1), b"amm", b"buy", b"round-7");
        let b = bind(&s(1), b"amm", b"sell", b"round-7");
        assert_ne!(a.commitment, b.commitment, "a different action is a different leaf");
        assert_eq!(a.identity, b.identity, "identity is per-context, not per-action");
        assert_eq!(a.nullifier, b.nullifier, "one nullifier per round holds across actions");
    }

    #[test]
    fn the_round_binds_the_nullifier_and_not_the_rest() {
        let a = bind(&s(1), b"amm", b"buy", b"round-7");
        let b = bind(&s(1), b"amm", b"buy", b"round-8");
        assert_ne!(a.nullifier, b.nullifier, "a new round is a fresh nullifier");
        assert_eq!(a.commitment, b.commitment, "the commitment does not depend on the round");
        assert_eq!(a.identity, b.identity, "nor does the identity");
    }

    #[test]
    fn the_secret_binds_all_three() {
        let a = bind(&s(1), b"amm", b"buy", b"round-7");
        let b = bind(&s(2), b"amm", b"buy", b"round-7");
        assert_ne!(a.identity, b.identity);
        assert_ne!(a.commitment, b.commitment);
        assert_ne!(a.nullifier, b.nullifier);
    }

    #[test]
    fn bind_composes_the_existing_commitment_and_nullifier() {
        // The leaf and nullifier are exactly the ones the membership relation and
        // the STARK prove, so act() does not run a parallel scheme beside them.
        let sec = s(9);
        let b = bind(&sec, b"amm", b"buy", b"round-7");
        let commit_handle = tagged_hash(ACT_COMMIT, &[b"amm", b"buy"]);
        let null_handle = tagged_hash(ACT_NULL, &[b"amm", b"round-7"]);
        assert_eq!(b.commitment, commit(&sec, &commit_handle));
        assert_eq!(b.nullifier, core_nullifier(&sec, &RoundId::from_bytes(null_handle)));
    }
}
