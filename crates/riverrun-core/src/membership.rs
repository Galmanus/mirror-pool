//! The membership relation — the statement a participant must prove without
//! revealing the witness. (Whether the backend proof hides the witness *formally*
//! is a property of that backend; `riverrun-stark` is succinct and post-quantum
//! but not formally zero-knowledge.)
//!
//! To act in a round, a participant proves:
//!
//! > *"I know a `secret` and `identity` such that (1) `c = commit(secret,
//! > identity)` is a leaf under the public set root `R`, and (2) my nullifier
//! > for this round is `n = nullifier(secret, round_id)`"*
//!
//! revealing only the **public** triple `(R, round_id, n)` — never `secret`,
//! `identity`, `c`, or the leaf index. That hiding is what unlinks the acting
//! key from the member: the observer learns a valid member acted and sees the
//! nullifier `n`, but cannot map `n` back to a commitment.
//!
//! This module defines the *relation* — the exact set of constraints a valid
//! witness must satisfy. [`check_relation`] evaluates it in the clear. It is
//! **not** zero-knowledge on its own (it takes the witness as input); it is the
//! specification of the arithmetic circuit that the post-quantum STARK backend
//! proves. Building the relation as pure, side-effect-free hash constraints is
//! deliberate: it is exactly the shape a FRI-STARK over a hash-friendly field
//! arithmetizes, so the transparent, post-quantum prover proves *this* and
//! nothing more.
//!
//! Nothing here proves anything. The proof that enforces this relation without
//! revealing the witness is the STARK in `riverrun-stark`, whose AIR binds the
//! same two constraints (nullifier from the proving secret, membership under the
//! public root) plus the committed action, with public inputs
//! `{root, nullifier, round, action}`.

use crate::{
    commitment::{commit, Commitment, Secret},
    merkle::{verify as merkle_verify, InclusionProof},
    nullifier::{nullifier, Nullifier, RoundId},
    Hash,
};

/// The public inputs to the membership proof — everything the on-chain program
/// and any observer sees.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipStatement {
    /// The anonymity-set root this proof is against.
    pub root: Hash,
    /// The round being acted in.
    pub round_id: RoundId,
    /// The nullifier the participant reveals (spent exactly once per round).
    pub nullifier: Nullifier,
}

/// The private witness — known only to the participant, never transmitted by the
/// membership proof (succinct and post-quantum; not formally zero-knowledge —
/// see `riverrun-stark`).
#[derive(Clone, Debug)]
pub struct MembershipWitness {
    pub secret: Secret,
    pub identity: [u8; 32],
    pub inclusion: InclusionProof,
}

/// Evaluate the membership relation in the clear.
///
/// Returns `true` iff the witness satisfies every constraint the statement
/// asserts. This is the single source of truth for what the STARK circuit must
/// enforce. It takes the witness as input, so it is emphatically **not** a
/// proof system — it is the relation the prover has to satisfy.
///
/// Constraints:
/// 1. **Nullifier binding:** `nullifier(secret, round_id) == statement.nullifier`.
///    Ties the revealed nullifier to the same secret proving membership, so a
///    participant cannot present someone else's membership with their own
///    nullifier (or vice versa).
/// 2. **Membership:** `commit(secret, identity)` verifies under `statement.root`
///    via the inclusion path. Proves the committed member is in the set.
pub fn check_relation(statement: &MembershipStatement, witness: &MembershipWitness) -> bool {
    let expected_nullifier = nullifier(&witness.secret, &statement.round_id);
    if expected_nullifier != statement.nullifier {
        return false;
    }
    let commitment: Commitment = commit(&witness.secret, &witness.identity);
    merkle_verify(&statement.root, &commitment, &witness.inclusion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    struct Member {
        secret: Secret,
        identity: [u8; 32],
        commitment: Commitment,
    }

    fn member(byte: u8) -> Member {
        let secret = Secret::from_bytes([byte; 32]);
        let identity = [byte.wrapping_add(100); 32];
        let commitment = commit(&secret, &identity);
        Member {
            secret,
            identity,
            commitment,
        }
    }

    /// Build a set, then a valid statement+witness for member `idx` in `round`.
    fn setup(
        members: &[Member],
        idx: usize,
        round: RoundId,
    ) -> (MembershipStatement, MembershipWitness) {
        let commitments: Vec<Commitment> = members.iter().map(|m| m.commitment).collect();
        let tree = MerkleTree::build(&commitments).unwrap();
        let m = &members[idx];
        let statement = MembershipStatement {
            root: tree.root(),
            round_id: round,
            nullifier: nullifier(&m.secret, &round),
        };
        let witness = MembershipWitness {
            secret: m.secret,
            identity: m.identity,
            inclusion: tree.prove(idx).unwrap(),
        };
        (statement, witness)
    }

    #[test]
    fn valid_witness_satisfies_relation() {
        let members: Vec<Member> = (0..6).map(|i| member(i as u8)).collect();
        let round = RoundId::from_bytes([42u8; 32]);
        for idx in 0..members.len() {
            let (st, w) = setup(&members, idx, round);
            assert!(check_relation(&st, &w), "member {idx} must satisfy");
        }
    }

    #[test]
    fn wrong_nullifier_breaks_relation() {
        let members: Vec<Member> = (0..4).map(|i| member(i as u8)).collect();
        let round = RoundId::from_bytes([7u8; 32]);
        let (mut st, w) = setup(&members, 1, round);
        // Claim a different member's nullifier.
        st.nullifier = nullifier(&members[3].secret, &round);
        assert!(!check_relation(&st, &w));
    }

    #[test]
    fn non_member_secret_breaks_relation() {
        let members: Vec<Member> = (0..4).map(|i| member(i as u8)).collect();
        let round = RoundId::from_bytes([7u8; 32]);
        let (st, mut w) = setup(&members, 0, round);
        // A secret not in the set, with a matching nullifier — still no valid path.
        let outsider = member(250);
        w.secret = outsider.secret;
        w.identity = outsider.identity;
        // Recompute the nullifier so constraint 1 passes; constraint 2 must fail.
        let st2 = MembershipStatement {
            nullifier: nullifier(&outsider.secret, &round),
            ..st
        };
        assert!(!check_relation(&st2, &w));
    }

    #[test]
    fn nullifier_across_rounds_is_unlinkable_but_provable() {
        let members: Vec<Member> = (0..4).map(|i| member(i as u8)).collect();
        let (st_a, w_a) = setup(&members, 2, RoundId::from_bytes([1u8; 32]));
        let (st_b, w_b) = setup(&members, 2, RoundId::from_bytes([2u8; 32]));
        // Same member proves membership in both rounds...
        assert!(check_relation(&st_a, &w_a));
        assert!(check_relation(&st_b, &w_b));
        // ...but the two nullifiers reveal no link.
        assert_ne!(st_a.nullifier, st_b.nullifier);
    }
}
