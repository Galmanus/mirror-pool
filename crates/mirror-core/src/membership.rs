//! The membership relation — the statement a participant proves in zero knowledge.
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
//! The [`Prover`]/[`Verifier`] traits are the seam the STARK backend plugs into.
//! The MVP ships the relation + a [`ReferenceProver`] that carries the witness
//! (correct, but not hiding — used to drive coordination and the adversarial
//! evaluation harness end-to-end); the STARK backend replaces it with a proof
//! that is succinct and zero-knowledge while enforcing the identical relation.

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

/// The private witness — known only to the participant, never revealed by a
/// zero-knowledge proof.
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
/// enforce; the reference and STARK provers agree with it by construction.
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

/// A membership proof. The MVP's [`ReferenceProof`] is transparent (carries the
/// witness); the STARK backend's proof is an opaque, succinct byte string.
pub trait MembershipProof {
    /// Serialize the proof for on-chain submission or transport.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Produces membership proofs for a statement + witness.
pub trait Prover {
    type Proof: MembershipProof;
    fn prove(
        &self,
        statement: &MembershipStatement,
        witness: &MembershipWitness,
    ) -> Result<Self::Proof, ProveError>;
}

/// Verifies membership proofs against a statement — without the witness.
pub trait Verifier {
    type Proof: MembershipProof;
    fn verify(&self, statement: &MembershipStatement, proof: &Self::Proof) -> bool;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProveError {
    #[error("witness does not satisfy the membership relation")]
    InvalidWitness,
}

// --- Reference backend (MVP) -------------------------------------------------
//
// The reference proof simply carries the witness. It is *sound* (the verifier
// re-runs `check_relation`, so it accepts only valid witnesses) and lets the
// coordinator and the adversarial evaluation harness run the full protocol
// end-to-end today. It is explicitly **not zero-knowledge** — the witness is
// present in the proof. Swapping in the STARK backend upgrades exactly this seam
// to succinct + zero-knowledge while keeping `check_relation` as the contract.

/// A transparent, non-hiding proof: the witness itself. Placeholder for the
/// STARK proof, used to exercise the protocol end-to-end in the MVP.
#[derive(Clone, Debug)]
pub struct ReferenceProof {
    pub witness: MembershipWitness,
}

impl MembershipProof for ReferenceProof {
    fn to_bytes(&self) -> Vec<u8> {
        // Not a stable wire format — the STARK proof defines that. Enough for
        // in-process transport in tests and the eval harness.
        let mut out = Vec::with_capacity(64 + 32 * self.witness.inclusion.siblings.len());
        out.extend_from_slice(self.witness.secret.as_bytes());
        out.extend_from_slice(&self.witness.identity);
        out.extend_from_slice(&(self.witness.inclusion.index as u64).to_le_bytes());
        for s in &self.witness.inclusion.siblings {
            out.extend_from_slice(s);
        }
        out
    }
}

/// The MVP prover.
#[derive(Default)]
pub struct ReferenceProver;

impl Prover for ReferenceProver {
    type Proof = ReferenceProof;
    fn prove(
        &self,
        statement: &MembershipStatement,
        witness: &MembershipWitness,
    ) -> Result<Self::Proof, ProveError> {
        if !check_relation(statement, witness) {
            return Err(ProveError::InvalidWitness);
        }
        Ok(ReferenceProof {
            witness: witness.clone(),
        })
    }
}

/// The MVP verifier: re-checks the relation. (The STARK verifier will instead
/// check a succinct proof without ever seeing the witness.)
#[derive(Default)]
pub struct ReferenceVerifier;

impl Verifier for ReferenceVerifier {
    type Proof = ReferenceProof;
    fn verify(&self, statement: &MembershipStatement, proof: &Self::Proof) -> bool {
        check_relation(statement, &proof.witness)
    }
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
    fn reference_prover_and_verifier_round_trip() {
        let members: Vec<Member> = (0..4).map(|i| member(i as u8)).collect();
        let round = RoundId::from_bytes([7u8; 32]);
        let (st, w) = setup(&members, 2, round);
        let proof = ReferenceProver.prove(&st, &w).unwrap();
        assert!(ReferenceVerifier.verify(&st, &proof));
    }

    #[test]
    fn wrong_nullifier_breaks_relation() {
        let members: Vec<Member> = (0..4).map(|i| member(i as u8)).collect();
        let round = RoundId::from_bytes([7u8; 32]);
        let (mut st, w) = setup(&members, 1, round);
        // Claim a different member's nullifier.
        st.nullifier = nullifier(&members[3].secret, &round);
        assert!(!check_relation(&st, &w));
        assert_eq!(
            ReferenceProver.prove(&st, &w).unwrap_err(),
            ProveError::InvalidWitness
        );
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
