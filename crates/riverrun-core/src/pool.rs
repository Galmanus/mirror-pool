//! The behavioral pool — **Tornado Cash for actions, not funds.**
//!
//! Tornado breaks the link between a *deposit* and a *withdrawal* of funds.
//! `riverrun` breaks the link between a **committed intent** and an
//! **executed action** — a swap, a claim, a vote, a withdrawal from some
//! protocol. Amounts are neither hidden nor the point; what is severed is the
//! **actor ↔ action** link.
//!
//! The flow, mirroring Tornado but with a behavior as the payload:
//!
//! 1. **Commit** (the "deposit"). A participant publishes
//!    `C = H(secret ‖ action)` into the pool's Merkle set. This registers "some
//!    member of this set intends action `A`" without revealing who.
//! 2. **Execute** (the "withdrawal"/`saque`). Later — ideally in a synchronized
//!    round of identical actions — the action `A` is performed from a fresh
//!    identity, accompanied by a zero-knowledge proof that *"I know a `secret`
//!    whose commitment `H(secret ‖ A)` is in the set, and my nullifier for this
//!    round is `n`"*. The action `A` is public (the observer sees it happened);
//!    the committer is not.
//! 3. **Settle.** The pool verifies the proof, checks the nullifier is fresh
//!    (one execution per member per round — the anti-replay), spends it, and
//!    releases the action. The public transcript is `{root, action, nullifier}`
//!    with no link back to a commitment.
//!
//! The cryptographic core is exactly [`crate::commitment`], [`crate::merkle`],
//! [`crate::nullifier`], and [`crate::membership`] — this module is the stateful
//! commit→execute→settle machine on top of them. The membership proof here uses
//! the transparent reference backend (it carries the witness); the post-quantum
//! STARK backend upgrades that seam to succinct zero-knowledge while proving the
//! identical relation, so `action` becomes a public input and `secret` stays
//! private.

use std::collections::HashSet;

use crate::commitment::{commit, Commitment, Secret};
use crate::membership::{
    MembershipStatement, MembershipWitness, Prover, ReferenceProof, ReferenceProver,
    ReferenceVerifier, Verifier,
};
use crate::merkle::MerkleTree;
use crate::nullifier::{nullifier, RoundId};
use crate::Hash;

/// A public description of an action, as a 32-byte hash (e.g. the hash of "swap
/// 1 SOL→USDC on venue V" or "withdraw from protocol P"). The action is public;
/// its author is what the pool hides.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ActionSpec(pub [u8; 32]);

impl ActionSpec {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A proof that some committed member is executing `action` this round —
/// unlinkable to which member. `statement` and `action` are public; the proof
/// witnesses membership without revealing the leaf.
#[derive(Clone, Debug)]
pub struct Execution {
    pub action: ActionSpec,
    pub statement: MembershipStatement,
    pub proof: ReferenceProof,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    #[error("the pool has no members to build a set from")]
    EmptyPool,
    #[error("no valid witness for this (secret, action, leaf): not a committed member")]
    NotAMember,
    #[error("the executed action is not the one bound by the proof")]
    ActionMismatch,
    #[error("membership proof did not verify against the pool root")]
    BadProof,
    #[error("nullifier already spent this round (double execution)")]
    NullifierSpent,
    #[error("proof is against a stale root; rebuild against the current pool")]
    StaleRoot,
}

/// The behavioral anonymity pool: a growing set of action-commitments and the
/// registry of nullifiers already spent.
#[derive(Default)]
pub struct BehaviorPool {
    members: Vec<Commitment>,
    spent: HashSet<Hash>,
}

impl BehaviorPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// **Commit** to an intended action. Returns the leaf index the committer
    /// keeps privately to later build their execution proof.
    pub fn commit(&mut self, secret: &Secret, action: &ActionSpec) -> usize {
        let c = commit(secret, action.as_bytes());
        self.members.push(c);
        self.members.len() - 1
    }

    /// Number of committed members (the anonymity-set size).
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The current set root. `None` until at least one member has committed.
    pub fn root(&self) -> Option<Hash> {
        MerkleTree::build(&self.members).ok().map(|t| t.root())
    }

    /// **Execute** (the withdrawal). Produce a proof that the member at
    /// `leaf_idx` — who committed `action` under `secret` — is performing that
    /// action in `round`, without revealing which leaf. Fails if the
    /// `(secret, action, leaf_idx)` triple is not a genuine committed member.
    pub fn prove_execution(
        &self,
        secret: &Secret,
        action: &ActionSpec,
        leaf_idx: usize,
        round: RoundId,
    ) -> Result<Execution, PoolError> {
        let tree = MerkleTree::build(&self.members).map_err(|_| PoolError::EmptyPool)?;
        let inclusion = tree.prove(leaf_idx).map_err(|_| PoolError::NotAMember)?;
        let statement = MembershipStatement {
            root: tree.root(),
            round_id: round,
            nullifier: nullifier(secret, &round),
        };
        let witness = MembershipWitness {
            secret: *secret,
            identity: *action.as_bytes(),
            inclusion,
        };
        let proof = ReferenceProver
            .prove(&statement, &witness)
            .map_err(|_| PoolError::NotAMember)?;
        Ok(Execution {
            action: *action,
            statement,
            proof,
        })
    }

    /// **Settle** an execution: verify the proof binds the claimed action against
    /// the current root, check the nullifier is fresh, spend it, and release the
    /// action — severed from its author. Idempotent-safe: a replayed nullifier is
    /// rejected and never re-recorded.
    pub fn settle(&mut self, exec: &Execution) -> Result<ActionSpec, PoolError> {
        // The current root must match the one the proof was made against.
        let current = self.root().ok_or(PoolError::EmptyPool)?;
        if current != exec.statement.root {
            return Err(PoolError::StaleRoot);
        }
        // The public action must be the one the proof binds (in ZK this is a
        // public input; here the reference proof carries it as the binder).
        if exec.proof.witness.identity != *exec.action.as_bytes() {
            return Err(PoolError::ActionMismatch);
        }
        if !ReferenceVerifier.verify(&exec.statement, &exec.proof) {
            return Err(PoolError::BadProof);
        }
        let n = *exec.statement.nullifier.as_bytes();
        if self.spent.contains(&n) {
            return Err(PoolError::NullifierSpent);
        }
        self.spent.insert(n);
        Ok(exec.action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> Secret {
        Secret::from_bytes([b; 32])
    }

    fn action(b: u8) -> ActionSpec {
        ActionSpec([b; 32])
    }

    fn round(b: u8) -> RoundId {
        RoundId::from_bytes([b; 32])
    }

    #[test]
    fn commit_execute_settle_round_trip() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        let exec = pool.prove_execution(&sa, &act, idx, round(9)).unwrap();
        assert_eq!(pool.settle(&exec).unwrap(), act);
    }

    #[test]
    fn two_members_same_action_are_exchangeable() {
        // The core unlinkability property: two members commit the *identical*
        // action; both execute in the same round. The public transcript differs
        // only in the nullifier — which is unlinkable to either commitment — so
        // no observer can say which member produced which execution.
        let mut pool = BehaviorPool::new();
        let (sa, sb, act) = (secret(1), secret(2), action(77));
        let ia = pool.commit(&sa, &act);
        let ib = pool.commit(&sb, &act);

        let ea = pool.prove_execution(&sa, &act, ia, round(3)).unwrap();
        let eb = pool.prove_execution(&sb, &act, ib, round(3)).unwrap();

        assert_eq!(pool.settle(&ea).unwrap(), act);
        assert_eq!(pool.settle(&eb).unwrap(), act);

        // Same public action, same root — only the nullifiers differ, and they
        // reveal nothing about which commitment they came from.
        assert_eq!(ea.action, eb.action);
        assert_eq!(ea.statement.root, eb.statement.root);
        assert_ne!(ea.statement.nullifier, eb.statement.nullifier);
    }

    #[test]
    fn double_execution_same_round_is_rejected() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        let e1 = pool.prove_execution(&sa, &act, idx, round(9)).unwrap();
        // A second execution by the same member in the same round reuses the
        // nullifier.
        let e2 = pool.prove_execution(&sa, &act, idx, round(9)).unwrap();
        assert!(pool.settle(&e1).is_ok());
        assert_eq!(pool.settle(&e2).unwrap_err(), PoolError::NullifierSpent);
    }

    #[test]
    fn same_member_can_act_once_per_new_round() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        assert!(pool
            .settle(&pool.prove_execution(&sa, &act, idx, round(1)).unwrap())
            .is_ok());
        // A fresh round yields a fresh nullifier → allowed again.
        assert!(pool
            .settle(&pool.prove_execution(&sa, &act, idx, round(2)).unwrap())
            .is_ok());
    }

    #[test]
    fn executing_an_uncommitted_action_fails() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        // Same secret and leaf, but claiming a *different* action than committed:
        // the commitment H(secret‖other) is not the leaf, so no valid witness.
        let other = action(51);
        assert_eq!(
            pool.prove_execution(&sa, &other, idx, round(9))
                .unwrap_err(),
            PoolError::NotAMember
        );
    }

    #[test]
    fn tampered_action_after_proof_is_rejected() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        let mut exec = pool.prove_execution(&sa, &act, idx, round(9)).unwrap();
        // Attacker swaps the public action while keeping the proof.
        exec.action = action(99);
        assert_eq!(pool.settle(&exec).unwrap_err(), PoolError::ActionMismatch);
    }

    #[test]
    fn non_member_secret_cannot_execute() {
        let mut pool = BehaviorPool::new();
        let (sa, act) = (secret(1), action(50));
        let idx = pool.commit(&sa, &act);
        // An outsider tries to ride member 0's leaf with their own secret.
        let outsider = secret(200);
        assert_eq!(
            pool.prove_execution(&outsider, &act, idx, round(9))
                .unwrap_err(),
            PoolError::NotAMember
        );
    }
}
