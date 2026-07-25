//! # riverrun-pool-zk
//!
//! The behavioral pool with the STARK **wired into the flow** — the honest fix
//! for audit-critical #1's confidentiality half. Unlike `riverrun-core`'s
//! reference-proof pool (which serializes the secret into the `Execution`), here
//! an [`Execution`] carries only **public data plus an opaque post-quantum STARK
//! membership proof**. The member's secret never leaves the prover.
//!
//! Flow:
//! - **commit**: publish `leaf = Rescue(secret, action)` into the set — the member
//!   registers *which intent* they may later execute.
//! - **execute**: produce an opaque STARK proof that *some* committed leaf is
//!   yours, that it commits to *this* action, and that the revealed round
//!   nullifier came from that same secret — none of which transmits the secret.
//! - **settle**: verify the opaque proof against the public root, round and
//!   nullifier, then spend the nullifier. No witness required.
//!
//! ## Honest scope (what this does and does NOT close)
//!
//! - Closes: the secret is no longer on the wire (confidentiality of
//!   audit-critical #1). Verified by a test asserting the `Execution` carries no
//!   witness.
//! - Closes: the nullifier is **bound inside the STARK** (audit-critical #1c).
//!   The proof's public inputs are `{root, nullifier, round, action}`, and the AIR
//!   witnesses every part from one secret, so pairing a valid membership proof
//!   with a nullifier of one's choosing no longer verifies — "one action per
//!   member per round" is cryptographically enforced here.
//! - Closes: the **action is bound too**. The leaf is `Rescue(secret, action)`, so
//!   a member can execute the intent they registered and not another. Without
//!   this, membership alone would let anyone in the set execute anything.
//! - Still open: the AIR is hand-rolled and **unaudited**. Passing negative tests
//!   are necessary, not sufficient, for soundness.
//! - Still open: verification is off-chain (the chosen trusted-relayer,
//!   post-quantum model). The on-chain `execute` still verifies no membership —
//!   audit-critical #2.
//! - The proof keeps the witness off the wire but Winterfell 0.13 has no witness
//!   randomization, so this is not a formal zero-knowledge guarantee.

use std::collections::HashSet;

use riverrun_stark::{leaf_of, nullifier, verify_bound, BaseElement, Hash, MembershipSet};

/// A member's secret witness: the two field-element preimage of their leaf.
pub type Secret = [BaseElement; 2];

/// The public action a member commits to and later executes, as two field
/// elements (a 32-byte action hash).
pub type Action = [BaseElement; 2];

/// Mint a fresh member secret from the operating system's CSPRNG.
///
/// The secret is two independent `f128` field elements — ~256 bits of entropy.
/// Every hiding property of the pool (the leaf `Rescue(secret, action)` and the
/// per-round `nullifier(secret, round)`) rests on this secret being unguessable:
/// a 256-bit secret costs a quantum adversary ~2^128 work under Grover, the
/// standard post-quantum level. Leaving secret generation to the caller is a
/// footgun (a weak secret is breakable regardless of the hash), so the pool
/// ships the generator.
pub fn random_secret() -> Secret {
    [random_field_element(), random_field_element()]
}

/// Draw one near-uniform `f128` element from 128 bits of OS entropy. The modular
/// reduction bias is negligible: the f128 modulus is within a tiny factor of
/// 2^128, so a uniform `u128` maps to a statistically uniform field element.
fn random_field_element() -> BaseElement {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG must be available to mint a member secret");
    BaseElement::new(u128::from_le_bytes(bytes))
}

/// Everything an execution publishes. Note the absence of any witness field —
/// only the public root, round, revealed nullifier, and the opaque proof.
#[derive(Clone)]
pub struct Execution {
    pub root: Hash,
    pub round: u64,
    pub nullifier: Hash,
    /// The action being executed. Public, and witnessed by the proof.
    pub action: Action,
    /// Opaque post-quantum STARK membership proof. Carries no secret.
    pub proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZkPoolError {
    EmptyPool,
    StaleRoot,
    BadProof,
    NullifierSpent,
}

/// The ZK-backed behavioral pool.
#[derive(Default)]
pub struct ZkPool {
    leaves: Vec<Hash>,
    spent: HashSet<[u8; 32]>,
}

impl ZkPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Commit a member's intent: publish `Rescue(secret, action)` as a leaf.
    /// Returns the member's private leaf index.
    pub fn commit(&mut self, secret: Secret, action: Action) -> usize {
        self.leaves.push(leaf_of(secret, action));
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Valid Merkle widths for the STARK: the bound trace spends one cycle on the
    /// nullifier and one per Merkle level, so its length is `(depth+2)·8`, a power
    /// of two (required for the FFT) only when `depth+2` is — i.e. tree sizes 4, 64
    /// and 16384 (depths 2, 6, 14).
    const VALID_WIDTHS: [usize; 3] = [4, 64, 16384];

    /// Leaves padded up to the smallest valid width that fits the members, with a
    /// fixed empty leaf appended after the real members so real indices stay stable.
    fn padded_leaves(&self) -> Vec<Hash> {
        let n = self.leaves.len().max(1);
        let width = Self::VALID_WIDTHS
            .into_iter()
            .find(|&w| n <= w)
            .expect("pool exceeds the largest fixed STARK tree size (16384)");
        let mut v = self.leaves.clone();
        let empty = Hash::new(BaseElement::new(0), BaseElement::new(0));
        v.resize(width, empty);
        v
    }

    fn set(&self) -> MembershipSet {
        MembershipSet::new(self.padded_leaves())
    }

    /// The public set root, or `None` if empty.
    pub fn root(&self) -> Option<Hash> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(self.set().root())
        }
    }

    /// The per-round nullifier for a secret: `Rescue(secret[0], secret[1], round)`.
    /// The membership proof witnesses this same derivation, so a nullifier that
    /// does not come from the proving member's secret makes the proof fail.
    fn nullifier(secret: &Secret, round: u64) -> Hash {
        nullifier(*secret, Self::round_element(round))
    }

    fn round_element(round: u64) -> BaseElement {
        BaseElement::new(round as u128)
    }

    /// Produce an execution: an opaque STARK membership proof plus the round
    /// nullifier. The secret stays here; it is not part of the returned value.
    pub fn prove_execution(
        &self,
        secret: Secret,
        index: usize,
        round: u64,
        action: Action,
    ) -> Execution {
        let set = self.set();
        Execution {
            root: set.root(),
            round,
            nullifier: Self::nullifier(&secret, round),
            action,
            proof: set.prove_bound(secret, index, Self::round_element(round), action),
        }
    }

    /// Verify an execution against the current root and spend its nullifier.
    /// Requires no witness — only the public statement and the opaque proof.
    pub fn settle(&mut self, exec: &Execution) -> Result<(), ZkPoolError> {
        let current = self.root().ok_or(ZkPoolError::EmptyPool)?;
        if current.to_bytes() != exec.root.to_bytes() {
            return Err(ZkPoolError::StaleRoot);
        }
        if !verify_bound(
            exec.root,
            exec.nullifier,
            Self::round_element(exec.round),
            exec.action,
            &exec.proof,
        ) {
            return Err(ZkPoolError::BadProof);
        }
        let n = exec.nullifier.to_bytes();
        if self.spent.contains(&n) {
            return Err(ZkPoolError::NullifierSpent);
        }
        self.spent.insert(n);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(a: u128, b: u128) -> Secret {
        [BaseElement::new(a), BaseElement::new(b)]
    }

    fn action(tag: u128) -> Action {
        [BaseElement::new(0xAC01 + tag), BaseElement::new(0xAC02 + tag)]
    }

    /// Fill the pool to `n` members, returning their (secret, index) handles.
    fn pool_with(n: u128) -> (ZkPool, Vec<(Secret, usize)>) {
        let mut pool = ZkPool::new();
        let members: Vec<(Secret, usize)> = (0..n)
            .map(|i| {
                let s = secret(1000 + i, 2000 + i);
                let idx = pool.commit(s, action(0));
                (s, idx)
            })
            .collect();
        (pool, members)
    }

    #[test]
    fn commit_execute_settle_round_trip() {
        let (mut pool, members) = pool_with(5);
        let (s, idx) = members[2];
        let exec = pool.prove_execution(s, idx, 0, action(0));
        assert!(pool.settle(&exec).is_ok());
    }

    #[test]
    fn settle_needs_no_secret() {
        // The whole point of 1b: settle takes only &Execution — the public root,
        // round, revealed nullifier, and the opaque proof. It never receives the
        // secret. We drop the secret before settling to make that explicit; the
        // opaque proof still verifies from public data alone. (That the secret is
        // also absent from the proof *bytes* is proven in riverrun-stark's
        // `transmitted_proof_does_not_carry_the_secret_verbatim`.)
        let (mut pool, members) = pool_with(5);
        let (s, idx) = members[1];
        let exec = pool.prove_execution(s, idx, 7, action(0));
        drop(s);
        assert!(pool.settle(&exec).is_ok());
    }

    #[test]
    fn double_execution_same_round_is_rejected() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[0];
        let e1 = pool.prove_execution(s, idx, 0, action(0));
        let e2 = pool.prove_execution(s, idx, 0, action(0));
        assert!(pool.settle(&e1).is_ok());
        assert_eq!(pool.settle(&e2).unwrap_err(), ZkPoolError::NullifierSpent);
    }

    #[test]
    fn same_member_acts_once_per_new_round() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[0];
        assert!(pool.settle(&pool.prove_execution(s, idx, 1, action(0))).is_ok());
        assert!(pool.settle(&pool.prove_execution(s, idx, 2, action(0))).is_ok());
    }

    #[test]
    fn an_execution_carrying_someone_elses_nullifier_is_rejected() {
        // Audit-critical #1c at the pool level. Before the nullifier was bound
        // inside the AIR, the proof only said "a member is here" and the nullifier
        // beside it was unchecked — a member could act, then act again in the same
        // round under a nullifier of their choosing.
        let (mut pool, members) = pool_with(3);
        let (s_a, idx_a) = members[0];
        let (s_b, _) = members[1];

        let mut exec = pool.prove_execution(s_a, idx_a, 4, action(0));
        exec.nullifier = ZkPool::nullifier(&s_b, 4);

        assert_eq!(pool.settle(&exec).unwrap_err(), ZkPoolError::BadProof);
    }

    #[test]
    fn executing_an_action_the_member_did_not_commit_is_rejected() {
        // The thesis: a member registers an intent and later executes *that*
        // intent unlinkably. Without the action inside the proof, membership
        // alone would let anyone in the set execute anything.
        let mut pool = ZkPool::new();
        let s = secret(1000, 2000);
        let committed = action(1);
        let idx = pool.commit(s, committed);

        let mut exec = pool.prove_execution(s, idx, 5, committed);
        exec.action = action(2);

        assert_eq!(pool.settle(&exec).unwrap_err(), ZkPoolError::BadProof);
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[3];
        let mut exec = pool.prove_execution(s, idx, 0, action(0));
        // Corrupt the opaque proof.
        if let Some(b) = exec.proof.get_mut(16) {
            *b ^= 0xFF;
        }
        assert_eq!(pool.settle(&exec).unwrap_err(), ZkPoolError::BadProof);
    }

    #[test]
    fn random_secret_is_unique_and_usable() {
        // Two minted secrets must differ (a constant generator would collide),
        // and a random secret must drive a full commit -> execute -> settle,
        // proving the OS-generated witness is a valid pool secret, not just bytes.
        let a = random_secret();
        let b = random_secret();
        assert_ne!(a, b, "two OS-random secrets collided");

        // Same size as the passing round-trip test (5 members), with the random
        // member placed among constant-secret padding.
        let mut pool = ZkPool::new();
        pool.commit(secret(1, 2), action(0));
        pool.commit(secret(3, 4), action(0));
        let idx = pool.commit(a, action(7));
        pool.commit(secret(5, 6), action(0));
        pool.commit(secret(7, 8), action(0));
        let exec = pool.prove_execution(a, idx, 0, action(7));
        assert!(pool.settle(&exec).is_ok(), "random secret failed to settle");
    }
}
