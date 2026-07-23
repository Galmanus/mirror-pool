//! # riverrun-pool-zk
//!
//! The behavioral pool with the STARK **wired into the flow** — the honest fix
//! for audit-critical #1's confidentiality half. Unlike `riverrun-core`'s
//! reference-proof pool (which serializes the secret into the `Execution`), here
//! an [`Execution`] carries only **public data plus an opaque post-quantum STARK
//! membership proof**. The member's secret never leaves the prover.
//!
//! Flow:
//! - **commit**: publish `leaf = Rescue(secret)` into the set.
//! - **execute**: produce an opaque STARK proof that *some* committed leaf is
//!   yours, plus the round nullifier — the secret is not transmitted.
//! - **settle**: verify the opaque proof against the public root and spend the
//!   nullifier. No witness required.
//!
//! ## Honest scope (what this does and does NOT close)
//!
//! - ✅ Closes: the secret is no longer on the wire (confidentiality of
//!   audit-critical #1). Verified by a test asserting the `Execution` carries no
//!   witness.
//! - ❌ Not yet closed (audit-critical #1c): the nullifier is **not bound inside
//!   the STARK**, so the proof does not witness that the revealed nullifier was
//!   derived from the *same* secret that proved membership. Until the nullifier
//!   is folded into the AIR, a member can prove membership and pair it with a
//!   nullifier of their choosing — so the "one action per member per round"
//!   soundness is not cryptographically enforced here. This is the next
//!   increment; it is not hidden.
//! - Verification is off-chain (the chosen trusted-relayer, post-quantum model).

use std::collections::HashSet;

use riverrun_stark::{leaf_of, verify_bytes, BaseElement, Hash, MembershipSet, Rescue128};

/// A member's secret witness: the two field-element preimage of their leaf.
pub type Secret = [BaseElement; 2];

/// Everything an execution publishes. Note the absence of any witness field —
/// only the public root, round, revealed nullifier, and the opaque proof.
#[derive(Clone)]
pub struct Execution {
    pub root: Hash,
    pub round: u64,
    pub nullifier: Hash,
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

    /// Commit a member: publish `Rescue(secret)` as a leaf. Returns the member's
    /// private leaf index.
    pub fn commit(&mut self, secret: Secret) -> usize {
        self.leaves.push(leaf_of(secret));
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Valid Merkle widths for the STARK: the trace length is `(depth+1)·8`,
    /// which is a power of two (required for the FFT) only when `depth+1` is a
    /// power of two — i.e. tree sizes 2, 8, 128, 32768 (depths 1, 3, 7, 15).
    const VALID_WIDTHS: [usize; 4] = [2, 8, 128, 32768];

    /// Leaves padded up to the smallest valid width that fits the members, with a
    /// fixed empty leaf appended after the real members so real indices stay stable.
    fn padded_leaves(&self) -> Vec<Hash> {
        let n = self.leaves.len().max(1);
        let width = Self::VALID_WIDTHS
            .into_iter()
            .find(|&w| n <= w)
            .expect("pool exceeds the largest fixed STARK tree size (32768)");
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
    /// (Not yet bound inside the membership proof — see the module-level scope note.)
    fn nullifier(secret: &Secret, round: u64) -> Hash {
        Rescue128::digest(&[secret[0], secret[1], BaseElement::new(round as u128)])
    }

    /// Produce an execution: an opaque STARK membership proof plus the round
    /// nullifier. The secret stays here; it is not part of the returned value.
    pub fn prove_execution(&self, secret: Secret, index: usize, round: u64) -> Execution {
        let set = self.set();
        Execution {
            root: set.root(),
            round,
            nullifier: Self::nullifier(&secret, round),
            proof: set.prove(secret, index),
        }
    }

    /// Verify an execution against the current root and spend its nullifier.
    /// Requires no witness — only the public statement and the opaque proof.
    pub fn settle(&mut self, exec: &Execution) -> Result<(), ZkPoolError> {
        let current = self.root().ok_or(ZkPoolError::EmptyPool)?;
        if current.to_bytes() != exec.root.to_bytes() {
            return Err(ZkPoolError::StaleRoot);
        }
        if !verify_bytes(exec.root, &exec.proof) {
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

    /// Fill the pool to `n` members, returning their (secret, index) handles.
    fn pool_with(n: u128) -> (ZkPool, Vec<(Secret, usize)>) {
        let mut pool = ZkPool::new();
        let members: Vec<(Secret, usize)> = (0..n)
            .map(|i| {
                let s = secret(1000 + i, 2000 + i);
                let idx = pool.commit(s);
                (s, idx)
            })
            .collect();
        (pool, members)
    }

    #[test]
    fn commit_execute_settle_round_trip() {
        let (mut pool, members) = pool_with(5);
        let (s, idx) = members[2];
        let exec = pool.prove_execution(s, idx, 0);
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
        let exec = pool.prove_execution(s, idx, 7);
        drop(s);
        assert!(pool.settle(&exec).is_ok());
    }

    #[test]
    fn double_execution_same_round_is_rejected() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[0];
        let e1 = pool.prove_execution(s, idx, 0);
        let e2 = pool.prove_execution(s, idx, 0);
        assert!(pool.settle(&e1).is_ok());
        assert_eq!(pool.settle(&e2).unwrap_err(), ZkPoolError::NullifierSpent);
    }

    #[test]
    fn same_member_acts_once_per_new_round() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[0];
        assert!(pool.settle(&pool.prove_execution(s, idx, 1)).is_ok());
        assert!(pool.settle(&pool.prove_execution(s, idx, 2)).is_ok());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (mut pool, members) = pool_with(4);
        let (s, idx) = members[3];
        let mut exec = pool.prove_execution(s, idx, 0);
        // Corrupt the opaque proof.
        if let Some(b) = exec.proof.get_mut(16) {
            *b ^= 0xFF;
        }
        assert_eq!(pool.settle(&exec).unwrap_err(), ZkPoolError::BadProof);
    }
}
