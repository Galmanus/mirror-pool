//! riverrun-sdk: the `act()` flow a fund, market maker, or agent integrates.
//!
//! One call, one unlinkable, *measured* action. `act()` derives everything from a
//! single secret (see `riverrun_core::act`, Phase B), commits the leaf to join a
//! round, waits for the crowd to form, **refuses to settle if the round's measured
//! anonymity is below the caller's floor**, proves membership+nullifier+action,
//! settles through a relayer, and returns a receipt with the anonymity you actually
//! got, not the advertised member count.
//!
//! The on-chain side and the prover are behind traits, so the flow is testable
//! without a live cluster and the real Solana backend plugs in later
//! (`docs/RIVERRUN_ACT_DESIGN.md`, Phase D). The floor check is the point: a fund
//! will not act into a crowd that does not hide it, and the SDK enforces that in
//! code, not in a promise.

use riverrun_core::act;
use riverrun_core::commitment::{Commitment, Secret};
use riverrun_core::nullifier::Nullifier;

/// What a caller wants to do, unlinkably.
pub struct ActRequest<'a> {
    /// The venue or app the action belongs to (unlinkable across contexts).
    pub context: &'a [u8],
    /// The public action to perform.
    pub action: &'a [u8],
    /// Where the fixed-denomination payout goes.
    pub recipient: [u8; 32],
    /// The payout amount (a pool's fixed denomination).
    pub amount: u64,
}

/// A round the backend formed, with its measured anonymity.
#[derive(Clone, Debug)]
pub struct RoundInfo {
    /// The round identifier the nullifier and proof are bound to.
    pub round: Vec<u8>,
    /// Members in the round (the advertised count).
    pub advertised_k: usize,
    /// The anonymity the ruler measured for this round (the number that matters).
    pub effective_k: f64,
}

/// An opaque membership+nullifier+action proof.
pub type Proof = Vec<u8>;

/// What `act()` returns: the settlement plus the anonymity you actually got.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// The settlement transaction signature.
    pub signature: String,
    /// The round the action settled in.
    pub round: Vec<u8>,
    /// The nullifier spent (one action per member per round).
    pub nullifier: Nullifier,
    /// The advertised member count of the round.
    pub advertised_k: usize,
    /// The measured effective-k, the anonymity actually delivered.
    pub effective_k: f64,
}

/// Why an `act()` did not settle.
#[derive(Clone, Debug, PartialEq)]
pub enum ActError {
    /// The round's measured anonymity was below the policy floor, so `act()`
    /// refused to settle rather than act into a crowd that would not hide you.
    BelowFloor { effective_k: f64, floor: f64 },
    /// The on-chain backend failed (commit, round formation, or settlement).
    Backend(String),
    /// The prover failed to produce a proof.
    Prover(String),
}

/// The on-chain side: publish a commitment, wait for the round, settle with a
/// proof. The real implementation talks to the Solana program; a test uses a mock.
pub trait Backend {
    /// Publish the commitment leaf to join the next round.
    fn commit(&mut self, commitment: &Commitment) -> Result<(), String>;
    /// Wait for the round to form and return it with its measured anonymity.
    fn await_round(&mut self) -> Result<RoundInfo, String>;
    /// Settle the action through a relayer; no member key signs. Returns the
    /// settlement signature.
    fn settle(
        &mut self,
        round: &RoundInfo,
        nullifier: &Nullifier,
        action: &[u8],
        recipient: &[u8; 32],
        amount: u64,
        proof: &Proof,
    ) -> Result<String, String>;
}

/// Builds the membership+nullifier+action proof for one settlement. The real
/// implementation drives the STARK; a test uses a mock.
pub trait Prover {
    fn prove(
        &self,
        secret: &Secret,
        context: &[u8],
        action: &[u8],
        round: &RoundInfo,
    ) -> Result<Proof, String>;
}

/// The caller's anonymity policy.
pub struct Policy {
    /// `act()` refuses to settle if the round's effective-k is below this. Set it
    /// to the anonymity you actually require; the flow enforces it.
    pub min_effective_k: f64,
}

/// The single flow: derive from one secret, commit, wait for the crowd, refuse if
/// it is too small, prove, settle, and return a receipt with the measured
/// anonymity. Identity, membership, and nullifier all come from `secret`.
pub fn act(
    secret: &Secret,
    req: &ActRequest,
    prover: &dyn Prover,
    backend: &mut dyn Backend,
    policy: &Policy,
) -> Result<Receipt, ActError> {
    // 1. The leaf has no round dependency, so publish it to join the next round.
    let commitment = act::commitment(secret, req.context, req.action);
    backend.commit(&commitment).map_err(ActError::Backend)?;

    // 2. The crowd forms.
    let round = backend.await_round().map_err(ActError::Backend)?;

    // 3. The anonymity floor: measure, do not hope. Refuse to act into a crowd
    //    that would not hide you, before anything is spent.
    if round.effective_k < policy.min_effective_k {
        return Err(ActError::BelowFloor {
            effective_k: round.effective_k,
            floor: policy.min_effective_k,
        });
    }

    // 4. The round is fixed now, so the nullifier is known: prove, then settle
    //    through the relayer. No member key signs the settlement.
    let nullifier = act::nullifier(secret, req.context, &round.round);
    let proof = prover
        .prove(secret, req.context, req.action, &round)
        .map_err(ActError::Prover)?;
    let signature = backend
        .settle(&round, &nullifier, req.action, &req.recipient, req.amount, &proof)
        .map_err(ActError::Backend)?;

    // 5. The receipt reports the anonymity actually delivered, not the count.
    Ok(Receipt {
        signature,
        round: round.round,
        nullifier,
        advertised_k: round.advertised_k,
        effective_k: round.effective_k,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend {
        round: RoundInfo,
        fail_commit: bool,
        committed: Option<Commitment>,
        settled_nullifier: Option<Nullifier>,
        settled_recipient: Option<[u8; 32]>,
    }
    impl MockBackend {
        fn with_effective_k(ek: f64) -> Self {
            Self {
                round: RoundInfo { round: b"round-7".to_vec(), advertised_k: 30, effective_k: ek },
                fail_commit: false,
                committed: None,
                settled_nullifier: None,
                settled_recipient: None,
            }
        }
    }
    impl Backend for MockBackend {
        fn commit(&mut self, c: &Commitment) -> Result<(), String> {
            if self.fail_commit {
                return Err("rpc unreachable".into());
            }
            self.committed = Some(*c);
            Ok(())
        }
        fn await_round(&mut self) -> Result<RoundInfo, String> {
            Ok(self.round.clone())
        }
        fn settle(
            &mut self,
            _round: &RoundInfo,
            nullifier: &Nullifier,
            _action: &[u8],
            recipient: &[u8; 32],
            _amount: u64,
            _proof: &Proof,
        ) -> Result<String, String> {
            self.settled_nullifier = Some(*nullifier);
            self.settled_recipient = Some(*recipient);
            Ok("SIG_OK".into())
        }
    }

    struct MockProver;
    impl Prover for MockProver {
        fn prove(&self, _s: &Secret, _c: &[u8], _a: &[u8], _r: &RoundInfo) -> Result<Proof, String> {
            Ok(vec![0xAB; 8])
        }
    }

    fn secret() -> Secret {
        Secret::from_bytes([7; 32])
    }
    fn request() -> ActRequest<'static> {
        ActRequest { context: b"amm", action: b"buy", recipient: [9; 32], amount: 1_000_000 }
    }
    fn policy(floor: f64) -> Policy {
        Policy { min_effective_k: floor }
    }

    #[test]
    fn act_settles_and_reports_measured_anonymity_not_the_advertised_count() {
        let mut be = MockBackend::with_effective_k(12.0);
        let r = act(&secret(), &request(), &MockProver, &mut be, &policy(6.0)).unwrap();
        assert_eq!(r.signature, "SIG_OK");
        assert_eq!(r.effective_k, 12.0, "the receipt reports the measured effective-k");
        assert_eq!(r.advertised_k, 30);
        assert_ne!(r.effective_k, r.advertised_k as f64, "measured is not the advertised count");
    }

    #[test]
    fn act_commits_the_leaf_derived_from_the_secret() {
        let mut be = MockBackend::with_effective_k(12.0);
        act(&secret(), &request(), &MockProver, &mut be, &policy(6.0)).unwrap();
        assert_eq!(
            be.committed.unwrap(),
            act::commitment(&secret(), b"amm", b"buy"),
            "the committed leaf is exactly the one derived from the secret + context + action"
        );
    }

    #[test]
    fn act_settles_the_nullifier_derived_from_the_secret_and_round() {
        let mut be = MockBackend::with_effective_k(12.0);
        act(&secret(), &request(), &MockProver, &mut be, &policy(6.0)).unwrap();
        assert_eq!(
            be.settled_nullifier.unwrap(),
            act::nullifier(&secret(), b"amm", b"round-7"),
            "the settled nullifier is exactly the one derived from the secret + context + round"
        );
    }

    #[test]
    fn act_refuses_to_settle_below_the_anonymity_floor() {
        // The round's measured anonymity is 3, below the fund's floor of 6.
        let mut be = MockBackend::with_effective_k(3.0);
        let err = act(&secret(), &request(), &MockProver, &mut be, &policy(6.0)).unwrap_err();
        assert_eq!(err, ActError::BelowFloor { effective_k: 3.0, floor: 6.0 });
        assert!(be.settled_nullifier.is_none(), "it must not settle when below the floor");
    }

    #[test]
    fn act_propagates_a_backend_failure_without_settling() {
        let mut be = MockBackend::with_effective_k(12.0);
        be.fail_commit = true;
        let err = act(&secret(), &request(), &MockProver, &mut be, &policy(6.0)).unwrap_err();
        assert!(matches!(err, ActError::Backend(_)));
        assert!(be.settled_nullifier.is_none());
    }
}
