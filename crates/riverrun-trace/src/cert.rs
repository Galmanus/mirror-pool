//! Proof-carrying **privacy certificates** for a coordinated round.
//!
//! This applies the AXL certificate pattern (Galmanus, *AXL: Proof-Carrying
//! Certificates for Bounded Autonomy*) to a privacy bound. It is a native
//! implementation, not a dependency on the AXL compiler, and the design credit is
//! AXL's.
//!
//! ## The trust gap it closes
//!
//! The coordinator ([`crate::coordinator`]) forms a round and claims a privacy
//! floor for it: *"effective-k is at least this, and every admitted member's
//! provenance class has at least `k_min` members, so no one is exposed."* On its
//! own that is the agent's word. A member about to join has to trust that the
//! coordinator computed honestly and was not buggy or adversarial.
//!
//! A certificate replaces trust with a check. When the agent fires a round it
//! emits a small artifact carrying the *evidence*---the provenance-class
//! histogram---and its two claims. Anyone can verify it, following AXL's three
//! properties:
//!
//! - **inescapable.** [`verify`] recomputes the effective-k from the carried
//!   histogram and asserts it equals the claim, and checks the floor directly. A
//!   coordinator cannot certify a floor the histogram does not support, because
//!   verification redoes the arithmetic.
//! - **portable.** The certificate is a small, serializable object a third
//!   party---a member, an auditor, a settling program---verifies without trusting
//!   the coordinator and without re-tracing the funding graph.
//! - **bound to the round.** A blake3 commitment ties the certificate to the exact
//!   admitted set, so it cannot be replayed onto a different round.
//!
//! ## Honest scope
//!
//! AXL's original bound (a sliding-window spending limit) needs an SMT solver
//! because the property is non-trivial. This bound does not: the two claims are a
//! closed-form function of the class-size multiset---$\keff = 2^{\sum (n_c/n)\log_2
//! n_c}$ and $\min_c n_c \geq k_{\min}$---so verification is cheap arithmetic, no
//! solver. This is the AXL *certificate pattern*, not its SMT machinery, and that
//! the bound is simple enough to check directly is a feature: the certificate is
//! trivially and independently verifiable, and the integer floor
//! ($\min_c n_c \geq k_{\min}$) is exactly what an on-chain settling program could
//! enforce without any floating point.
//!
//! The certificate carries only the class-size histogram, never member
//! identities, so it proves the crowd meets the floor without revealing who is in
//! which class: the certificate is itself privacy-preserving.

use crate::effective_k;

/// A privacy certificate for one coordinated round: either an issued bound with
/// its evidence, or a fail-closed refusal.
#[derive(Clone, Debug, PartialEq)]
pub enum PrivacyCertificate {
    /// The round meets the floor. Carries the evidence needed to re-check it.
    Issued {
        /// The floor cleared: every admitted member's provenance class has at
        /// least this many members.
        k_min: usize,
        /// The number of admitted members (the advertised crowd size).
        crowd: usize,
        /// The round's effective anonymity-set size, as claimed. Verification
        /// recomputes this from `class_sizes` and rejects any mismatch.
        effective_k: f64,
        /// The provenance-class histogram of the admitted set: the load-bearing
        /// evidence. No member identity appears here.
        class_sizes: Vec<usize>,
        /// blake3 commitment binding this certificate to the exact admitted set.
        round_commit: [u8; 32],
    },
    /// No round meeting the floor could be formed. Fail-closed, like AXL.
    Refused { reason: String },
}

/// A verified certificate reduces to these load-bearing facts. Metadata (the
/// float `effective_k`) is recomputed, not trusted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Verified {
    pub crowd: usize,
    pub k_min: usize,
    pub effective_k: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerifyError {
    /// The certificate refuses: no safe round.
    Refused(String),
    /// The carried histogram does not sum to the admitted crowd.
    HistogramMismatch,
    /// A provenance class is below the claimed floor: a member would be exposed.
    FloorBreached { smallest: usize, k_min: usize },
    /// The recomputed effective-k does not match the claim (tampering or drift).
    EffectiveKDrift { claimed: f64, recomputed: f64 },
    /// The certificate is not bound to this admitted set.
    WrongRound,
}

/// Commit to an admitted set: blake3 over the sorted member ids and the sorted
/// class-size histogram. Deterministic and order-independent.
fn commit(admitted: &[String], class_sizes: &[usize]) -> [u8; 32] {
    let mut ids: Vec<&str> = admitted.iter().map(String::as_str).collect();
    ids.sort_unstable();
    let mut sizes = class_sizes.to_vec();
    sizes.sort_unstable();

    let mut h = blake3::Hasher::new();
    h.update(b"riverrun-privacy-cert-v1");
    h.update(&(ids.len() as u64).to_le_bytes());
    for id in ids {
        h.update(&(id.len() as u64).to_le_bytes());
        h.update(id.as_bytes());
    }
    h.update(&(sizes.len() as u64).to_le_bytes());
    for n in sizes {
        h.update(&(n as u64).to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Issue a certificate for a round of `admitted` members whose provenance classes
/// have sizes `class_sizes`, against the floor `k_min`. Fail-closed: if the crowd
/// is empty or any class is below the floor, [`PrivacyCertificate::Refused`].
pub fn certify(admitted: &[String], class_sizes: &[usize], k_min: usize) -> PrivacyCertificate {
    let k_min = k_min.max(1);
    let crowd: usize = class_sizes.iter().sum();

    if crowd == 0 {
        return PrivacyCertificate::Refused {
            reason: "no members could be admitted into a safe round".into(),
        };
    }
    if crowd != admitted.len() {
        return PrivacyCertificate::Refused {
            reason: "the admitted set and its class histogram disagree".into(),
        };
    }
    let smallest = class_sizes.iter().copied().min().unwrap_or(0);
    if smallest < k_min {
        return PrivacyCertificate::Refused {
            reason: format!(
                "a provenance class of {smallest} is below the floor of {k_min}: \
                 admitting it would expose a member"
            ),
        };
    }

    PrivacyCertificate::Issued {
        k_min,
        crowd,
        effective_k: effective_k(class_sizes).effective,
        class_sizes: class_sizes.to_vec(),
        round_commit: commit(admitted, class_sizes),
    }
}

/// Independently verify a certificate against the admitted set a member is about
/// to join. Recomputes everything; trusts nothing in the certificate but its
/// structure.
pub fn verify(cert: &PrivacyCertificate, admitted: &[String]) -> Result<Verified, VerifyError> {
    let (k_min, crowd, claimed_k, class_sizes, round_commit) = match cert {
        PrivacyCertificate::Refused { reason } => {
            return Err(VerifyError::Refused(reason.clone()))
        }
        PrivacyCertificate::Issued { k_min, crowd, effective_k, class_sizes, round_commit } => {
            (*k_min, *crowd, *effective_k, class_sizes, round_commit)
        }
    };

    // 1. the histogram must account for exactly the admitted crowd
    let sum: usize = class_sizes.iter().sum();
    if sum != crowd || sum != admitted.len() {
        return Err(VerifyError::HistogramMismatch);
    }
    // 2. the floor: no class below k_min, so no member is exposed
    let smallest = class_sizes.iter().copied().min().unwrap_or(0);
    if smallest < k_min {
        return Err(VerifyError::FloorBreached { smallest, k_min });
    }
    // 3. inescapable: recompute effective-k and reject drift
    let recomputed = effective_k(class_sizes).effective;
    if (recomputed - claimed_k).abs() > 1e-9 {
        return Err(VerifyError::EffectiveKDrift { claimed: claimed_k, recomputed });
    }
    // 4. bound to this exact round
    if commit(admitted, class_sizes) != *round_commit {
        return Err(VerifyError::WrongRound);
    }

    Ok(Verified { crowd, k_min, effective_k: recomputed })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("m{i}")).collect()
    }

    #[test]
    fn a_safe_round_certifies_and_verifies() {
        let admitted = members(8);
        let sizes = vec![5, 3];
        let cert = certify(&admitted, &sizes, 2);
        let v = verify(&cert, &admitted).expect("a floor-clearing round must verify");
        assert_eq!(v.crowd, 8);
        assert_eq!(v.k_min, 2);
        assert!(v.effective_k > 4.0);
    }

    #[test]
    fn an_exposed_round_is_refused_not_issued() {
        // a singleton class breaches the floor
        let admitted = members(6);
        let sizes = vec![5, 1];
        let cert = certify(&admitted, &sizes, 2);
        assert!(matches!(cert, PrivacyCertificate::Refused { .. }));
        assert_eq!(
            verify(&cert, &admitted),
            Err(VerifyError::Refused(
                "a provenance class of 1 is below the floor of 2: admitting it would expose a member".into()
            ))
        );
    }

    #[test]
    fn a_tampered_effective_k_is_caught_by_recomputation() {
        // This is the inescapable property: forge a higher effective-k and it dies.
        let admitted = members(8);
        let sizes = vec![5, 3];
        let mut cert = certify(&admitted, &sizes, 2);
        if let PrivacyCertificate::Issued { effective_k, .. } = &mut cert {
            *effective_k = 8.0; // claim more anonymity than the histogram supports
        }
        assert!(matches!(
            verify(&cert, &admitted),
            Err(VerifyError::EffectiveKDrift { .. })
        ));
    }

    #[test]
    fn a_tampered_histogram_is_caught() {
        // Inflate a class in the evidence without changing the crowd: the sum no
        // longer matches, or (if kept summing) the commitment breaks.
        let admitted = members(8);
        let sizes = vec![5, 3];
        let mut cert = certify(&admitted, &sizes, 2);
        if let PrivacyCertificate::Issued { class_sizes, .. } = &mut cert {
            *class_sizes = vec![6, 3]; // sums to 9, not 8
        }
        assert_eq!(verify(&cert, &admitted), Err(VerifyError::HistogramMismatch));
    }

    #[test]
    fn a_certificate_cannot_be_replayed_onto_another_round() {
        let admitted_a = members(8);
        let sizes = vec![5, 3];
        let cert = certify(&admitted_a, &sizes, 2);

        // a different crowd of the same shape must not accept A's certificate
        let admitted_b: Vec<String> = (100..108).map(|i| format!("m{i}")).collect();
        assert_eq!(verify(&cert, &admitted_b), Err(VerifyError::WrongRound));
    }

    #[test]
    fn the_certificate_carries_no_identities() {
        // The evidence is a histogram, not a membership list: privacy-preserving.
        let admitted = members(8);
        let cert = certify(&admitted, &[5, 3], 2);
        if let PrivacyCertificate::Issued { class_sizes, .. } = &cert {
            assert_eq!(class_sizes, &vec![5, 3]);
        } else {
            panic!("should have issued");
        }
        // (there is no field on Issued that could hold a member id)
    }
}
