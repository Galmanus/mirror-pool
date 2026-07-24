//! The provenance-aware round coordinator.
//!
//! riverrun's privacy rests on a *synchronized round*: a crowd of members acting
//! together. But a crowd is not privacy just because it is large. Anonymity is
//! measured by the effective set size ([`crate::effective_k`]), and that number
//! is decided by **funding provenance**: a member alone in their provenance class
//! is exposed no matter how big the round, because an adversary who reads the
//! funding graph narrows the actor to that class.
//!
//! So forming a good round is an optimization, and riverrun is the only system
//! that can run it, because it is the only one that can *measure* a round's
//! anonymity. This module is the policy an agent uses: given the members who want
//! to act, it admits the ones whose provenance class is well-populated and defers
//! the ones who would be exposed, telling each deferred member what to do. The
//! result is a round that maximizes effective-k under a hard floor: **every
//! admitted member shares their class with at least `k_min - 1` others.**
//!
//! The counter-intuitive consequence, which the demo shows: a *smaller* round,
//! chosen well, gives *more* anonymity than batching everyone, because batching
//! everyone drags in the singletons who fragment the provenance distribution and
//! collapse the effective set size.

use std::collections::BTreeMap;

use crate::effective_k;

/// A member who wants to act this round, tagged with their funding-provenance
/// class (as produced by [`crate::rpc::provenance_class`], or a synthetic label
/// in tests and demos).
#[derive(Clone, Debug)]
pub struct PendingIntent {
    pub member: String,
    pub class: String,
}

impl PendingIntent {
    pub fn new(member: impl Into<String>, class: impl Into<String>) -> Self {
        Self { member: member.into(), class: class.into() }
    }
}

/// A member held back from this round, with the reason and a concrete remedy.
#[derive(Clone, Debug, PartialEq)]
pub struct Deferral {
    pub member: String,
    pub class: String,
    pub reason: String,
}

/// The plan an agent commits to for one round.
#[derive(Clone, Debug)]
pub struct RoundPlan {
    /// Members admitted to the synchronized round (this is exactly the set that
    /// would be fed to the batched proof).
    pub admitted: Vec<String>,
    /// Members deferred, each with a remedy.
    pub deferred: Vec<Deferral>,
    /// The formed round's effective anonymity-set size.
    pub effective_k: f64,
    /// The smallest provenance class among the admitted members: the anonymity of
    /// the least-protected member in the round.
    pub worst_personal_k: usize,
    /// The provenance-class histogram of the admitted set. The evidence a
    /// certificate carries; no member identity.
    pub admitted_class_sizes: Vec<usize>,
    /// The floor this round was formed against.
    pub k_min: usize,
}

impl RoundPlan {
    pub fn advertised_k(&self) -> usize {
        self.admitted.len()
    }

    /// A proof-carrying privacy certificate for this round (see [`crate::cert`]).
    /// The agent hands this to admitted members, who verify it independently
    /// rather than trusting that the round is private.
    pub fn certificate(&self) -> crate::cert::PrivacyCertificate {
        crate::cert::certify(&self.admitted, &self.admitted_class_sizes, self.k_min)
    }
}

/// Plan a round from `pending`, admitting a member only if at least `k_min`
/// pending members share their provenance class.
///
/// This greedy floor is not a heuristic that merely tends to help: it is a
/// guarantee. Every admitted member ends up in a class of size $\geq$ `k_min`, so
/// no admitted member is exposed, and among rounds with that property this one is
/// the largest (it admits every safe member). Because it drops exactly the
/// singleton and thin classes that fragment the distribution, it also lifts the
/// round's effective-k above the naive "admit everyone" round --- see
/// [`naive_effective_k`] and the tests.
pub fn coordinate(pending: &[PendingIntent], k_min: usize) -> RoundPlan {
    let k_min = k_min.max(1);

    // group members by provenance class, preserving arrival order within a class
    let mut by_class: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for p in pending {
        by_class.entry(&p.class).or_default().push(&p.member);
    }

    let mut admitted = Vec::new();
    let mut deferred = Vec::new();
    let mut admitted_sizes = Vec::new();

    for (class, members) in &by_class {
        if members.len() >= k_min {
            admitted_sizes.push(members.len());
            for m in members {
                admitted.push((*m).to_string());
            }
        } else {
            let need = k_min - members.len();
            for m in members {
                deferred.push(Deferral {
                    member: (*m).to_string(),
                    class: (*class).to_string(),
                    reason: format!(
                        "only {} pending member(s) share your provenance origin; a round \
                         now would leave you in a crowd of {}. Wait for {} more same-origin \
                         member(s), or fund a fresh wallet from an origin the round already \
                         has.",
                        members.len(),
                        members.len(),
                        need
                    ),
                });
            }
        }
    }

    let effective_k = effective_k(&admitted_sizes).effective;
    let worst_personal_k = admitted_sizes.iter().copied().min().unwrap_or(0);

    RoundPlan {
        admitted,
        deferred,
        effective_k,
        worst_personal_k,
        admitted_class_sizes: admitted_sizes,
        k_min,
    }
}

/// The effective-k of the round you would get by naively admitting *everyone* in
/// `pending`. Provided so the coordinator's gain can be stated as a number rather
/// than asserted.
pub fn naive_effective_k(pending: &[PendingIntent]) -> f64 {
    let mut by_class: BTreeMap<&str, usize> = BTreeMap::new();
    for p in pending {
        *by_class.entry(&p.class).or_default() += 1;
    }
    let sizes: Vec<usize> = by_class.values().copied().collect();
    effective_k(&sizes).effective
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intents(spec: &[(&str, usize)]) -> Vec<PendingIntent> {
        // spec: (class, count) -> that many members in that class
        let mut out = Vec::new();
        for (class, n) in spec {
            for i in 0..*n {
                out.push(PendingIntent::new(format!("{class}-{i}"), *class));
            }
        }
        out
    }

    #[test]
    fn a_same_origin_crowd_is_admitted_whole() {
        // Ten members, all funded from the same origin: no one is exposed, the
        // whole crowd is one class, effective-k is the full size.
        let p = intents(&[("A", 10)]);
        let plan = coordinate(&p, 2);
        assert_eq!(plan.admitted.len(), 10);
        assert!(plan.deferred.is_empty());
        assert!((plan.effective_k - 10.0).abs() < 1e-9, "got {}", plan.effective_k);
        assert_eq!(plan.worst_personal_k, 10);
    }

    #[test]
    fn singletons_are_deferred_with_a_remedy() {
        // Two big classes and two lone members. The lone members would each be a
        // crowd of one; defer them.
        let p = intents(&[("A", 5), ("B", 3), ("C", 1), ("D", 1)]);
        let plan = coordinate(&p, 2);
        assert_eq!(plan.admitted.len(), 8, "A and B admitted");
        assert_eq!(plan.deferred.len(), 2, "C and D deferred");
        for d in &plan.deferred {
            assert!(d.reason.contains("origin"), "remedy should be actionable");
        }
        assert!(plan.worst_personal_k >= 2, "no admitted member is alone");
    }

    #[test]
    fn a_smaller_coordinated_round_beats_batching_everyone() {
        // The core claim: choosing well gives MORE anonymity than admitting all.
        let p = intents(&[("A", 5), ("B", 3), ("C", 1), ("D", 1)]);
        let coordinated = coordinate(&p, 2).effective_k;
        let naive = naive_effective_k(&p);
        assert!(
            coordinated > naive,
            "coordinated {coordinated} must beat naive {naive}"
        );
        // for these numbers: coordinated ~4.1 (round of 8), naive ~3.1 (round of 10)
        assert!(coordinated > 4.0 && naive < 3.5, "coordinated {coordinated}, naive {naive}");
    }

    #[test]
    fn an_all_singleton_set_forms_no_safe_round() {
        // If everyone has a unique origin, there is no crowd to hide in. The
        // honest answer is an empty round, not a fake one.
        let p = intents(&[("A", 1), ("B", 1), ("C", 1), ("D", 1)]);
        let plan = coordinate(&p, 2);
        assert!(plan.admitted.is_empty());
        assert_eq!(plan.deferred.len(), 4);
        assert_eq!(plan.effective_k, 0.0);
    }

    #[test]
    fn a_fired_round_hands_out_a_verifiable_certificate() {
        use crate::cert::{verify, PrivacyCertificate};
        let p = intents(&[("A", 5), ("B", 3), ("C", 1)]);
        let plan = coordinate(&p, 2);
        let cert = plan.certificate();
        assert!(matches!(cert, PrivacyCertificate::Issued { .. }));
        // a member re-checks the coordinator's claim against the admitted set,
        // trusting nothing the coordinator said
        let v = verify(&cert, &plan.admitted).expect("the round's certificate must verify");
        assert!(v.effective_k > 4.0);
        assert_eq!(v.crowd, plan.admitted.len());
    }

    #[test]
    fn k_min_is_respected() {
        // With a floor of 4, the class of 3 is now too thin and is deferred.
        let p = intents(&[("A", 5), ("B", 3)]);
        let plan = coordinate(&p, 4);
        assert_eq!(plan.admitted.len(), 5, "only A clears a floor of 4");
        assert_eq!(plan.deferred.len(), 3, "B is deferred");
    }
}
