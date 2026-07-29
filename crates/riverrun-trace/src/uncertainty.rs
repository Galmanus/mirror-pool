//! What a measured effective-k does **not** know: the two uncertainties that must
//! travel with every number this crate publishes.
//!
//! [`effective_k`](crate::effective_k) returns a point estimate from one class
//! histogram. Two different things are missing from it, and neither substitutes
//! for the other:
//!
//! * **The bracket.** Members whose backward walk reached no attributable origin
//!   are not a measured class, they are a *gap*. Treating them as one shared
//!   "rootless" crowd is the most favourable reading; treating each as its own
//!   class is the least favourable. Both are computed exactly, and the truth is
//!   between them. `docs/EFFECTIVE_K.md` published only the favourable reading.
//! * **The sampling interval.** A pool's depositors are sampled, not censused.
//!   Resampling the measured members with replacement and recomputing effective-k
//!   gives the spread of the estimator over the draw. This is a bootstrap
//!   percentile range, **not** a confidence interval — see [`Interval`].
//!
//! And one thing that is neither: an **RPC failure is not evidence**. A throttled
//! call that returns nothing must never be recorded as "this wallet has no
//! funder", because that is the one bucket a privacy measurement most wants to be
//! large. [`Census`] separates our failures from the chain's facts and refuses to
//! publish a headline when we caused too many of them.
//!
//! ## Disanalogy with the neighbouring measurement in this bounty
//!
//! `solanabr/mirror-pool` PR #5 brackets and bootstraps `ρ = 2^{−H(C)}`, the
//! *fraction* of nominal k that survives, precisely because ρ is independent of
//! `k` and therefore comparable across pools of different sizes. This crate's
//! headline is `effective_k = 2^{H(X|C)}`, a member count, which is **not**
//! k-independent: two samples of different sizes cannot be compared by it. The
//! bootstrap here holds `n` fixed inside every replicate, so the interval is a
//! statement about *this* sample size and nothing else. Reading an effective-k
//! interval across two pools of different `n` is the mistake ρ exists to avoid,
//! and this crate does not do that comparison.

use crate::{effective_k, EffectiveK};
use crate::rng::SplitMix64;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// outcomes and the census
// ---------------------------------------------------------------------------

/// Why one member's backward walk produced no class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// The bounded walk (depth 3, SOL only, capped fan-out) reached no hub. This
    /// says something about the *bound*, not only about the wallet: a deeper or
    /// SPL-aware trace can only merge this wallet into a rooted class, never the
    /// reverse. `docs/EFFECTIVE_K.md` states the same limit in prose; here it is
    /// a value the arithmetic can act on.
    NoOriginWithinBound,
    /// The per-target node or transaction budget ran out before the walk
    /// terminated. A budget limit, never a finding.
    TraceBudgetExhausted,
    /// An RPC error, a 429, or a timeout while tracing this member. **Ours, not
    /// the chain's.** These members leave the distribution entirely rather than
    /// inflating the unresolved bucket.
    RpcFailure,
}

impl UnresolvedReason {
    /// Whether the outcome says anything about the wallet as opposed to about our
    /// own budget or infrastructure.
    ///
    /// Nothing here returns `true`. That is deliberate and it is the honest
    /// reading of this tracer: `NoOriginWithinBound` is produced by a walk capped
    /// at depth 3 with 14 nodes and SOL transfers only, so "no origin" always
    /// means "none within the bound we could afford".
    pub fn is_evidence(self) -> bool {
        false
    }

    /// Whether the outcome is a failure of ours rather than a property of the
    /// chain. Only these are excluded from the measured population.
    pub fn is_our_failure(self) -> bool {
        matches!(self, UnresolvedReason::RpcFailure)
    }
}

/// The end state of tracing one member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberOutcome {
    /// Classified: the provenance class the partition groups on.
    Resolved { class: String },
    Unresolved { reason: UnresolvedReason },
}

/// A count of every terminal state in a run. No "other" bucket, because an
/// "other" bucket is where an unaccounted failure hides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Census {
    pub resolved: usize,
    pub no_origin_within_bound: usize,
    pub trace_budget_exhausted: usize,
    pub rpc_failure: usize,
}

/// Above this share of members lost to our own RPC, a run refuses to publish a
/// headline: one in a hundred.
///
/// A hard gate rather than a printed warning, because a warning above a number
/// gets dropped when the number is quoted.
pub const MAX_FAILURE_RATE: f64 = 0.01;

impl Census {
    pub fn record(&mut self, outcome: &MemberOutcome) {
        match outcome {
            MemberOutcome::Resolved { .. } => self.resolved += 1,
            MemberOutcome::Unresolved { reason } => match reason {
                UnresolvedReason::NoOriginWithinBound => self.no_origin_within_bound += 1,
                UnresolvedReason::TraceBudgetExhausted => self.trace_budget_exhausted += 1,
                UnresolvedReason::RpcFailure => self.rpc_failure += 1,
            },
        }
    }

    pub fn of(outcomes: &[MemberOutcome]) -> Self {
        let mut c = Census::default();
        for o in outcomes {
            c.record(o);
        }
        c
    }

    /// Every member the run attempted, failures included.
    pub fn attempted(&self) -> usize {
        self.resolved + self.no_origin_within_bound + self.trace_budget_exhausted + self.rpc_failure
    }

    /// Members whose outcome says something about the chain: everything except
    /// our own RPC failures.
    pub fn measurable(&self) -> usize {
        self.attempted() - self.rpc_failure
    }

    pub fn failure_rate(&self) -> f64 {
        let a = self.attempted();
        if a == 0 {
            return 0.0;
        }
        self.rpc_failure as f64 / a as f64
    }

    /// Whether a headline may be published from this run at all.
    pub fn may_publish(&self) -> bool {
        self.attempted() > 0 && self.failure_rate() <= MAX_FAILURE_RATE
    }

    /// The line that must accompany any figure from this run.
    pub fn summary(&self) -> String {
        format!(
            "attempted {} | resolved {} | unresolved-within-bound {} | budget-unresolved {} \
             | rpc failures {} ({:.2}%)",
            self.attempted(),
            self.resolved,
            self.no_origin_within_bound,
            self.trace_budget_exhausted,
            self.rpc_failure,
            self.failure_rate() * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// the bracket
// ---------------------------------------------------------------------------

/// The two readings of a run's unresolved members, computed exactly.
///
/// `upper` merges every unresolved member into one shared class: the reading
/// `docs/EFFECTIVE_K.md` published, and the most favourable one available.
/// `lower` splits them into singletons: the least favourable. Neither is known to
/// be true, so both are reported.
#[derive(Clone, Debug, PartialEq)]
pub struct Bracket {
    /// Unresolved merged into one class — the favourable reading.
    pub upper: EffectiveK,
    /// Unresolved split into singletons — the adversarial reading.
    pub lower: EffectiveK,
    pub resolved: usize,
    /// Unresolved members, excluding RPC failures: those are ours and belong to
    /// neither reading.
    pub unresolved: usize,
}

/// Below this share of resolved members, the two readings are far enough apart
/// that quoting either one reports the sampling budget rather than the pool.
pub const MIN_RESOLVED_FRACTION: f64 = 0.5;

/// And below this many resolved members the fraction itself is noise: 4 of 6 is
/// a majority and still nothing.
pub const MIN_RESOLVED_MEMBERS: usize = 8;

/// Whether a run's headline may be published, and if not, why in one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Publish,
    Refuse { reason: String },
}

impl Gate {
    pub fn publishes(&self) -> bool {
        matches!(self, Gate::Publish)
    }
}

impl Bracket {
    /// Build from the resolved class histogram plus a count of unresolved
    /// members. `unresolved` must exclude RPC failures.
    pub fn new(resolved_class_sizes: &[usize], unresolved: usize) -> Option<Bracket> {
        let resolved: usize = resolved_class_sizes.iter().sum();
        if resolved + unresolved == 0 || resolved_class_sizes.contains(&0) {
            return None;
        }

        let mut merged: Vec<usize> = resolved_class_sizes.to_vec();
        if unresolved > 0 {
            merged.push(unresolved);
        }
        let mut split: Vec<usize> = resolved_class_sizes.to_vec();
        split.extend(std::iter::repeat_n(1, unresolved));

        Some(Bracket {
            upper: effective_k(&merged),
            lower: effective_k(&split),
            resolved,
            unresolved,
        })
    }

    /// Build from per-member outcomes. RPC failures are dropped rather than
    /// counted as unresolved.
    pub fn from_outcomes(outcomes: &[MemberOutcome]) -> Option<Bracket> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut unresolved = 0usize;
        for o in outcomes {
            match o {
                MemberOutcome::Resolved { class } => *counts.entry(class.as_str()).or_insert(0) += 1,
                MemberOutcome::Unresolved { reason } => {
                    if !reason.is_our_failure() {
                        unresolved += 1;
                    }
                }
            }
        }
        let sizes: Vec<usize> = counts.into_values().collect();
        Bracket::new(&sizes, unresolved)
    }

    pub fn measured(&self) -> usize {
        self.resolved + self.unresolved
    }

    pub fn resolved_fraction(&self) -> f64 {
        let m = self.measured();
        if m == 0 {
            0.0
        } else {
            self.resolved as f64 / m as f64
        }
    }

    /// How many members the bracket spans, in members. The width of what we do
    /// not know.
    pub fn width(&self) -> f64 {
        self.upper.effective - self.lower.effective
    }

    /// Whether the sample supports quoting a single number.
    pub fn is_informative(&self) -> bool {
        self.resolved >= MIN_RESOLVED_MEMBERS
            && self.resolved_fraction() >= MIN_RESOLVED_FRACTION
    }

    /// The informativeness gate, with the refusal spelled out. Combined with the
    /// census so one call decides whether a run publishes.
    pub fn gate(&self, census: &Census) -> Gate {
        if !census.may_publish() {
            return Gate::Refuse {
                reason: format!(
                    "{} of {} members lost to our own RPC ({:.1}%, limit {:.1}%): the unresolved \
                     bucket would be our making, not the pool's",
                    census.rpc_failure,
                    census.attempted(),
                    census.failure_rate() * 100.0,
                    MAX_FAILURE_RATE * 100.0
                ),
            };
        }
        if self.resolved < MIN_RESOLVED_MEMBERS {
            return Gate::Refuse {
                reason: format!(
                    "only {} members resolved to an origin (minimum {}): too few to quote a number",
                    self.resolved, MIN_RESOLVED_MEMBERS
                ),
            };
        }
        if self.resolved_fraction() < MIN_RESOLVED_FRACTION {
            return Gate::Refuse {
                reason: format!(
                    "{} of {} members ({:.0}%) reached an origin, under the {:.0}% floor: \
                     effective-k spans {:.1}…{:.1} and the span is the trace bound, not the pool",
                    self.resolved,
                    self.measured(),
                    self.resolved_fraction() * 100.0,
                    MIN_RESOLVED_FRACTION * 100.0,
                    self.lower.effective,
                    self.upper.effective
                ),
            };
        }
        Gate::Publish
    }
}

// ---------------------------------------------------------------------------
// the bootstrap interval
// ---------------------------------------------------------------------------

/// The spread of the resampled estimator, and the estimate it was resampled from.
///
/// **Not a confidence interval, and not guaranteed to contain `point`.** It is
/// the 2.5th-to-97.5th percentile range of effective-k over bootstrap replicates.
/// Under a heavy tail — one crowd plus many singletons, which is the shape every
/// run here lands in — resampling drops singleton classes about 37% of the time,
/// which raises the estimator, so the whole range can sit above the original
/// estimate. That is a property of the population, not an arithmetic error; the
/// shift is reported as [`Interval::resampling_bias`] rather than hidden inside
/// the range.
///
/// A second bias is **not** fixed here and moves the same way: plug-in entropy
/// from counts understates `H(C)` at small `n`, and by the chain rule
/// `H(X|C) = log2 K − H(C)` that overstates `H(X|C)` and therefore effective-k.
/// A bootstrap resamples the same estimator, so its range is centred on the
/// biased value. Every effective-k this crate reports is plausibly optimistic,
/// and correcting it needs a different estimator (Miller–Madow, or a
/// coverage-adjusted family) which this crate does not implement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Interval {
    /// The estimate from the sample as drawn.
    pub point: f64,
    pub lo: f64,
    pub hi: f64,
    /// Mean of the replicates. Its distance from `point` is the resampling bias.
    pub mean: f64,
    pub replicates: usize,
    pub seed: u64,
}

impl Interval {
    pub fn width(&self) -> f64 {
        self.hi - self.lo
    }

    /// `mean − point`: how far resampling moves the estimator. Positive under a
    /// heavy tail, and its size is a tail diagnostic.
    pub fn resampling_bias(&self) -> f64 {
        self.mean - self.point
    }

    pub fn contains_point(&self) -> bool {
        self.lo <= self.point && self.point <= self.hi
    }
}

/// Replicates behind every published interval. Each is O(n); 10,000 keeps the
/// percentiles stable to about three decimals on a sample of 30.
pub const DEFAULT_REPLICATES: usize = 10_000;

/// The fixed seed every published interval is computed at, so a reader
/// recomputing a number gets *our* number and not merely a similar one.
pub const DEFAULT_SEED: u64 = 0x7269_7665_7272_756E; // "riverrun" in ascii

fn class_indices(labels: &[String]) -> (Vec<usize>, usize) {
    let mut index: BTreeMap<&str, usize> = BTreeMap::new();
    let mut out = Vec::with_capacity(labels.len());
    for l in labels {
        let next = index.len();
        let id = *index.entry(l.as_str()).or_insert(next);
        out.push(id);
    }
    let classes = index.len();
    (out, classes)
}

/// One replicate: resample `n` members with replacement, recompute effective-k.
fn replicate(members: &[usize], classes: usize, rng: &mut SplitMix64) -> f64 {
    let n = members.len();
    let mut counts = vec![0usize; classes];
    for _ in 0..n {
        counts[members[rng.below(n)]] += 1;
    }
    // A class no resampled member landed in is absent from the replicate, not a
    // class of size zero.
    let sizes: Vec<usize> = counts.into_iter().filter(|&c| c > 0).collect();
    effective_k(&sizes).effective
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = (q * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// A 95% percentile range for effective-k over the draw of members.
///
/// `labels` is one class label per member of the partition being reported — for a
/// bracketed run that is the *upper* reading, where the unresolved share one
/// label. `None` for an empty sample.
pub fn effective_k_interval(labels: &[String], replicates: usize, seed: u64) -> Option<Interval> {
    if labels.is_empty() || replicates == 0 {
        return None;
    }
    let (members, classes) = class_indices(labels);
    let mut sizes = vec![0usize; classes];
    for &m in &members {
        sizes[m] += 1;
    }
    let point = effective_k(&sizes).effective;

    let mut rng = SplitMix64::new(seed);
    let mut draws: Vec<f64> = Vec::with_capacity(replicates);
    for _ in 0..replicates {
        draws.push(replicate(&members, classes, &mut rng));
    }
    draws.sort_by(|a, b| a.partial_cmp(b).expect("effective-k is never NaN"));
    let mean = draws.iter().sum::<f64>() / draws.len() as f64;

    Some(Interval {
        point,
        lo: percentile(&draws, 0.025),
        hi: percentile(&draws, 0.975),
        mean,
        replicates: draws.len(),
        seed,
    })
}

/// The member labels of a bracket's favourable (upper) reading: the resolved
/// classes as they were measured, plus one shared label for the unresolved.
/// Convenience for feeding [`effective_k_interval`] from a histogram.
pub fn upper_reading_labels(resolved_class_sizes: &[usize], unresolved: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(resolved_class_sizes.iter().sum::<usize>() + unresolved);
    for (i, &n) in resolved_class_sizes.iter().enumerate() {
        for _ in 0..n {
            out.push(format!("class{i}"));
        }
    }
    for _ in 0..unresolved {
        out.push("rootless".to_string());
    }
    out
}

#[cfg(test)]
mod census_tests {
    use super::*;

    fn resolved(c: &str) -> MemberOutcome {
        MemberOutcome::Resolved { class: c.to_string() }
    }
    fn unresolved(r: UnresolvedReason) -> MemberOutcome {
        MemberOutcome::Unresolved { reason: r }
    }

    #[test]
    fn an_rpc_failure_is_never_evidence_and_leaves_the_distribution() {
        assert!(UnresolvedReason::RpcFailure.is_our_failure());
        for r in [
            UnresolvedReason::NoOriginWithinBound,
            UnresolvedReason::TraceBudgetExhausted,
            UnresolvedReason::RpcFailure,
        ] {
            assert!(!r.is_evidence(), "{r:?}: a bounded walk never proves absence");
        }
        let c = Census::of(&[
            resolved("hubA"),
            unresolved(UnresolvedReason::NoOriginWithinBound),
            unresolved(UnresolvedReason::RpcFailure),
        ]);
        assert_eq!(c.attempted(), 3);
        assert_eq!(c.measurable(), 2, "our failure is not part of the population");
    }

    #[test]
    fn a_run_that_lost_too_many_members_to_rpc_refuses_to_publish() {
        let mut c = Census::default();
        for _ in 0..99 {
            c.record(&resolved("hubA"));
        }
        c.record(&unresolved(UnresolvedReason::RpcFailure));
        assert!((c.failure_rate() - 0.01).abs() < 1e-12);
        assert!(c.may_publish(), "1 in 100 is exactly at the limit");

        c.record(&unresolved(UnresolvedReason::RpcFailure));
        assert!(!c.may_publish(), "2 in 101 is over it");
    }

    #[test]
    fn an_empty_run_publishes_nothing() {
        assert!(!Census::default().may_publish());
    }

    #[test]
    fn the_summary_names_the_failures_as_their_own_number() {
        let c = Census::of(&[resolved("a"), unresolved(UnresolvedReason::RpcFailure)]);
        let s = c.summary();
        assert!(s.contains("rpc failures 1"), "{s}");
        assert!(s.contains("resolved 1"), "{s}");
    }
}

#[cfg(test)]
mod bracket_tests {
    use super::*;

    #[test]
    fn the_bracket_spans_both_readings_and_the_merge_is_the_favourable_one() {
        // Six resolved in two classes of three, six unresolved.
        let b = Bracket::new(&[3, 3], 6).unwrap();
        assert_eq!(b.upper.advertised, 12);
        assert_eq!(b.lower.advertised, 12);
        assert_eq!(b.upper.classes, 3, "merged: 3, 3, 6");
        assert_eq!(b.lower.classes, 8, "split: 3, 3, and six singletons");
        assert!(
            b.upper.effective > b.lower.effective,
            "merging the unresolved must read more favourably: {} vs {}",
            b.upper.effective,
            b.lower.effective
        );
        assert!(b.width() > 0.0);
    }

    #[test]
    fn with_nothing_unresolved_the_bracket_collapses_to_a_point() {
        let b = Bracket::new(&[5, 3, 2], 0).unwrap();
        assert_eq!(b.upper, b.lower);
        assert!((b.width() - 0.0).abs() < 1e-12);
    }

    #[test]
    fn an_all_unresolved_run_brackets_the_whole_range() {
        // Nothing resolved: the reading is either one crowd of 20 or 20 singletons.
        let b = Bracket::new(&[], 20).unwrap();
        assert!((b.upper.effective - 20.0).abs() < 1e-9);
        assert!((b.lower.effective - 1.0).abs() < 1e-9);
        assert_eq!(b.resolved, 0);
    }

    #[test]
    fn rpc_failures_are_excluded_from_the_unresolved_bucket() {
        let outcomes = vec![
            MemberOutcome::Resolved { class: "hubA".into() },
            MemberOutcome::Resolved { class: "hubA".into() },
            MemberOutcome::Unresolved { reason: UnresolvedReason::NoOriginWithinBound },
            MemberOutcome::Unresolved { reason: UnresolvedReason::RpcFailure },
        ];
        let b = Bracket::from_outcomes(&outcomes).unwrap();
        assert_eq!(b.resolved, 2);
        assert_eq!(b.unresolved, 1, "the RPC failure is ours, not the pool's");
        assert_eq!(b.measured(), 3);
    }

    #[test]
    fn a_mostly_unresolved_sample_is_refused_by_the_gate() {
        // Eleven resolved singletons, nineteen unresolved: the shape of the run
        // published in docs/EFFECTIVE_K.md.
        let b = Bracket::new(&[1; 11], 19).unwrap();
        assert!(!b.is_informative(), "11 of 30 is 37%, under the 50% floor");
        let census = Census { resolved: 11, no_origin_within_bound: 19, ..Census::default() };
        let gate = b.gate(&census);
        assert!(!gate.publishes());
        match gate {
            Gate::Refuse { reason } => {
                assert!(reason.contains("37%"), "the refusal must carry the number: {reason}");
            }
            Gate::Publish => unreachable!(),
        }
    }

    #[test]
    fn a_majority_resolved_sample_passes_the_gate() {
        let b = Bracket::new(&[4, 4, 4], 3).unwrap();
        assert!(b.is_informative());
        let census = Census { resolved: 12, no_origin_within_bound: 3, ..Census::default() };
        assert!(b.gate(&census).publishes());
    }

    #[test]
    fn a_tiny_but_fully_resolved_sample_is_still_refused() {
        // 4 of 4 is 100% resolved and still nothing: the floor on the count is
        // what stops a two-member run from publishing a clean-looking number.
        let b = Bracket::new(&[2, 2], 0).unwrap();
        assert!(b.resolved_fraction() > 0.99);
        assert!(!b.is_informative(), "4 members is under the {MIN_RESOLVED_MEMBERS} floor");
        let census = Census { resolved: 4, ..Census::default() };
        match b.gate(&census) {
            Gate::Refuse { reason } => assert!(reason.contains("minimum 8"), "{reason}"),
            Gate::Publish => panic!("4 resolved members must not publish"),
        }
    }

    #[test]
    fn the_failure_gate_outranks_the_informativeness_gate() {
        // A run that would otherwise publish, wrecked by our own RPC.
        let b = Bracket::new(&[4, 4, 4], 3).unwrap();
        let census = Census {
            resolved: 12,
            no_origin_within_bound: 3,
            rpc_failure: 5,
            ..Census::default()
        };
        match b.gate(&census) {
            Gate::Refuse { reason } => assert!(reason.contains("our own RPC"), "{reason}"),
            Gate::Publish => panic!("25% RPC loss must block the headline"),
        }
    }

    #[test]
    fn a_degenerate_histogram_is_refused_rather_than_coped_with() {
        assert!(Bracket::new(&[], 0).is_none());
        assert!(Bracket::new(&[3, 0, 2], 1).is_none());
    }
}

#[cfg(test)]
mod interval_tests {
    use super::*;

    fn labels(spec: &[(&str, usize)]) -> Vec<String> {
        let mut out = Vec::new();
        for (name, n) in spec {
            for _ in 0..*n {
                out.push((*name).to_string());
            }
        }
        out
    }

    #[test]
    fn one_class_has_no_sampling_spread() {
        let i = effective_k_interval(&labels(&[("hubA", 40)]), 500, DEFAULT_SEED).unwrap();
        assert!((i.point - 40.0).abs() < 1e-9);
        assert!((i.lo - 40.0).abs() < 1e-9);
        assert!((i.hi - 40.0).abs() < 1e-9);
    }

    #[test]
    fn the_interval_is_reproducible_from_its_seed() {
        let l = labels(&[("a", 12), ("b", 9), ("c", 4), ("d", 1)]);
        let x = effective_k_interval(&l, 1_000, DEFAULT_SEED).unwrap();
        let y = effective_k_interval(&l, 1_000, DEFAULT_SEED).unwrap();
        assert_eq!(x, y, "same sample, same seed, same bytes");
        let z = effective_k_interval(&l, 1_000, DEFAULT_SEED ^ 1).unwrap();
        // The percentiles land on a discrete set of replicate values and can
        // coincide across seeds; the replicate mean cannot, so it is what pins
        // that a different seed actually redrew the members.
        assert_ne!(x.mean, z.mean, "a different seed must actually resample");
        assert_eq!(x.point, z.point, "the point estimate is the sample, not the draw");
    }

    #[test]
    fn a_smaller_sample_gives_a_wider_interval() {
        let big = labels(&[("a", 40), ("b", 30), ("c", 20), ("d", 10)]);
        let small = labels(&[("a", 4), ("b", 3), ("c", 2), ("d", 1)]);
        let wide = effective_k_interval(&small, 4_000, DEFAULT_SEED).unwrap();
        let tight = effective_k_interval(&big, 4_000, DEFAULT_SEED).unwrap();
        // Widths are in members, so normalise by the sample size before comparing.
        let rel = |i: &Interval, n: usize| i.width() / n as f64;
        assert!(
            rel(&wide, 10) > rel(&tight, 100),
            "small sample {:.3} not relatively wider than large {:.3}",
            rel(&wide, 10),
            rel(&tight, 100)
        );
    }

    #[test]
    fn a_crowded_population_resamples_close_to_its_estimate() {
        let l = labels(&[("a", 20), ("b", 10), ("c", 5), ("d", 5)]);
        let i = effective_k_interval(&l, 2_000, DEFAULT_SEED).unwrap();
        assert!(i.contains_point(), "point {} outside [{}, {}]", i.point, i.lo, i.hi);
        assert!(
            i.resampling_bias().abs() / i.point < 0.05,
            "crowded classes should barely shift: bias {} on {}",
            i.resampling_bias(),
            i.point
        );
    }

    #[test]
    fn a_heavy_tail_biases_the_estimate_upward_under_resampling() {
        // One crowd plus twenty-four singletons: the shape of every real run here.
        // Resampling drops a singleton class ~37% of the time, which moves its
        // member into some other class and raises effective-k. The bias is a tail
        // diagnostic, so it is asserted rather than assumed.
        let mut spec: Vec<(String, usize)> = vec![("crowd".to_string(), 6)];
        for i in 0..24 {
            spec.push((format!("solo{i}"), 1));
        }
        let l: Vec<String> = spec
            .iter()
            .flat_map(|(n, c)| std::iter::repeat_n(n.clone(), *c))
            .collect();
        let i = effective_k_interval(&l, 4_000, DEFAULT_SEED).unwrap();
        assert!(
            i.resampling_bias() > 0.0,
            "a heavy tail must bias effective-k upward, got {}",
            i.resampling_bias()
        );
    }

    #[test]
    fn an_empty_sample_yields_nothing() {
        assert!(effective_k_interval(&[], 100, DEFAULT_SEED).is_none());
        assert!(effective_k_interval(&labels(&[("a", 3)]), 0, DEFAULT_SEED).is_none());
    }

    #[test]
    fn the_upper_reading_labels_reproduce_the_bracket_ceiling() {
        let b = Bracket::new(&[1; 11], 19).unwrap();
        let l = upper_reading_labels(&[1; 11], 19);
        assert_eq!(l.len(), 30);
        let i = effective_k_interval(&l, 200, DEFAULT_SEED).unwrap();
        assert!(
            (i.point - b.upper.effective).abs() < 1e-9,
            "the interval's point must be the bracket's upper reading: {} vs {}",
            i.point,
            b.upper.effective
        );
    }
}
