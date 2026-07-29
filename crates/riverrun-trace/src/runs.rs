//! The measured runs this repository publishes, as data rather than prose.
//!
//! `docs/EFFECTIVE_K.md` reports one live mainnet measurement in a table. A
//! reader cannot recompute anything from a table, and neither can a test. This
//! module carries the same run as a value, so the bracket, the interval and the
//! gate in [`crate::uncertainty`] all run against the number the repository
//! actually published — including when they refuse it.
//!
//! ## What is committed here, and what is not
//!
//! What is committed is the **class histogram** of the run: how many members, how
//! many classes, how large each class. That is enough to recompute every
//! statistic reported.
//!
//! What is **not** committed is the per-member evidence: the sampled depositor
//! addresses, the funding edges walked, the hub addresses reached. Those were
//! never written to disk, so this run cannot be re-derived from the chain by a
//! third party — only recomputed from the histogram. A reader who wants to check
//! the *tracing* rather than the *arithmetic* has to re-run
//! `riverrun audit <POOL> 30` against a live RPC and will get a different sample.
//! The neighbouring measurement in this bounty (`solanabr/mirror-pool` PR #5)
//! commits its raw per-member chains as JSON and is therefore checkable offline
//! in a way this run is not. That gap is real and named rather than papered over.
//!
//! The histogram itself is not a guess: `n = 30`, `12 classes`, `largest 19` has
//! exactly one solution, which [`the_published_histogram_is_forced`] proves.

use crate::uncertainty::{
    effective_k_interval, upper_reading_labels, Bracket, Census, Interval, DEFAULT_REPLICATES,
    DEFAULT_SEED,
};

/// One live measurement, reduced to what the arithmetic needs.
#[derive(Clone, Copy, Debug)]
pub struct MeasuredRun {
    /// Where it was published.
    pub source: &'static str,
    /// The pool program measured.
    pub pool: &'static str,
    /// Members sampled, failures included.
    pub sampled: usize,
    /// Class sizes of the members that reached an attributable origin.
    pub resolved_class_sizes: &'static [usize],
    /// Members whose bounded walk reached no origin. Not a class: a gap.
    pub unresolved: usize,
    /// Members lost to our own RPC. Excluded from the population entirely.
    pub rpc_failures: usize,
}

/// The run behind the headline "advertised k = 30, effective k = 6.5".
///
/// Privacy Cash, a live Tornado-style SOL pool on Solana mainnet, 30 sampled
/// depositors, of which 11 reached an attributable origin and each reached a
/// distinct one. The remaining 19 reached none within the bound and were reported
/// as a single "rootless" class — which is the bracket's **upper** reading, not a
/// measured class.
pub const PRIVACY_CASH_N30: MeasuredRun = MeasuredRun {
    source: "docs/EFFECTIVE_K.md",
    pool: "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD",
    sampled: 30,
    resolved_class_sizes: &[1; 11],
    unresolved: 19,
    rpc_failures: 0,
};

impl MeasuredRun {
    pub fn census(&self) -> Census {
        Census {
            resolved: self.resolved_class_sizes.iter().sum(),
            no_origin_within_bound: self.unresolved,
            trace_budget_exhausted: 0,
            rpc_failure: self.rpc_failures,
        }
    }

    pub fn bracket(&self) -> Bracket {
        Bracket::new(self.resolved_class_sizes, self.unresolved)
            .expect("a published run has a non-degenerate histogram")
    }

    /// The interval around the **upper** reading — the number that was published.
    /// Fixed replicates and fixed seed, so the range is reproducible byte for
    /// byte.
    pub fn interval(&self) -> Interval {
        let labels = upper_reading_labels(self.resolved_class_sizes, self.unresolved);
        effective_k_interval(&labels, DEFAULT_REPLICATES, DEFAULT_SEED)
            .expect("a published run has members")
    }

    /// One block, everything a quote of this run must carry with it.
    pub fn report(&self) -> String {
        let b = self.bracket();
        let i = self.interval();
        let c = self.census();
        let gate = b.gate(&c);
        let verdict = match &gate {
            crate::uncertainty::Gate::Publish => "PUBLISH".to_string(),
            crate::uncertainty::Gate::Refuse { reason } => format!("REFUSED — {reason}"),
        };
        format!(
            "{} ({} sampled)\n\
             {}\n\
             effective-k, unresolved merged (published) : {:.2}\n\
             effective-k, unresolved split (adversarial): {:.2}\n\
             bracket                                    : {:.2} … {:.2} members\n\
             95% resampling range of the merged reading : {:.2} … {:.2} \
             (bias {:+.2}, {} replicates, seed {:#018x})\n\
             gate                                       : {}",
            self.pool,
            self.sampled,
            c.summary(),
            b.upper.effective,
            b.lower.effective,
            b.lower.effective,
            b.upper.effective,
            i.lo,
            i.hi,
            i.resampling_bias(),
            i.replicates,
            i.seed,
            verdict
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uncertainty::Gate;

    /// The histogram in [`PRIVACY_CASH_N30`] is a transcription of three numbers
    /// published in `docs/EFFECTIVE_K.md` — 30 members, 12 classes, largest class
    /// 19 — and this checks the transcription is forced rather than chosen: the
    /// other 11 classes hold 11 members between them and no class may be empty,
    /// so every one of them holds exactly one.
    #[test]
    fn the_published_histogram_is_forced() {
        let published_members = 30;
        let published_classes = 12;
        let published_largest = 19;

        let rest_members = published_members - published_largest;
        let rest_classes = published_classes - 1;
        assert_eq!(rest_members, rest_classes, "11 members across 11 non-empty classes");

        let mut sizes: Vec<usize> = PRIVACY_CASH_N30.resolved_class_sizes.to_vec();
        sizes.push(PRIVACY_CASH_N30.unresolved);
        assert_eq!(sizes.iter().sum::<usize>(), published_members);
        assert_eq!(sizes.len(), published_classes);
        assert_eq!(sizes.iter().copied().max().unwrap(), published_largest);
    }

    /// The upper reading must reproduce what the document published: 2.69 bits of
    /// residual anonymity, an effective k of 6.5, worst case 1. If this drifts,
    /// either the metric changed or the document is stale.
    #[test]
    fn the_upper_reading_reproduces_the_published_numbers() {
        let b = PRIVACY_CASH_N30.bracket();
        assert_eq!(b.upper.advertised, 30);
        assert_eq!(b.upper.classes, 12);
        assert_eq!(b.upper.worst_case, 1);
        assert!(
            (b.upper.residual_bits - 2.690).abs() < 5e-4,
            "residual bits {} != published 2.69",
            b.upper.residual_bits
        );
        assert!(
            (b.upper.effective - 6.455).abs() < 5e-3,
            "effective k {} != published 6.5",
            b.upper.effective
        );
    }

    /// The finding this module exists for: the published 6.5 is the *ceiling* of
    /// the bracket, not its centre. If every unresolved member is in fact alone,
    /// the same run reads as an effective k of 1.
    #[test]
    fn the_published_number_is_the_ceiling_of_a_bracket_that_bottoms_out_at_one() {
        let b = PRIVACY_CASH_N30.bracket();
        assert!((b.lower.effective - 1.0).abs() < 1e-9, "lower {}", b.lower.effective);
        assert!((b.upper.effective - 6.455).abs() < 5e-3);
        assert!(b.width() > 5.4, "the span is most of the number: {:.2}", b.width());
    }

    /// And the gate refuses it. 11 of 30 members reached an origin, so the run
    /// does not support quoting a single effective k, and the tool says so rather
    /// than printing the favourable end.
    #[test]
    fn the_published_run_does_not_pass_this_crate_s_own_gate() {
        let b = PRIVACY_CASH_N30.bracket();
        let gate = b.gate(&PRIVACY_CASH_N30.census());
        match gate {
            Gate::Refuse { reason } => {
                assert!(reason.contains("37%"), "{reason}");
                assert!(reason.contains("1.0…6.5") || reason.contains("1.0…6.4"), "{reason}");
            }
            Gate::Publish => panic!("11 of 30 resolved must not publish a point estimate"),
        }
    }

    /// The interval is reproducible and its bias is positive, which is the tail
    /// signature: 11 of the 12 classes are singletons.
    #[test]
    fn the_interval_is_reproducible_and_shows_the_tail() {
        let a = PRIVACY_CASH_N30.interval();
        let b = PRIVACY_CASH_N30.interval();
        assert_eq!(a, b);
        assert_eq!(a.replicates, DEFAULT_REPLICATES);
        assert!(
            a.resampling_bias() > 0.0,
            "singleton-heavy classes bias the estimate upward: {}",
            a.resampling_bias()
        );
        assert!(a.lo < a.hi);
    }

    /// The report must never print a number without the bracket, the interval and
    /// the verdict beside it.
    #[test]
    fn the_report_carries_the_uncertainty_with_the_number() {
        let r = PRIVACY_CASH_N30.report();
        for expected in ["bracket", "95% resampling range", "gate", "REFUSED", "seed"] {
            assert!(r.contains(expected), "report missing {expected}:\n{r}");
        }
    }
}
