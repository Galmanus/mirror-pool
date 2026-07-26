//! The repeated-use bound: how a *persistent* identity erodes across its uses.
//!
//! The [`effective_k`](crate::effective_k) ruler scores a **single** action. A
//! riverrun-ID identity is one secret used **repeatedly** — `shape` across contexts,
//! `turn` across cycles. Its pseudonyms are cryptographically unlinkable, but a
//! persistent *quasi-identifier* rides underneath every use: the funding-provenance
//! origin, which recurs and is public. An adversary links a user's actions across
//! contexts by that origin (not the pseudonym) and **intersects** the candidate sets —
//! the classic intersection / statistical-disclosure attack.
//!
//! This module measures that erosion. It is deterministic and offline, and it reduces
//! to the single-shot ruler at `n = 1`. Design and proofs:
//! `docs/REPEATED_USE_ANONYMITY.md`.

use std::collections::HashSet;

/// One use of a persistent identity: the set of population members whose observable
/// features are consistent with the actor in this context (the true holder is always
/// among them). Its size is the single-shot candidate count for this use.
#[derive(Clone, Debug)]
pub struct Use {
    /// The context `θ` this use happened in (a dApp, a round) — for labelling only.
    pub context: u64,
    /// Population member ids consistent with the observation in this context.
    pub candidates: Vec<u32>,
}

impl Use {
    pub fn new(context: u64, candidates: impl IntoIterator<Item = u32>) -> Self {
        Use { context, candidates: candidates.into_iter().collect() }
    }
}

/// The erosion curve of a persistent identity across its uses.
#[derive(Clone, Debug, PartialEq)]
pub struct Erosion {
    /// `k_eff^(1..n)`: the identity's anonymity after each use — the size of the
    /// running intersection of candidate sets. Monotone non-increasing.
    pub k_eff: Vec<f64>,
    /// Cumulative leak `Σε = log2(|U|) − log2(k_eff^(i))` after each use, in bits.
    pub spent_bits: Vec<f64>,
    /// The budget `log2(|U| / k_min)`: the identity is spent once `spent_bits` crosses it.
    pub budget_bits: f64,
    /// The first use index (0-based) whose `k_eff` drops below `k_min` — you should
    /// `turn` (and re-provenance) *before* performing it. `None` if the floor holds
    /// across every use.
    pub rotate_before: Option<usize>,
}

/// Measure how a persistent identity erodes across `uses`, against a `population` of
/// size `|U|`, holding an anonymity floor `k_min`.
///
/// `k_eff^(i)` is the size of the running intersection `S_i = ∩_{j≤i} candidates_j`:
/// the number of population members still indistinguishable from the holder after `i`
/// uses. Because the holder is in every candidate set, the intersection never empties
/// under a consistent transcript; a contradictory transcript (disjoint sets) reports
/// `k_eff = 0`, i.e. fully identified.
pub fn repeated_use_effective_k(population: usize, uses: &[Use], k_min: f64) -> Erosion {
    let budget_bits = if population as f64 > k_min && k_min > 0.0 {
        (population as f64 / k_min).log2()
    } else {
        0.0
    };

    let mut k_eff = Vec::with_capacity(uses.len());
    let mut spent_bits = Vec::with_capacity(uses.len());
    let mut rotate_before = None;

    let mut surviving: Option<HashSet<u32>> = None;
    for (i, u) in uses.iter().enumerate() {
        let this: HashSet<u32> = u.candidates.iter().copied().collect();
        surviving = Some(match surviving.take() {
            None => this,
            Some(prev) => prev.intersection(&this).copied().collect(),
        });
        let k = surviving.as_ref().map(|s| s.len()).unwrap_or(0) as f64;
        k_eff.push(k);

        // Σε = log2(|U|) − log2(k): the leak accumulated from full population to here.
        let spent = if k >= 1.0 && population > 0 {
            (population as f64).log2() - k.log2()
        } else {
            (population.max(1) as f64).log2()
        };
        spent_bits.push(spent);

        if rotate_before.is_none() && k < k_min {
            rotate_before = Some(i);
        }
    }

    Erosion { k_eff, spent_bits, budget_bits, rotate_before }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduces_to_the_single_shot_ruler_at_one_use() {
        // A single use of a 6-member class in a pool of 30: the identity's anonymity
        // is exactly its class size, matching the single-shot per-actor count.
        let uses = [Use::new(1, 0..6)];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        assert_eq!(e.k_eff, vec![6.0]);
        assert_eq!(e.rotate_before, None, "6 >= 4, safe for one use");
    }

    #[test]
    fn intersection_is_monotone_non_increasing() {
        // Nested candidate sets that all contain the holder (id 0): 6 -> 3 -> 1.
        let uses = [
            Use::new(1, 0..6),        // {0,1,2,3,4,5}
            Use::new(2, 0..3),        // {0,1,2}
            Use::new(3, [0u32]),      // {0}
        ];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        assert_eq!(e.k_eff, vec![6.0, 3.0, 1.0], "erosion never increases");
    }

    #[test]
    fn the_worked_example_fires_rotation_before_the_breaching_use() {
        // The doc's worked example: floor 4, budget = log2(30/4) ~= 2.907 bits.
        // k_eff = 6 (ok), 3 (< 4 -> breach at use index 1), 1.
        let uses = [Use::new(1, 0..6), Use::new(2, 0..3), Use::new(3, [0u32])];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        assert!((e.budget_bits - (30.0f64 / 4.0).log2()).abs() < 1e-9);
        assert_eq!(e.rotate_before, Some(1), "turn before the second use, which breaches the floor");
        // the leak crosses the budget exactly when k_eff falls under the floor
        assert!(e.spent_bits[1] > e.budget_bits, "budget blown at use 1 (0-based)");
        assert!(e.spent_bits[0] < e.budget_bits, "still within budget after the first use");
    }

    #[test]
    fn a_wide_identity_never_triggers_rotation() {
        // Every use leaves a large crowd: the identity is safe indefinitely.
        let uses = [Use::new(1, 0..20), Use::new(2, 0..18), Use::new(3, 0..16)];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        assert_eq!(e.rotate_before, None);
        assert!(e.k_eff.iter().all(|&k| k >= 4.0));
    }

    #[test]
    fn cumulative_leak_matches_the_closed_form() {
        // spent_bits[i] == log2(|U|) - log2(k_eff[i]) for every i.
        let uses = [Use::new(1, 0..6), Use::new(2, 0..3)];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        for i in 0..uses.len() {
            let expected = 30.0f64.log2() - e.k_eff[i].log2();
            assert!((e.spent_bits[i] - expected).abs() < 1e-9, "use {i}");
        }
    }

    #[test]
    fn a_contradictory_transcript_reads_as_identified() {
        // A wide first use (6 >= floor 4), then a disjoint set: the intersection empties,
        // so the identity reads as fully identified at the second use.
        let uses = [Use::new(1, 0..6), Use::new(2, [7u32, 8, 9])];
        let e = repeated_use_effective_k(30, &uses, 4.0);
        assert_eq!(e.k_eff, vec![6.0, 0.0]);
        assert_eq!(e.rotate_before, Some(1));
    }
}
