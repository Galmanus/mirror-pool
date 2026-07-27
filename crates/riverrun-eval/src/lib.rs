//! Adversarial evaluation harness for `riverrun`.
//!
//! The thesis of `riverrun` is that a *synchronized* round of *identical*
//! actions, submitted by keys unlinked from member commitments, strips the
//! behavioral signals modern chain-clustering relies on. This harness makes that
//! falsifiable: it builds a population of participants with distinct behavioral
//! fingerprints, generates two on-chain traces of the same intent — one
//! *unprotected* (each acts on their own habit) and one *protected* (the pool
//! fires them synchronized and identical) — then runs the **same** clustering
//! attacker against both and measures attribution accuracy.
//!
//! The expected result: unprotected traces are highly attributable (the
//! attacker recovers most of the action→identity mapping); protected traces
//! collapse the attacker to chance (`1/k`). Same attacker, same population — the
//! only difference is the pool. That contrast is the exhibit.
//!
//! Determinism: everything is driven by an explicit `splitmix64` seed, so runs
//! are reproducible and the numbers in the README can be regenerated exactly.

pub mod attack;
pub mod composition;
pub mod model;
pub mod rng;

use attack::NearestProfileAttacker;
use model::{Population, RoundIntent};

/// Result of one experiment: mean attribution accuracy over many rounds, for
/// both trace modes, plus the chance baseline.
#[derive(Clone, Copy, Debug)]
pub struct ExperimentResult {
    pub k: usize,
    pub rounds: usize,
    pub unprotected_accuracy: f64,
    pub protected_accuracy: f64,
    pub chance: f64,
}

/// Run the full experiment for a pool of `k` participants over `rounds` rounds.
///
/// For each round a fresh intent is drawn; both traces are generated from the
/// *same* intent and population so the comparison is apples-to-apples. The
/// attacker holds accurate per-identity behavioral profiles (the strongest
/// realistic attacker: it already knows each member's habits) and attempts to
/// recover the true action→identity assignment.
pub fn run_experiment(k: usize, rounds: usize, seed: u64) -> ExperimentResult {
    let mut rng = rng::SplitMix64::new(seed);
    let population = Population::sample(k, &mut rng);
    let attacker = NearestProfileAttacker::from_population(&population);

    let mut unprotected_hits = 0usize;
    let mut protected_hits = 0usize;
    let total = rounds * k;

    for _ in 0..rounds {
        let intent = RoundIntent::sample(&mut rng);

        let unprotected = population.unprotected_trace(&intent, &mut rng);
        let protected = population.protected_trace(&intent, &mut rng);

        unprotected_hits += attacker.correct_attributions(&unprotected);
        protected_hits += attacker.correct_attributions(&protected);
    }

    ExperimentResult {
        k,
        rounds,
        unprotected_accuracy: unprotected_hits as f64 / total as f64,
        protected_accuracy: protected_hits as f64 / total as f64,
        chance: 1.0 / k as f64,
    }
}

/// One row of the self-fill degradation exhibit: for an advertised pool of
/// `advertised_k`, how much anonymity survives when the adversary self-fills
/// `adversary_owned` of the slots.
#[derive(Clone, Copy, Debug)]
pub struct SelfFillRow {
    pub advertised_k: usize,
    pub adversary_owned: usize,
    pub effective_k: f64,
}

/// The honest degradation curve for a fully-protected round: sweep the adversary
/// share from owning none of the round to owning all but the target, and report
/// the effective anonymity the honest user actually gets at each share.
///
/// A perfectly synchronized identical round hides the honest user among the other
/// honest slots and no further, so effective-k is exactly the honest count
/// `advertised_k - adversary_owned`. The first row is the advertised `k`; the
/// last (`adversary_owned = advertised_k - 1`) is the floor every mix shares: 1.
pub fn self_fill_degradation(advertised_k: usize) -> Vec<SelfFillRow> {
    (0..advertised_k)
        .map(|adversary_owned| SelfFillRow {
            advertised_k,
            adversary_owned,
            effective_k: composition::effective_k_selffill(advertised_k, adversary_owned),
        })
        .collect()
}

/// Measure the effective anonymity an honest user actually gets from a single
/// round, composing two real erosions end to end: a **leaky coordinator** (a
/// fraction `leak` of each member's behavioral habit survives imperfect
/// synchronization) and **self-fill** (the adversary owns `adversary_owned` of
/// the `k` slots and subtracts them). The target is one honest member; the
/// adversary forms its posterior over the honest slots from the observed round
/// and the effective-k is `2^{H}` of that posterior.
///
/// `leak = 0` with `adversary_owned = 0` is the fully-protected round and returns
/// close to `k`; raising either erodes the number. This is the ruler of
/// \S self-fill and the behavioral harness, run as one measurement.
pub fn measure_leaky_round(
    k: usize,
    adversary_owned: usize,
    leak: f64,
    seed: u64,
) -> composition::RoundAnonymity {
    let mut rng = rng::SplitMix64::new(seed);
    let population = Population::sample(k, &mut rng);
    let attacker = NearestProfileAttacker::from_population(&population);
    let intent = RoundIntent::sample(&mut rng);
    let trace = population.leaky_protected_trace(&intent, leak, &mut rng);

    // self-fill: the adversary owns the last `adversary_owned` slots and subtracts
    // them, leaving the first h = k - a honest. The target is honest slot 0.
    let h = k.saturating_sub(adversary_owned);
    if h == 0 {
        return composition::RoundAnonymity { advertised_k: k, honest_count: 0, effective_k: 0.0 };
    }
    let honest_ids: Vec<usize> = population.members[..h].iter().map(|m| m.id).collect();
    let target_id = population.members[0].id;
    let target_action = trace
        .iter()
        .find(|a| a.true_id == target_id)
        .expect("the target's action is in the trace");
    // Timing reference: the earliest honest action. The adversary knows its own
    // self-filled slots, so it anchors on the honest ones it is trying to separate.
    let t_ref = trace
        .iter()
        .filter(|a| a.true_id < h)
        .map(|a| a.time)
        .fold(f64::INFINITY, f64::min);

    let posterior = attacker.posterior_for_action(target_action, t_ref, &honest_ids);
    composition::RoundAnonymity {
        advertised_k: k,
        honest_count: h,
        effective_k: composition::effective_k(&posterior),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fully_protected_leaky_round_realizes_near_full_k() {
        // leak = 0, no adversary: the observable is identity-independent, so the
        // posterior is near uniform over all k and effective-k is close to k.
        let r = measure_leaky_round(8, 0, 0.0, 12_345);
        assert_eq!(r.honest_count, 8);
        assert!(
            r.effective_k > 6.0,
            "a fully protected round of 8 should deliver near 8, got {}",
            r.effective_k
        );
    }

    #[test]
    fn self_fill_caps_the_leaky_round_at_the_honest_set() {
        // The adversary owns 5 of 8 slots; the honest user cannot exceed the 3 that
        // remain, whatever the coordinator does.
        let r = measure_leaky_round(8, 5, 0.0, 12_345);
        assert_eq!(r.honest_count, 3);
        assert!(r.effective_k <= 3.0 + 1e-9, "effective-k {} exceeds the honest set", r.effective_k);
    }

    #[test]
    fn self_fill_dominates_behavioral_leak_in_this_model() {
        // The honest, robust finding over many seeds (one seed is too noisy given
        // how small the leak effect is): an imperfect coordinator that leaks the
        // full habit barely moves the single-target posterior, while self-fill
        // erodes it strongly. Structural exposure dominates residual behavioral
        // signal here, which is why riverrun leads with the self-fill and
        // funding-graph floors rather than with behavioral noise.
        let n = 300u64;
        let mean = |a: usize, leak: f64| -> f64 {
            (0..n)
                .map(|s| measure_leaky_round(8, a, leak, 4_000 + s).effective_k)
                .sum::<f64>()
                / n as f64
        };
        let clean = mean(0, 0.0);
        let full_leak = mean(0, 1.0);
        let self_filled = mean(4, 0.0);
        // leak erodes anonymity, but only weakly (a few percent), not a collapse
        assert!(full_leak <= clean + 1e-9, "full leak must not raise anonymity: {full_leak} vs {clean}");
        assert!(full_leak > 0.8 * clean, "leak's effect is weak here, not a collapse: {full_leak} vs {clean}");
        // self-fill is the dominant axis: owning half the slots roughly halves it
        assert!(self_filled < 0.6 * clean, "self-fill must dominate: {self_filled} vs {clean}");
    }

    #[test]
    fn effective_k_stays_within_one_and_the_honest_set() {
        for leak in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let r = measure_leaky_round(8, 2, leak, 77);
            assert!(
                r.effective_k >= 1.0 - 1e-9 && r.effective_k <= r.honest_count as f64 + 1e-9,
                "effective-k {} left [1, {}] at leak {leak}",
                r.effective_k,
                r.honest_count
            );
        }
    }

    #[test]
    fn self_fill_degradation_runs_from_full_k_down_to_one() {
        let curve = self_fill_degradation(17);
        assert_eq!(curve.len(), 17);
        assert_eq!(curve[0].effective_k, 17.0, "no self-fill: the full advertised set");
        assert_eq!(
            curve.last().unwrap().effective_k,
            1.0,
            "adversary owns all but the target: the floor every mix shares"
        );
        // monotone non-increasing: more adversary slots never help the honest user
        for pair in curve.windows(2) {
            assert!(pair[1].effective_k <= pair[0].effective_k);
        }
    }
}
