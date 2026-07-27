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

#[cfg(test)]
mod tests {
    use super::*;

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
