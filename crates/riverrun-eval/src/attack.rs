//! The clustering attacker.
//!
//! This is the adversary `riverrun` must defeat, modeled as the strongest
//! realistic version: it already holds an accurate behavioral profile of every
//! member (habitual relative timing and position size — the co-buy-timing and
//! sizing-fingerprint signals). Given a round's observed actions it recovers the
//! action→identity assignment by nearest-profile matching.
//!
//! The exact same attacker is run against both traces. Against the unprotected
//! trace the behavioral signals are present and it succeeds; against the
//! protected trace the signals are gone and it degrades to chance. We do not
//! weaken the attacker for the protected case — the *data* defeats it.

use crate::model::{Action, Population};

/// Feature scales for normalizing the two signals into a common cost. Chosen as
/// the spans of the population's habits so timing and sizing contribute
/// comparably.
const TIME_SCALE: f64 = 60.0;
const SIZE_SCALE: f64 = 900.0;

/// One member's behavioral profile as the attacker knows it.
#[derive(Clone, Copy, Debug)]
struct Profile {
    id: usize,
    /// Habitual timing offset, measured relative to the earliest actor (so it is
    /// comparable to a round's observed relative times without knowing the exact
    /// intent timestamp).
    relative_offset: f64,
    position_size: f64,
}

pub struct NearestProfileAttacker {
    profiles: Vec<Profile>,
}

impl NearestProfileAttacker {
    /// Build the attacker's profiles from the true population fingerprints — the
    /// strongest attacker: it knows every member's habits exactly.
    pub fn from_population(pop: &Population) -> Self {
        let min_offset = pop
            .members
            .iter()
            .map(|m| m.timing_offset)
            .fold(f64::INFINITY, f64::min);
        let profiles = pop
            .members
            .iter()
            .map(|m| Profile {
                id: m.id,
                relative_offset: m.timing_offset - min_offset,
                position_size: m.position_size,
            })
            .collect();
        Self { profiles }
    }

    /// Normalized distance between an observed action (given the round's timing
    /// reference) and a member profile.
    fn cost(&self, action: &Action, t_ref: f64, profile: &Profile) -> f64 {
        let rel_time = action.time - t_ref;
        let dt = (rel_time - profile.relative_offset).abs() / TIME_SCALE;
        let ds = (action.size - profile.position_size).abs() / SIZE_SCALE;
        dt + ds
    }

    /// The adversary's posterior belief (unnormalized `exp(-cost)` weights) that
    /// `action` was produced by each candidate identity in `candidate_ids`, given
    /// the round's timing reference `t_ref`.
    ///
    /// The weight uses the *same* normalized cost as attribution, so the scale is
    /// the population's measured habit span (`TIME_SCALE`, `SIZE_SCALE`), not a
    /// free temperature: this is the maximum-entropy posterior consistent with the
    /// expected normalized distance. The qualitative result (a leaky coordinator
    /// erodes anonymity, self-fill caps it) does not depend on the scale.
    pub fn posterior_for_action(
        &self,
        action: &Action,
        t_ref: f64,
        candidate_ids: &[usize],
    ) -> Vec<f64> {
        candidate_ids
            .iter()
            .map(|id| {
                let profile = self
                    .profiles
                    .iter()
                    .find(|p| p.id == *id)
                    .expect("candidate id must be a member of the population");
                (-self.cost(action, t_ref, profile)).exp()
            })
            .collect()
    }

    /// Recover the action→identity assignment for one round and return how many
    /// actions were attributed to their true initiator.
    ///
    /// Assignment is greedy minimum-cost over the full bijection: repeatedly take
    /// the cheapest unused (action, profile) pair. Deterministic, and a close
    /// approximation of optimal assignment for this cost.
    pub fn correct_attributions(&self, actions: &[Action]) -> usize {
        let k = actions.len();
        debug_assert_eq!(k, self.profiles.len());
        if k == 0 {
            return 0;
        }
        let t_ref = actions.iter().map(|a| a.time).fold(f64::INFINITY, f64::min);

        // All (cost, action_idx, profile_idx) triples, sorted ascending.
        let mut pairs: Vec<(f64, usize, usize)> = Vec::with_capacity(k * k);
        for (ai, a) in actions.iter().enumerate() {
            for (pi, p) in self.profiles.iter().enumerate() {
                pairs.push((self.cost(a, t_ref, p), ai, pi));
            }
        }
        pairs.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());

        let mut action_used = vec![false; k];
        let mut profile_used = vec![false; k];
        let mut assignment: Vec<Option<usize>> = vec![None; k]; // action -> profile id
        let mut assigned = 0usize;
        for (_, ai, pi) in pairs {
            if assigned == k {
                break;
            }
            if action_used[ai] || profile_used[pi] {
                continue;
            }
            action_used[ai] = true;
            profile_used[pi] = true;
            assignment[ai] = Some(self.profiles[pi].id);
            assigned += 1;
        }

        actions
            .iter()
            .zip(assignment.iter())
            .filter(|(a, assigned_id)| **assigned_id == Some(a.true_id))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Population, RoundIntent};
    use crate::rng::SplitMix64;

    #[test]
    fn attacker_beats_unprotected_but_not_protected() {
        let mut rng = SplitMix64::new(2024);
        let pop = Population::sample(8, &mut rng);
        let attacker = NearestProfileAttacker::from_population(&pop);

        let mut unprotected = 0usize;
        let mut protected = 0usize;
        let rounds = 500;
        for _ in 0..rounds {
            let intent = RoundIntent::sample(&mut rng);
            unprotected += attacker.correct_attributions(&pop.unprotected_trace(&intent, &mut rng));
            protected += attacker.correct_attributions(&pop.protected_trace(&intent, &mut rng));
        }
        let total = (rounds * 8) as f64;
        let unprotected_acc = unprotected as f64 / total;
        let protected_acc = protected as f64 / total;

        // Unprotected traces are highly attributable.
        assert!(
            unprotected_acc > 0.7,
            "unprotected accuracy {unprotected_acc} should be high"
        );
        // Protected traces collapse the attacker to roughly chance (1/8 = 0.125).
        assert!(
            protected_acc < 0.25,
            "protected accuracy {protected_acc} should be near chance"
        );
    }
}
