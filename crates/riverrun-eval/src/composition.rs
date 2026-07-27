//! The **round-composition adversary**: what anonymity does the honest user
//! actually get when the adversary owns some of the round's slots?
//!
//! The behavioral harness (`model.rs`, `attack.rs`) answers "does a synchronized
//! identical round strip timing and sizing signals" and shows it collapses a
//! profiling attacker to chance `1/k`. But `1/k` is the *advertised* anonymity.
//! It silently assumes all `k` slots are independent honest participants.
//!
//! They are not, in general. An adversary can **self-fill**: submit their own
//! members into the same round (a Sybil, or a whale funding many notes). Every
//! slot they own is one they can subtract from the honest set. If a round of
//! `k = 17` has `a = 16` adversary slots, the one honest user is alone: the
//! adversary knows the other sixteen are theirs, so the "anonymity set" is a
//! single person. Effective-k is 1. This is not a flaw unique to `riverrun`; it
//! is the floor of every mix, and an honest tool must **measure** it rather than
//! advertise the gross count.
//!
//! This module composes two channels the honest user faces at once:
//!
//! 1. **self-fill** shrinks the anonymity set from the advertised `k` to the
//!    honest count `h = k - a`.
//! 2. within those `h` honest slots, any **residual behavioral signal** (an
//!    imperfectly synchronized round, or the funding-graph provenance the tracer
//!    measures) further concentrates the adversary's posterior below a uniform
//!    `1/h`.
//!
//! The reported number is Serjantov-Danezis effective-k, `2^{H(p)}`, over the
//! adversary's posterior `p` for the target among the honest slots. Shannon, not
//! min-entropy: min-entropy reports a single dominant class as effective-k 1 even
//! when the measurement found nothing to split on, which overstates exposure. We
//! report the average an adversary faces and surface the worst case separately.

/// Serjantov-Danezis effective anonymity set size: `2^{H(p)}` where `H` is the
/// Shannon entropy (in bits) of the adversary's posterior `p` over the
/// candidates for the target. A uniform posterior over `n` candidates gives `n`;
/// a point mass gives `1`.
///
/// The input need not be normalized; it is treated as unnormalized weights.
pub fn effective_k(weights: &[f64]) -> f64 {
    let total: f64 = weights.iter().filter(|w| **w > 0.0).sum();
    if total <= 0.0 {
        return 0.0;
    }
    // H(p) = -sum p_i log2 p_i, with the convention 0*log0 = 0.
    let mut entropy = 0.0;
    for &w in weights {
        if w > 0.0 {
            let p = w / total;
            entropy -= p * p.log2();
        }
    }
    entropy.exp2()
}

/// Effective-k of a fully-protected round of `k` slots of which `adversary_owned`
/// are self-filled by the adversary. With a perfectly synchronized identical
/// round the adversary's posterior over the `h = k - adversary_owned` honest
/// slots is uniform, so effective-k is `h` (and `1` when only the target is
/// honest, `0` when the adversary owns every slot).
pub fn effective_k_selffill(k: usize, adversary_owned: usize) -> f64 {
    k.saturating_sub(adversary_owned) as f64
}

/// The honest user's true anonymity, composing self-fill with a behavioral
/// residual over the honest slots.
///
/// `honest_posterior` is the adversary's relative belief (unnormalized weights)
/// that each honest slot is the target, as recovered from whatever signal
/// survives the round. A uniform vector means the round fully protected the
/// honest set; a concentrated vector means residual signal leaked. The length is
/// the honest count `h`; the advertised set was `advertised_k`.
#[derive(Clone, Debug)]
pub struct RoundAnonymity {
    pub advertised_k: usize,
    pub honest_count: usize,
    pub effective_k: f64,
}

/// Compose the two channels: shrink to the honest set, then apply the behavioral
/// residual within it. `effective_k` never exceeds `honest_count`, and
/// `honest_count` never exceeds `advertised_k`.
pub fn round_anonymity(advertised_k: usize, honest_posterior: &[f64]) -> RoundAnonymity {
    let honest_count = honest_posterior.len();
    // Shannon effective-k over the honest slots is bounded above by the support
    // size, which is at most honest_count: the composition can only lose
    // anonymity relative to a uniform honest set, never invent it.
    let effective_k = effective_k(honest_posterior);
    RoundAnonymity {
        advertised_k,
        honest_count,
        effective_k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn uniform_posterior_over_n_gives_effective_k_n() {
        // The whole point of Shannon effective-k: a flat posterior over n honest
        // candidates is worth exactly n.
        approx(effective_k(&[1.0; 5]), 5.0);
        approx(effective_k(&[0.25, 0.25, 0.25, 0.25]), 4.0);
    }

    #[test]
    fn a_point_mass_gives_effective_k_one() {
        // The adversary is certain: one honest candidate, fully exposed.
        approx(effective_k(&[1.0, 0.0, 0.0, 0.0]), 1.0);
    }

    #[test]
    fn effective_k_is_between_one_and_the_support_size() {
        // Any non-uniform, non-degenerate posterior sits strictly inside (1, n).
        let e = effective_k(&[0.5, 0.25, 0.25]);
        assert!(e > 1.0 && e < 3.0, "effective-k {e} must be inside (1, 3)");
    }

    #[test]
    fn no_self_fill_gives_the_full_advertised_set() {
        // a = 0: nobody is subtracted, the honest set is the whole round.
        approx(effective_k_selffill(17, 0), 17.0);
    }

    #[test]
    fn self_fill_shrinks_the_honest_set_one_for_one() {
        // Every adversary-owned slot is one the adversary subtracts.
        approx(effective_k_selffill(17, 5), 12.0);
    }

    #[test]
    fn a_whale_owning_all_but_one_collapses_effective_k_to_one() {
        // THE degradation an honest mix must report: k = 17, adversary owns 16,
        // the lone honest user is alone. Advertised 17, effective 1.
        approx(effective_k_selffill(17, 16), 1.0);
    }

    #[test]
    fn an_adversary_owning_every_slot_leaves_no_honest_set() {
        approx(effective_k_selffill(17, 17), 0.0);
    }

    #[test]
    fn effective_k_is_monotone_non_increasing_in_adversary_share() {
        let mut prev = f64::INFINITY;
        for a in 0..=17 {
            let e = effective_k_selffill(17, a);
            assert!(e <= prev + 1e-12, "effective-k rose from {prev} to {e} at a={a}");
            prev = e;
        }
    }

    #[test]
    fn a_fully_protected_honest_set_realizes_its_full_size() {
        // Uniform residual over 12 honest slots: the honest user gets all 12.
        let r = round_anonymity(17, &[1.0; 12]);
        assert_eq!(r.advertised_k, 17);
        assert_eq!(r.honest_count, 12);
        approx(r.effective_k, 12.0);
    }

    #[test]
    fn a_behavioral_residual_erodes_below_the_honest_set() {
        // Same 12 honest slots, but signal survived and concentrated the
        // adversary's belief. Effective-k must fall below the honest count.
        let mut post = vec![1.0; 12];
        post[0] = 8.0; // one slot looks much more like the target
        let r = round_anonymity(17, &post);
        assert_eq!(r.honest_count, 12);
        assert!(
            r.effective_k < 12.0,
            "residual signal must erode effective-k below the honest set, got {}",
            r.effective_k
        );
        assert!(r.effective_k > 1.0, "but not to full exposure here");
    }

    #[test]
    fn effective_k_never_exceeds_the_honest_count() {
        // The composition law: no residual model can invent anonymity the honest
        // set does not contain.
        let r = round_anonymity(17, &[1.0; 12]);
        assert!(r.effective_k <= r.honest_count as f64 + 1e-9);
        assert!(r.honest_count <= r.advertised_k);
    }
}
