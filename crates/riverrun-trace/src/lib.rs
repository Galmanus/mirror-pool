//! # riverrun-trace
//!
//! The **provenance-tracer**: an adversarial on-chain de-anonymizer, and the
//! measuring stick it implies.
//!
//! Every noise-based privacy tool in this space measures itself against a
//! *self-made* attacker and reports an attribution AUC. But they all leave one
//! leak open — several admit it in their own writeups — the **funding /
//! common-funder graph**: trace a target's money backward and you reach an
//! attributable origin (a CEX, a doxxed funder). That backward walk is the whole
//! ballgame, and it is a *graph* property no AUC captures.
//!
//! `riverrun-trace` makes it a first-class, measured axis. The tracer (see
//! [`tracer::Tracer`]) walks the funding graph backward and reports, per target:
//! does it reach a labeled root (**provenance**), and if so how many and how
//! concentrated (**attribution**), and does it sit in a cycle (**structural
//! rootlessness**). Run over a population it yields the numbers below.
//!
//! The design is deliberately dual-use in the honest sense: the same tool that
//! scores a *defense* is, on its own, the strongest open de-anonymizer of the
//! funding graph — the sorohunter pattern (build the attacker; the defense falls
//! out as its dual).

pub mod graph;
pub mod rng;
#[cfg(feature = "onchain")]
pub mod rpc;
pub mod scenario;
pub mod tracer;

use scenario::Scheme;
use tracer::Tracer;

/// Population-level provenance statistics for one construction.
#[derive(Clone, Copy, Debug)]
pub struct SchemeStats {
    pub targets: usize,
    /// Fraction of targets for which the tracer finds *any* attributable origin.
    /// This is the leak the field leaves open — lower is more private.
    pub root_hit_rate: f64,
    /// Mean depth to the nearest reachable root (over targets that have one).
    pub mean_nearest_depth: f64,
    /// Mean attribution ambiguity in bits — how undecidable "which origin" is,
    /// even when one exists. Higher is more private.
    pub mean_attribution_bits: f64,
    /// Fraction of targets sitting inside a cycle (non-trivial SCC).
    pub cyclic_rate: f64,
    /// Anonymity that survives an adversary who partitions the set by provenance.
    pub effective_k: EffectiveK,
}

/// What a `k`-member anonymity set is actually worth against an adversary who
/// can tell which **provenance class** the acting member belongs to.
///
/// Pools advertise `1/k`: k members, so a one-in-k guess. That counts members.
/// If the adversary can sort those members into classes by where their funding
/// came from — and the funding graph is public — then learning the actor's class
/// leaves only that class to guess within.
///
/// The residual uncertainty is the class size, averaged over which class the
/// actor came from:
///
/// ```text
/// H_residual = Σ_c (n_c / n) · log2(n_c)      effective k = 2^H_residual
/// ```
///
/// One class holding everyone returns `log2(n)` — nothing was partitioned, the
/// set is worth its advertised size. All-singleton classes return 0 bits, an
/// effective k of 1: every member is individually identified.
///
/// Note the direction. It is tempting to measure how *concentrated* the classes
/// are (min-entropy over the class distribution), but that reports catastrophe
/// exactly when the measurement found nothing to partition on. Residual
/// anonymity is the quantity the member cares about.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EffectiveK {
    pub advertised: usize,
    pub classes: usize,
    pub residual_bits: f64,
    /// `2^residual_bits` — the anonymity set the member actually gets.
    pub effective: f64,
    /// The smallest class: what the least lucky member gets.
    pub worst_case: usize,
}

/// Compute [`EffectiveK`] from the sizes of the provenance classes.
pub fn effective_k(class_sizes: &[usize]) -> EffectiveK {
    let n: usize = class_sizes.iter().sum();
    if n == 0 {
        return EffectiveK {
            advertised: 0,
            classes: 0,
            residual_bits: 0.0,
            effective: 0.0,
            worst_case: 0,
        };
    }
    let residual_bits: f64 = class_sizes
        .iter()
        .map(|&c| (c as f64 / n as f64) * (c as f64).log2())
        .sum();
    EffectiveK {
        advertised: n,
        classes: class_sizes.len(),
        residual_bits,
        effective: residual_bits.exp2(),
        worst_case: class_sizes.iter().copied().min().unwrap_or(0),
    }
}

/// Run the tracer over every target of a scheme and aggregate.
pub fn evaluate(scheme: &Scheme) -> SchemeStats {
    let tracer = Tracer::new(&scheme.graph);
    let n = scheme.targets.len();

    let mut hits = 0usize;
    let mut depth_sum = 0.0;
    let mut depth_count = 0usize;
    let mut bits_sum = 0.0;
    let mut cyclic = 0usize;
    // provenance class = the set of attributable origins a target reaches
    let mut classes: std::collections::BTreeMap<Vec<u32>, usize> = std::collections::BTreeMap::new();

    for &t in &scheme.targets {
        let r = tracer.trace(t);
        let mut key: Vec<u32> = r.reachable_roots.iter().map(|(l, _)| *l).collect();
        key.sort_unstable();
        key.dedup();
        *classes.entry(key).or_insert(0) += 1;
        if r.has_attributable_root() {
            hits += 1;
            if let Some(d) = r.nearest_depth {
                depth_sum += d as f64;
                depth_count += 1;
            }
        }
        bits_sum += r.attribution_entropy_bits;
        if r.in_cycle {
            cyclic += 1;
        }
    }

    SchemeStats {
        targets: n,
        root_hit_rate: hits as f64 / n as f64,
        mean_nearest_depth: if depth_count > 0 {
            depth_sum / depth_count as f64
        } else {
            f64::NAN
        },
        mean_attribution_bits: bits_sum / n as f64,
        cyclic_rate: cyclic as f64 / n as f64,
        effective_k: effective_k(&classes.values().copied().collect::<Vec<_>>()),
    }
}

#[cfg(test)]
mod effective_k_tests {
    use super::effective_k;

    #[test]
    fn one_class_holding_everyone_keeps_the_full_set() {
        // Nothing was partitioned: the members are worth their advertised count.
        let k = effective_k(&[64]);
        assert_eq!(k.advertised, 64);
        assert_eq!(k.classes, 1);
        assert!((k.effective - 64.0).abs() < 1e-9, "got {}", k.effective);
        assert_eq!(k.worst_case, 64);
    }

    #[test]
    fn singleton_classes_destroy_the_set() {
        let k = effective_k(&[1, 1, 1, 1]);
        assert!((k.residual_bits - 0.0).abs() < 1e-9);
        assert!((k.effective - 1.0).abs() < 1e-9, "got {}", k.effective);
        assert_eq!(k.worst_case, 1);
    }

    #[test]
    fn equal_classes_give_back_the_class_size() {
        // Eight members in two provenance classes are worth four, not eight.
        let k = effective_k(&[4, 4]);
        assert_eq!(k.advertised, 8);
        assert!((k.effective - 4.0).abs() < 1e-9, "got {}", k.effective);
    }

    #[test]
    fn the_unlucky_member_is_reported_separately() {
        // The average hides them: one member alone in their class gets nothing,
        // while the mean still looks respectable.
        let k = effective_k(&[15, 1]);
        assert_eq!(k.worst_case, 1, "one member is alone in their class");
        // (15/16)·log2(15) ≈ 3.66 bits ≈ 12.7 members: the average still reads as
        // a healthy set while one member has none at all.
        assert!(
            (12.0..13.0).contains(&k.effective),
            "the mean hides them: {}",
            k.effective
        );
    }
}
