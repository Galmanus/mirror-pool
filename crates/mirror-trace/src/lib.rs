//! # mirror-trace
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
//! `mirror-trace` makes it a first-class, measured axis. The tracer (see
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

    for &t in &scheme.targets {
        let r = tracer.trace(t);
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
    }
}
