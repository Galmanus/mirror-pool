//! Synthetic funding-graph generators for the exhibit.
//!
//! Three constructions, so the tracer can contrast the field's approach against
//! the two circularity variants:
//!
//! - [`rooted_decoy`] — what every noise-based tool ships. A real transfer is
//!   buried among decoys, but the target's funding still chains back to a single
//!   labeled origin (a CEX). Decoys add breadth, not rootlessness. Provenance
//!   leaks: the tracer names the origin with near-certainty.
//! - [`cyclic_ambiguous`] — the **realistic** defense. The target lives inside a
//!   churning pool (a strongly-connected component). Labeled origins *do* fund
//!   the pool, but each funds many members and the target sits in the cycle, so
//!   the tracer reaches *many* origins at similar depth: a root exists, but
//!   *which* one is dissolved (high attribution entropy — the polysemy weapon).
//! - [`cyclic_rootless`] — the **idealized** defense. External funding enters the
//!   pool only through unlabeled participants, so the reverse-closure contains no
//!   attributable origin at all. Honest caveat encoded in the construction: this
//!   holds *only* if the pool's funding sources are themselves unattributable —
//!   the moment one is a known CEX, it degrades to [`cyclic_ambiguous`].

use crate::graph::ProvenanceGraph;
use crate::rng::SplitMix64;

/// A generated scenario: the graph plus the set of targets to audit.
pub struct Scheme {
    pub graph: ProvenanceGraph,
    pub targets: Vec<usize>,
}

/// Build a strongly-connected pool of `pool_size` unlabeled nodes: a directed
/// ring (guaranteeing one SCC of the full size) plus extra intra-pool edges for
/// realistic density. Returns the pool node ids.
fn build_pool(graph: &mut ProvenanceGraph, rng: &mut SplitMix64, pool_size: usize) -> Vec<usize> {
    let nodes: Vec<usize> = (0..pool_size).map(|_| graph.add_node(None)).collect();
    for i in 0..pool_size {
        graph.add_funding(nodes[i], nodes[(i + 1) % pool_size]);
    }
    // Extra churn edges, all internal, keeping the single big cycle.
    for _ in 0..pool_size {
        let a = nodes[rng.below(pool_size)];
        let b = nodes[rng.below(pool_size)];
        graph.add_funding(a, b);
    }
    nodes
}

/// The field's construction: decoys, but a single traceable labeled origin.
pub fn rooted_decoy(rng: &mut SplitMix64, n_targets: usize, chain_len: usize) -> Scheme {
    let mut graph = ProvenanceGraph::new();
    let n_roots = 4;
    let roots: Vec<usize> = (0..n_roots)
        .map(|i| graph.add_node(Some(i as u32)))
        .collect();

    let mut targets = Vec::with_capacity(n_targets);
    for _ in 0..n_targets {
        let root = roots[rng.below(n_roots)];
        let mut prev = root;
        for _ in 0..chain_len {
            let hop = graph.add_node(None);
            graph.add_funding(prev, hop);
            prev = hop;
        }
        let target = graph.add_node(None);
        graph.add_funding(prev, target);
        // Decoy: a fresh, history-less key also funds the target. Adds an
        // ancestor, but it is unlabeled, so it does not hide the real origin.
        let decoy = graph.add_node(None);
        graph.add_funding(decoy, target);
        targets.push(target);
    }
    Scheme { graph, targets }
}

/// Realistic circularity: a churning pool funded by several labeled origins, so a
/// root exists but attribution is dissolved across many.
pub fn cyclic_ambiguous(
    rng: &mut SplitMix64,
    n_targets: usize,
    pool_size: usize,
    n_roots: usize,
) -> Scheme {
    let mut graph = ProvenanceGraph::new();
    let pool = build_pool(&mut graph, rng, pool_size);
    let roots: Vec<usize> = (0..n_roots)
        .map(|i| graph.add_node(Some(i as u32)))
        .collect();
    // Each labeled origin funds several pool members — spreading the blame.
    for &r in &roots {
        for _ in 0..3 {
            graph.add_funding(r, pool[rng.below(pool_size)]);
        }
    }
    let targets: Vec<usize> = (0..n_targets).map(|_| pool[rng.below(pool_size)]).collect();
    Scheme { graph, targets }
}

/// Idealized circularity: external funding enters the pool only through unlabeled
/// participants, so no attributable origin exists in any target's closure.
pub fn cyclic_rootless(rng: &mut SplitMix64, n_targets: usize, pool_size: usize) -> Scheme {
    let mut graph = ProvenanceGraph::new();
    let pool = build_pool(&mut graph, rng, pool_size);
    // A handful of unlabeled external funders seed the pool.
    for _ in 0..3 {
        let funder = graph.add_node(None);
        graph.add_funding(funder, pool[rng.below(pool_size)]);
    }
    let targets: Vec<usize> = (0..n_targets).map(|_| pool[rng.below(pool_size)]).collect();
    Scheme { graph, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::Tracer;

    #[test]
    fn rooted_scheme_leaks_provenance() {
        let mut rng = SplitMix64::new(1);
        let s = rooted_decoy(&mut rng, 50, 4);
        let tracer = Tracer::new(&s.graph);
        let leaked = s
            .targets
            .iter()
            .filter(|&&t| tracer.trace(t).has_attributable_root())
            .count();
        assert_eq!(leaked, s.targets.len(), "every target must trace to a root");
    }

    #[test]
    fn rootless_scheme_hides_provenance() {
        let mut rng = SplitMix64::new(2);
        let s = cyclic_rootless(&mut rng, 50, 40);
        let tracer = Tracer::new(&s.graph);
        for &t in &s.targets {
            let r = tracer.trace(t);
            assert!(!r.has_attributable_root(), "no labeled origin should exist");
            assert!(r.in_cycle, "target should sit in the pool cycle");
        }
    }

    #[test]
    fn ambiguous_scheme_keeps_a_root_but_dissolves_which() {
        let mut rng = SplitMix64::new(3);
        let s = cyclic_ambiguous(&mut rng, 50, 40, 6);
        let tracer = Tracer::new(&s.graph);
        for &t in &s.targets {
            let r = tracer.trace(t);
            assert!(r.has_attributable_root(), "roots do fund the pool");
            assert!(r.in_cycle);
            // With multiple labeled origins spread over the pool, attribution
            // should be genuinely ambiguous (well above 1 bit).
            assert!(
                r.attribution_entropy_bits > 1.0,
                "attribution should be dissolved, got {} bits",
                r.attribution_entropy_bits
            );
        }
    }
}
