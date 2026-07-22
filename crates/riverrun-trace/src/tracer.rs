//! The provenance-tracer — the adversary.
//!
//! Given a target account it answers the two questions on which all
//! chain-analysis rests:
//!
//! 1. **Provenance ("where did it come from?")** — does the backward funding walk
//!    reach a *labeled root* (an attributable origin), and how deep? The
//!    circularity weapon attacks this: if the target sits in a cycle whose
//!    reverse-closure contains no labeled root, the walk has no origin to name.
//! 2. **Attribution ("which origin?")** — when roots *are* reachable, how
//!    concentrated is the blame? One reachable root → certain (0 bits of
//!    ambiguity). Many equidistant roots → the polysemy weapon: the analyst
//!    cannot privilege one, so attribution entropy is high.
//!
//! The tracer computes both, plus whether the target lies inside a non-trivial
//! strongly-connected component (structural rootlessness). It is deliberately the
//! *strongest reasonable* analyst: it sees the entire graph and every label.

use crate::graph::{ProvenanceGraph, RootLabel};
use std::collections::{BTreeMap, VecDeque};

/// What the analyst learns about one target.
#[derive(Clone, Debug, PartialEq)]
pub struct ProvenanceReport {
    pub target: usize,
    /// Distinct reachable roots, each with the shortest backward depth to it.
    pub reachable_roots: Vec<(RootLabel, usize)>,
    /// Depth to the nearest reachable root, if any.
    pub nearest_depth: Option<usize>,
    /// Ambiguity of attribution across reachable roots, in bits. `0.0` means a
    /// single root (fully attributed); higher means the analyst cannot decide
    /// which origin is responsible.
    pub attribution_entropy_bits: f64,
    /// True iff the target is inside a cycle (non-trivial SCC) — it has no
    /// source node in the inferred ownership relation to point at.
    pub in_cycle: bool,
    /// Size of the target's strongly-connected component.
    pub scc_size: usize,
}

impl ProvenanceReport {
    /// The single fact the whole field leaves open: did the analyst find *any*
    /// attributable origin for this target?
    pub fn has_attributable_root(&self) -> bool {
        !self.reachable_roots.is_empty()
    }
}

/// A tracer bound to a graph. Strongly-connected components are computed once at
/// construction so per-target queries are cheap.
pub struct Tracer<'g> {
    graph: &'g ProvenanceGraph,
    /// Component id per node.
    comp: Vec<usize>,
    /// Size of each component, indexed by component id.
    comp_size: Vec<usize>,
}

impl<'g> Tracer<'g> {
    pub fn new(graph: &'g ProvenanceGraph) -> Self {
        let (comp, comp_size) = strongly_connected_components(graph);
        Self {
            graph,
            comp,
            comp_size,
        }
    }

    /// Trace one target back through the funding graph.
    pub fn trace(&self, target: usize) -> ProvenanceReport {
        let n = self.graph.len();
        let mut depth = vec![usize::MAX; n];
        let mut queue = VecDeque::new();
        depth[target] = 0;
        queue.push_back(target);

        // label -> shortest depth at which it was reached
        let mut roots: BTreeMap<RootLabel, usize> = BTreeMap::new();

        while let Some(v) = queue.pop_front() {
            let d = depth[v];
            if let Some(label) = self.graph.root_label(v) {
                roots
                    .entry(label)
                    .and_modify(|e| *e = (*e).min(d))
                    .or_insert(d);
            }
            for &p in self.graph.predecessors(v) {
                if depth[p] == usize::MAX {
                    depth[p] = d + 1;
                    queue.push_back(p);
                }
            }
        }

        let reachable_roots: Vec<(RootLabel, usize)> =
            roots.iter().map(|(&l, &d)| (l, d)).collect();
        let nearest_depth = reachable_roots.iter().map(|&(_, d)| d).min();
        let attribution_entropy_bits = attribution_entropy(&reachable_roots);

        let scc_size = self.comp_size[self.comp[target]];

        ProvenanceReport {
            target,
            reachable_roots,
            nearest_depth,
            attribution_entropy_bits,
            in_cycle: scc_size > 1,
            scc_size,
        }
    }
}

/// Entropy (bits) of the analyst's belief over which reachable root is the true
/// origin. Weight each root by `1/(1+depth)` — closer origins are more suspect —
/// then normalize and take Shannon entropy. One root → 0 bits; `k` equidistant
/// roots → `log2(k)` bits.
fn attribution_entropy(roots: &[(RootLabel, usize)]) -> f64 {
    if roots.len() <= 1 {
        return 0.0;
    }
    let weights: Vec<f64> = roots.iter().map(|&(_, d)| 1.0 / (1.0 + d as f64)).collect();
    let total: f64 = weights.iter().sum();
    let mut h = 0.0;
    for w in weights {
        let p = w / total;
        if p > 0.0 {
            h -= p * p.log2();
        }
    }
    h
}

/// Tarjan's algorithm, iterative (no recursion depth limit), returning the
/// component id of every node and the size of every component. A node in a
/// component of size > 1 lies on a cycle.
fn strongly_connected_components(graph: &ProvenanceGraph) -> (Vec<usize>, Vec<usize>) {
    let n = graph.len();
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut scc_stack: Vec<usize> = Vec::new();
    let mut comp = vec![UNVISITED; n];
    let mut sizes: Vec<usize> = Vec::new();
    let mut counter = 0usize;

    for start in 0..n {
        if index[start] != UNVISITED {
            continue;
        }
        // Work stack of (node, next successor pointer).
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&(v, pi)) = work.last() {
            if pi == 0 {
                index[v] = counter;
                low[v] = counter;
                counter += 1;
                scc_stack.push(v);
                on_stack[v] = true;
            }
            let succ = graph.successors(v);
            if pi < succ.len() {
                let w = succ[pi];
                work.last_mut().unwrap().1 += 1;
                if index[w] == UNVISITED {
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                // Finished v; propagate low to parent, close SCC if root.
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    low[parent] = low[parent].min(low[v]);
                }
                if low[v] == index[v] {
                    let id = sizes.len();
                    let mut size = 0usize;
                    loop {
                        let w = scc_stack.pop().unwrap();
                        on_stack[w] = false;
                        comp[w] = id;
                        size += 1;
                        if w == v {
                            break;
                        }
                    }
                    sizes.push(size);
                }
            }
        }
    }
    (comp, sizes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_chain_traces_to_its_root() {
        // root(label 7) -> a -> b -> target
        let mut g = ProvenanceGraph::new();
        let root = g.add_node(Some(7));
        let a = g.add_node(None);
        let b = g.add_node(None);
        let target = g.add_node(None);
        g.add_funding(root, a);
        g.add_funding(a, b);
        g.add_funding(b, target);

        let tracer = Tracer::new(&g);
        let r = tracer.trace(target);
        assert_eq!(r.reachable_roots, vec![(7, 3)]);
        assert_eq!(r.nearest_depth, Some(3));
        assert_eq!(r.attribution_entropy_bits, 0.0);
        assert!(!r.in_cycle);
        assert!(r.has_attributable_root());
    }

    #[test]
    fn pure_cycle_has_no_root_and_is_cyclic() {
        // a -> b -> c -> a, no labels. Funding enters nowhere attributable.
        let mut g = ProvenanceGraph::new();
        let a = g.add_node(None);
        let b = g.add_node(None);
        let c = g.add_node(None);
        g.add_funding(a, b);
        g.add_funding(b, c);
        g.add_funding(c, a);

        let tracer = Tracer::new(&g);
        let r = tracer.trace(a);
        assert!(r.reachable_roots.is_empty());
        assert_eq!(r.nearest_depth, None);
        assert!(r.in_cycle);
        assert_eq!(r.scc_size, 3);
        assert!(
            !r.has_attributable_root(),
            "a cycle has no attributable origin"
        );
    }

    #[test]
    fn two_equidistant_roots_maximize_ambiguity() {
        // root1 -> x -> target ; root2 -> y -> target. Both at depth 2.
        let mut g = ProvenanceGraph::new();
        let r1 = g.add_node(Some(1));
        let r2 = g.add_node(Some(2));
        let x = g.add_node(None);
        let y = g.add_node(None);
        let target = g.add_node(None);
        g.add_funding(r1, x);
        g.add_funding(x, target);
        g.add_funding(r2, y);
        g.add_funding(y, target);

        let tracer = Tracer::new(&g);
        let r = tracer.trace(target);
        assert_eq!(r.reachable_roots.len(), 2);
        // Two equally-weighted roots → exactly 1 bit of attribution ambiguity.
        assert!((r.attribution_entropy_bits - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cycle_with_external_labeled_funder_is_still_attributable() {
        // A labeled root funds the cycle from outside: root -> a, a->b->c->a.
        // The target is in a cycle BUT a labeled origin is reachable, so it is
        // not truly rootless — the tracer must still find the root.
        let mut g = ProvenanceGraph::new();
        let root = g.add_node(Some(9));
        let a = g.add_node(None);
        let b = g.add_node(None);
        let c = g.add_node(None);
        g.add_funding(root, a);
        g.add_funding(a, b);
        g.add_funding(b, c);
        g.add_funding(c, a);

        let tracer = Tracer::new(&g);
        let r = tracer.trace(b);
        assert!(r.in_cycle, "b is in the a-b-c cycle");
        assert!(
            r.has_attributable_root(),
            "an external labeled funder defeats naive circularity"
        );
        // b <- a <- root : the labeled origin is two backward hops away.
        assert_eq!(r.reachable_roots, vec![(9, 2)]);
    }
}
