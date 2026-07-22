//! The provenance graph.
//!
//! Nodes are accounts. A directed edge `u -> v` means **`u` funded `v`** (value
//! flowed from `u` to `v`). Provenance analysis walks these edges *backward*:
//! the funders of `v` are its predecessors. Some nodes carry a [`RootLabel`] —
//! they are *attributable origins* the analyst already knows (a CEX deposit
//! address, a sanctioned wallet, a doxxed funder). The whole game of
//! de-anonymization is: starting from a target, does the backward walk reach a
//! labeled root, and if so, which one and how certainly?
//!
//! Because value flows forward in time, the *literal* funding graph is always a
//! rooted DAG — every chain of funding bottoms out at some source. The interesting
//! structure (and the defense) lives in whether that source is **labeled** and
//! whether the target sits inside a **cycle** in the inferred ownership relation,
//! which — unlike the time-ordered ledger — may be cyclic.

/// A human-known origin label (exchange name, sanctioned tag, etc.).
pub type RootLabel = u32;

/// Directed funding graph with optional root labels on nodes.
#[derive(Clone, Debug, Default)]
pub struct ProvenanceGraph {
    /// `succ[u]` = nodes `u` funded (out-edges `u -> v`).
    succ: Vec<Vec<usize>>,
    /// `preds[v]` = nodes that funded `v` (in-edges), kept in sync for backward
    /// walks — the tracer's primary direction.
    preds: Vec<Vec<usize>>,
    /// `root[v] = Some(label)` iff `v` is an attributable origin.
    root: Vec<Option<RootLabel>>,
}

impl ProvenanceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node, returning its id. `label = Some(_)` marks it an attributable root.
    pub fn add_node(&mut self, label: Option<RootLabel>) -> usize {
        let id = self.root.len();
        self.succ.push(Vec::new());
        self.preds.push(Vec::new());
        self.root.push(label);
        id
    }

    /// Record that `from` funded `to`.
    pub fn add_funding(&mut self, from: usize, to: usize) {
        // Ignore accidental self-loops on a single node; a 1-node "cycle" is not
        // a meaningful anonymity structure.
        if from == to {
            return;
        }
        if !self.succ[from].contains(&to) {
            self.succ[from].push(to);
            self.preds[to].push(from);
        }
    }

    pub fn len(&self) -> usize {
        self.root.len()
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// The funders of `v` (backward neighbors).
    pub fn predecessors(&self, v: usize) -> &[usize] {
        &self.preds[v]
    }

    /// The nodes `u` funded (forward neighbors) — used by Tarjan for SCCs.
    pub fn successors(&self, u: usize) -> &[usize] {
        &self.succ[u]
    }

    /// The root label of `v`, if any.
    pub fn root_label(&self, v: usize) -> Option<RootLabel> {
        self.root[v]
    }

    pub fn is_root(&self, v: usize) -> bool {
        self.root[v].is_some()
    }
}
