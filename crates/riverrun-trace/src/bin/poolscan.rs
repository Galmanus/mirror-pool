//! `pool-provenance` — measure the funding-graph leak of a **real, live
//! anonymity set** on Solana mainnet.
//!
//! Every anonymity pool reports its privacy as `1/k`: k members, so an observer
//! has a 1-in-k chance of attributing an action. That number counts *members*.
//! It says nothing about where those members' money came from — and the funding
//! graph is public.
//!
//! This tool enumerates the real depositors of a live pool program, walks each
//! one's funding graph backward, and reports the population statistics nobody
//! publishes:
//!
//!   * what fraction of a real anonymity set reaches an attributable origin,
//!   * how the set partitions into provenance classes, and
//!   * the residual uncertainty in bits once an adversary uses that partition —
//!     the *effective* k, as opposed to the advertised k.
//!
//! ## How to read the output (this matters)
//!
//! * **Aggregates only.** No depositor is named in the output. The point is a
//!   property of the construction, not of any person.
//! * **The partition bound is conditional.** Provenance classes shrink the
//!   adversary's search space only for an adversary who can also observe the
//!   provenance class of the *acting* identity. That is exactly the situation a
//!   fresh withdrawal wallet is in — it has to be funded from somewhere — but it
//!   is an assumption, and it is stated rather than hidden.
//! * **This under-reports.** Public RPC, SOL transfers only, top-level
//!   instructions, bounded depth and fan-out, hub labels by activity heuristic
//!   rather than a maintained tag database. Every one of those bounds makes the
//!   measured leak smaller than the real one.
//!
//! Usage: `pool-provenance [POOL_PROGRAM_ID] [SAMPLE_SIZE]`
//! RPC endpoint via `SOLANA_RPC`, default mainnet-beta.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use riverrun_trace::graph::ProvenanceGraph;
use riverrun_trace::effective_k;
use riverrun_trace::rpc::{fee_payer, incoming_funders, system_transfers, Rpc, HUB_THRESHOLD};
use riverrun_trace::tracer::Tracer;

/// Privacy Cash — a live Tornado-style SOL privacy pool on Solana mainnet.
/// Chosen because it is a real, funded, currently-used anonymity set, which is
/// the only kind of population this measurement means anything on.
const DEFAULT_POOL: &str = "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD";

const DEFAULT_SAMPLE: usize = 20;
const POOL_SIG_SCAN: usize = 400;
const DEPTH: usize = 3;
const NODES_PER_TARGET: usize = 14;
const FUNDERS_PER_ADDR: usize = 4;
const SCAN_TX_PER_ADDR: usize = 6;
const TX_BUDGET: usize = 2600;

/// One depositor's backward trace.
struct Traced {
    /// Every address reached walking backward (excluding the depositor).
    ancestors: BTreeSet<String>,
    /// Hub addresses reached — the attributable origins.
    roots: BTreeSet<String>,
    nearest_depth: Option<usize>,
    in_cycle: bool,
}

fn main() {
    let pool = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_POOL.to_string());
    let sample: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SAMPLE);

    let mut rpc = Rpc::new();
    let mut tx_budget = TX_BUDGET;

    eprintln!("pool program : {pool}");
    eprintln!("enumerating depositors from recent pool activity...\n");

    let depositors = enumerate_depositors(&mut rpc, &pool, sample, &mut tx_budget);
    if depositors.is_empty() {
        eprintln!("no depositors recovered (RPC unavailable, or the pool has no recent\nuser-paid deposits in the scanned window).");
        std::process::exit(1);
    }
    eprintln!("\n{} distinct depositors sampled\ntracing each one's funding graph backward...\n", depositors.len());

    let mut traced: Vec<Traced> = Vec::new();
    for (i, d) in depositors.iter().enumerate() {
        let t = trace_one(&mut rpc, d, &mut tx_budget);
        eprintln!(
            "  [{:>2}/{}] ancestors {:>2}  roots {}  {}",
            i + 1,
            depositors.len(),
            t.ancestors.len(),
            t.roots.len(),
            if t.roots.is_empty() { "" } else { "← attributable" }
        );
        traced.push(t);
        if tx_budget == 0 {
            eprintln!("  (transaction budget exhausted — reporting on {} of {})", traced.len(), depositors.len());
            break;
        }
    }

    report(&traced, &pool, rpc.calls);
}

/// Distinct, non-hub fee payers of transactions that touch the pool program and
/// move SOL out of that fee payer — i.e. users depositing, not the relayer
/// paying for someone's withdrawal. The hub filter removes the relayer for free:
/// a relayer is by construction a cap-hitting address.
fn enumerate_depositors(
    rpc: &mut Rpc,
    pool: &str,
    want: usize,
    tx_budget: &mut usize,
) -> Vec<String> {
    let sigs = rpc.signatures(pool, POOL_SIG_SCAN);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for sig in sigs {
        if out.len() >= want || *tx_budget == 0 {
            break;
        }
        *tx_budget -= 1;
        let Some(tx) = rpc.transaction(&sig) else {
            continue;
        };
        let Some(payer) = fee_payer(&tx) else { continue };
        if seen.contains(&payer) {
            continue;
        }
        // a deposit moves SOL *out of* the payer within the same transaction
        // A deposit moves SOL out of the fee payer into a pool-owned account.
        // The threshold skips rent-exempt account creations, which every
        // deposit also does and which would otherwise match.
        const MIN_DEPOSIT_LAMPORTS: u64 = 10_000_000; // 0.01 SOL
        let deposits = system_transfers(&tx).into_iter().any(|(src, dst, lamports)| {
            src == payer && dst != payer && lamports >= MIN_DEPOSIT_LAMPORTS
        });
        if !deposits {
            continue;
        }
        seen.insert(payer.clone());
        // skip infrastructure: relayers and exchange hot wallets are cap-hitting
        if rpc.sig_count(&payer) >= HUB_THRESHOLD {
            eprintln!("  skipping hub-like address (relayer / exchange)");
            continue;
        }
        eprintln!("  depositor #{}", out.len() + 1);
        out.push(payer);
    }
    out
}

/// Backward BFS from one depositor, then the same [`Tracer`] the synthetic
/// exhibit uses, so the numbers are comparable across real and simulated runs.
fn trace_one(rpc: &mut Rpc, target: &str, tx_budget: &mut usize) -> Traced {
    let mut id_of: HashMap<String, usize> = HashMap::new();
    let mut addr_of: Vec<String> = Vec::new();
    let mut hubs: HashSet<String> = HashSet::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    let intern = |addr: &str, id_of: &mut HashMap<String, usize>, addr_of: &mut Vec<String>| {
        *id_of.entry(addr.to_string()).or_insert_with(|| {
            addr_of.push(addr.to_string());
            addr_of.len() - 1
        })
    };
    intern(target, &mut id_of, &mut addr_of);

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((target.to_string(), 0));
    visited.insert(target.to_string());

    while let Some((addr, depth)) = queue.pop_front() {
        if depth >= DEPTH || addr_of.len() >= NODES_PER_TARGET || *tx_budget == 0 {
            continue;
        }
        let (funders, is_hub) =
            incoming_funders(rpc, &addr, tx_budget, FUNDERS_PER_ADDR, SCAN_TX_PER_ADDR);
        if is_hub {
            hubs.insert(addr.clone());
            continue;
        }
        for f in funders {
            intern(&f, &mut id_of, &mut addr_of);
            edges.push((f.clone(), addr.clone()));
            if !visited.contains(&f) && addr_of.len() < NODES_PER_TARGET {
                visited.insert(f.clone());
                queue.push_back((f, depth + 1));
            }
        }
    }

    // Hub status of the frontier: an address we never expanded may still be a hub.
    for addr in addr_of.clone() {
        if addr == target || hubs.contains(&addr) || *tx_budget == 0 {
            continue;
        }
        let is_frontier = !visited.contains(&addr) || edges.iter().all(|(f, _)| f != &addr);
        if is_frontier && rpc.sig_count(&addr) >= HUB_THRESHOLD {
            hubs.insert(addr);
        }
    }

    let mut g = ProvenanceGraph::new();
    let mut node_id: Vec<usize> = Vec::with_capacity(addr_of.len());
    for (i, addr) in addr_of.iter().enumerate() {
        let label = if hubs.contains(addr) { Some(i as u32) } else { None };
        node_id.push(g.add_node(label));
    }
    for (from, to) in &edges {
        g.add_funding(node_id[id_of[from]], node_id[id_of[to]]);
    }

    let report = Tracer::new(&g).trace(node_id[id_of[target]]);

    Traced {
        ancestors: addr_of.iter().skip(1).cloned().collect(),
        roots: report
            .reachable_roots
            .iter()
            .map(|(label, _)| addr_of[*label as usize].clone())
            .collect(),
        nearest_depth: report.nearest_depth,
        in_cycle: report.in_cycle,
    }
}

fn report(traced: &[Traced], pool: &str, rpc_calls: usize) {
    let n = traced.len() as f64;
    let rooted = traced.iter().filter(|t| !t.roots.is_empty()).count();
    let cyclic = traced.iter().filter(|t| t.in_cycle).count();
    let depths: Vec<usize> = traced.iter().filter_map(|t| t.nearest_depth).collect();
    let mean_depth = if depths.is_empty() {
        0.0
    } else {
        depths.iter().sum::<usize>() as f64 / depths.len() as f64
    };

    // Provenance partition: two depositors fall in the same class when their
    // reachable-root sets match. "unrooted" is itself a class.
    let mut classes: HashMap<String, usize> = HashMap::new();
    for t in traced {
        let key = if t.roots.is_empty() {
            "«unrooted»".to_string()
        } else {
            t.roots.iter().cloned().collect::<Vec<_>>().join("+")
        };
        *classes.entry(key).or_insert(0) += 1;
    }
    let largest = classes.values().copied().max().unwrap_or(0);
    // the same function the synthetic exhibit uses, so the two are comparable
    let ek = effective_k(&classes.values().copied().collect::<Vec<_>>());
    let smallest = ek.worst_case;

    // Direct ancestor collisions: depositors sharing at least one funder.
    let mut ancestor_owners: HashMap<&String, usize> = HashMap::new();
    for t in traced {
        for a in &t.ancestors {
            *ancestor_owners.entry(a).or_insert(0) += 1;
        }
    }
    let shared_ancestors = ancestor_owners.values().filter(|&&c| c > 1).count();
    let colliding = traced
        .iter()
        .filter(|t| t.ancestors.iter().any(|a| ancestor_owners[a] > 1))
        .count();

    println!("\n=== funding-graph exposure of a live anonymity set ===");
    println!("pool program            : {pool}");
    println!("depositors sampled      : {}", traced.len());
    println!("RPC calls               : {rpc_calls}");
    println!();
    println!("attributable origin     : {rooted}/{} ({:.0}%)", traced.len(), 100.0 * rooted as f64 / n);
    println!("mean depth to origin    : {mean_depth:.2} hops");
    println!("in a funding cycle      : {cyclic}/{}", traced.len());
    println!();
    println!("provenance classes      : {}", classes.len());
    println!("largest class           : {largest}/{} ({:.0}%)", traced.len(), 100.0 * largest as f64 / n);
    println!("smallest class          : {smallest}");
    println!("residual anonymity      : {:.2} bits", ek.residual_bits);
    println!(
        "advertised k            : {}  ->  effective k : {:.1}  (worst case {smallest})",
        traced.len(),
        ek.effective
    );
    println!();
    println!("shared funder addresses : {shared_ancestors}");
    println!(
        "depositors sharing one  : {colliding}/{} ({:.0}%)",
        traced.len(),
        100.0 * colliding as f64 / n
    );
    println!(
        "\nRead this as a lower bound. Public RPC, SOL transfers only, depth {DEPTH},\n\
         at most {NODES_PER_TARGET} addresses per target, hub labels by activity heuristic.\n\
         A funded analyst with a tag database and SPL-flow following measures more,\n\
         never less. No depositor is named above: the finding is a property of the\n\
         construction, not of anyone who used it.\n\
         \n\
         The partition bound assumes an adversary who can observe the provenance\n\
         class of the acting identity as well as the set. A withdrawal wallet has\n\
         to be funded from somewhere, which is what makes that assumption cheap."
    );
}
