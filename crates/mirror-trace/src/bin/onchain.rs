//! `onchain-trace` — run the provenance-tracer against **real Solana mainnet**.
//!
//! Pulls a target's backward funding graph over JSON-RPC (system-program SOL
//! transfers), labels high-activity hubs as *heuristic* attributable origins, and
//! runs the same [`mirror_trace::tracer::Tracer`] used on the synthetic exhibit.
//!
//! Honesty notes, stated up front because they matter for how to read the output:
//!   * Root labels here are an **activity heuristic** (an address whose recent
//!     signature count hits our sampling cap is treated as an exchange-like hub).
//!     A production analyst plugs in a maintained tag database (Arkham,
//!     Chainalysis); we do not fabricate specific CEX addresses.
//!   * We follow **system-program SOL transfers only**, top-level instructions,
//!     bounded in depth/fanout — a deliberately shallow trace. A real analyst
//!     goes deeper and also follows SPL token flows. So this *under*-reports the
//!     leak; the true funding-graph exposure is at least this bad.
//!
//! Usage: `onchain-trace [TARGET_ADDRESS]`  (discovers a live target if omitted)
//! RPC endpoint via `SOLANA_RPC` env, default mainnet-beta.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use mirror_trace::graph::ProvenanceGraph;
use mirror_trace::tracer::Tracer;
use serde_json::{json, Value};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const SIG_LIMIT: usize = 1000; // getSignaturesForAddress hard cap
const HUB_THRESHOLD: usize = 1000; // only a *cap-hitting* address counts as a hub root
const MAX_DEPTH: usize = 3;
const NODE_CAP: usize = 40;
const TX_FETCH_CAP: usize = 80;
const FUNDERS_PER_ADDR: usize = 5;
const SCAN_TX_PER_ADDR: usize = 12; // bound getTransaction calls spent per address

struct Rpc {
    agent: ureq::Agent,
    url: String,
    calls: usize,
}

impl Rpc {
    fn new() -> Self {
        let url = std::env::var("SOLANA_RPC")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .build();
        Self {
            agent,
            url,
            calls: 0,
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Option<Value> {
        self.calls += 1;
        std::thread::sleep(Duration::from_millis(130)); // be polite to public RPC
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        for attempt in 0..2 {
            match self.agent.post(&self.url).send_json(body.clone()) {
                Ok(resp) => {
                    if let Ok(v) = resp.into_json::<Value>() {
                        return Some(v.get("result")?.clone());
                    }
                    return None;
                }
                Err(ureq::Error::Status(429, _)) if attempt == 0 => {
                    std::thread::sleep(Duration::from_millis(800));
                }
                Err(_) => return None,
            }
        }
        None
    }
}

/// Incoming SOL funders of `addr` (sources of system transfers whose destination
/// is `addr`), plus whether `addr` looks like a high-activity hub.
fn incoming_funders(rpc: &mut Rpc, addr: &str, tx_budget: &mut usize) -> (Vec<String>, bool) {
    let sigs = rpc.call(
        "getSignaturesForAddress",
        json!([addr, {"limit": SIG_LIMIT}]),
    );
    let sig_arr = sigs.as_ref().and_then(|v| v.as_array());
    let sig_count = sig_arr.map(|a| a.len()).unwrap_or(0);
    let is_hub = sig_count >= HUB_THRESHOLD;
    if is_hub {
        // Roots are terminal — don't spend budget expanding a hub.
        return (Vec::new(), true);
    }

    let mut funders = Vec::new();
    let signatures: Vec<String> = sig_arr
        .into_iter()
        .flatten()
        .filter_map(|s| {
            s.get("signature")
                .and_then(|x| x.as_str())
                .map(String::from)
        })
        .collect();

    let mut scanned = 0usize;
    for sig in signatures {
        if *tx_budget == 0 || funders.len() >= FUNDERS_PER_ADDR || scanned >= SCAN_TX_PER_ADDR {
            break;
        }
        scanned += 1;
        *tx_budget -= 1;
        let tx = rpc.call(
            "getTransaction",
            json!([sig, {"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]),
        );
        let Some(tx) = tx else { continue };
        let instrs = tx
            .pointer("/transaction/message/instructions")
            .and_then(|v| v.as_array());
        let Some(instrs) = instrs else { continue };
        for ix in instrs {
            let is_transfer = ix.pointer("/parsed/type").and_then(|v| v.as_str())
                == Some("transfer")
                && ix.get("program").and_then(|v| v.as_str()) == Some("system");
            if !is_transfer {
                continue;
            }
            let info = ix.pointer("/parsed/info");
            let dest = info
                .and_then(|i| i.get("destination"))
                .and_then(|v| v.as_str());
            let src = info.and_then(|i| i.get("source")).and_then(|v| v.as_str());
            if dest == Some(addr) {
                if let Some(s) = src {
                    if s != addr && !funders.contains(&s.to_string()) {
                        funders.push(s.to_string());
                    }
                }
            }
        }
    }
    (funders, false)
}

/// Recent signature count for an address (bounded by our sampling cap).
fn sig_count(rpc: &mut Rpc, addr: &str) -> usize {
    rpc.call(
        "getSignaturesForAddress",
        json!([addr, {"limit": SIG_LIMIT}]),
    )
    .and_then(|v| v.as_array().map(|a| a.len()))
    .unwrap_or(0)
}

/// Find a live *non-hub* target with incoming transfers, so the backward trace
/// has somewhere to walk. Scans recent system-program transfers and accepts the
/// first destination that has history but is not itself a high-activity hub.
fn discover_target(rpc: &mut Rpc, tx_budget: &mut usize) -> Option<String> {
    let sigs = rpc.call(
        "getSignaturesForAddress",
        json!([SYSTEM_PROGRAM, {"limit": 30}]),
    )?;
    for s in sigs.as_array()? {
        if *tx_budget == 0 {
            break;
        }
        *tx_budget -= 1;
        let sig = s.get("signature")?.as_str()?;
        let tx = rpc.call(
            "getTransaction",
            json!([sig, {"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]),
        )?;
        let Some(instrs) = tx
            .pointer("/transaction/message/instructions")
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        for ix in instrs {
            let is_transfer = ix.pointer("/parsed/type").and_then(|v| v.as_str())
                == Some("transfer")
                && ix.get("program").and_then(|v| v.as_str()) == Some("system");
            if !is_transfer {
                continue;
            }
            if let Some(d) = ix
                .pointer("/parsed/info/destination")
                .and_then(|v| v.as_str())
            {
                let c = sig_count(rpc, d);
                // history, but not a hub → a plausible user wallet to trace.
                if (1..HUB_THRESHOLD).contains(&c) {
                    return Some(d.to_string());
                }
            }
        }
    }
    None
}

fn main() {
    let mut rpc = Rpc::new();
    let mut tx_budget = TX_FETCH_CAP;

    let target = std::env::args().nth(1).or_else(|| {
        eprintln!("no address given — discovering a live target from recent transfers...");
        discover_target(&mut rpc, &mut tx_budget)
    });
    let Some(target) = target else {
        eprintln!("could not obtain a target address (RPC unavailable?). pass one as an argument.");
        std::process::exit(1);
    };
    eprintln!("target: {target}\ntracing backward funding graph over mainnet...\n");

    // Backward BFS building the provenance graph.
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
    intern(&target, &mut id_of, &mut addr_of);

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((target.clone(), 0));
    visited.insert(target.clone());

    while let Some((addr, depth)) = queue.pop_front() {
        if depth > MAX_DEPTH || addr_of.len() >= NODE_CAP || tx_budget == 0 {
            continue;
        }
        let (funders, is_hub) = incoming_funders(&mut rpc, &addr, &mut tx_budget);
        if is_hub {
            hubs.insert(addr.clone());
            eprintln!("  hub (heuristic root): {addr}");
            continue;
        }
        for f in funders {
            intern(&f, &mut id_of, &mut addr_of);
            edges.push((f.clone(), addr.clone()));
            eprintln!(
                "  {} <- {}  (depth {})",
                &addr[..8.min(addr.len())],
                &f[..8.min(f.len())],
                depth + 1
            );
            if !visited.contains(&f) && addr_of.len() < NODE_CAP {
                visited.insert(f.clone());
                queue.push_back((f, depth + 1));
            }
        }
    }

    // Build the labeled ProvenanceGraph (hubs → roots, labeled by node index).
    let mut g = ProvenanceGraph::new();
    let mut node_id: Vec<usize> = Vec::with_capacity(addr_of.len());
    for (i, addr) in addr_of.iter().enumerate() {
        let label = if hubs.contains(addr) {
            Some(i as u32)
        } else {
            None
        };
        node_id.push(g.add_node(label));
    }
    for (from, to) in &edges {
        g.add_funding(node_id[id_of[from]], node_id[id_of[to]]);
    }

    let tracer = Tracer::new(&g);
    let report = tracer.trace(node_id[id_of[&target]]);

    println!("\n=== provenance report (real mainnet) ===");
    println!("target                 : {target}");
    println!("addresses sampled      : {}", addr_of.len());
    println!("RPC calls              : {}", rpc.calls);
    println!("in a funding cycle     : {}", report.in_cycle);
    println!("SCC size               : {}", report.scc_size);
    if report.has_attributable_root() {
        println!(
            "ATTRIBUTABLE ORIGIN    : YES — reached a hub at depth {}",
            report.nearest_depth.unwrap()
        );
        for (label, depth) in &report.reachable_roots {
            println!("    root {}  (depth {})", addr_of[*label as usize], depth);
        }
        println!(
            "attribution ambiguity  : {:.2} bits",
            report.attribution_entropy_bits
        );
        println!(
            "\nverdict: the funding graph leaks — a shallow, SOL-only backward walk\n\
             already names an attributable origin. This is the axis the field's\n\
             decoy tools leave open, measured on live mainnet."
        );
    } else {
        println!("ATTRIBUTABLE ORIGIN    : none reached within depth {MAX_DEPTH} (shallow trace)");
        println!(
            "\nnote: absence here is the shallow bound, not proof of rootlessness —\n\
             a deeper trace or SPL-flow following may still reach an origin."
        );
    }
}
