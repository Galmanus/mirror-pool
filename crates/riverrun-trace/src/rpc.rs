//! Shared Solana JSON-RPC plumbing for the on-chain tracers.
//!
//! Only compiled with the `onchain` feature, so the pure library stays
//! dependency-free and testable offline.
//!
//! Everything here is deliberately bounded — depth, fan-out, transactions
//! fetched — because the point is to establish a *lower bound* on the funding
//! graph leak using nothing but a public RPC endpoint. A real analyst goes
//! deeper, follows SPL flows, and pays for a tag database. Whatever these tools
//! find, the truth is worse.

use std::time::Duration;

use serde_json::{json, Value};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
/// `getSignaturesForAddress` hard cap.
pub const SIG_LIMIT: usize = 1000;
/// Only a *cap-hitting* address counts as an exchange-like hub root.
pub const HUB_THRESHOLD: usize = 1000;

pub struct Rpc {
    agent: ureq::Agent,
    url: String,
    /// Total RPC requests issued.
    pub calls: usize,
    /// Requests that failed at the transport layer or returned a JSON-RPC error.
    /// A caller that gets an empty result *and* sees failures here must not read
    /// the emptiness as "nothing to find" — it may be "could not look".
    pub failures: usize,
}

impl Rpc {
    pub fn new() -> Self {
        let url = std::env::var("SOLANA_RPC")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .build();
        Self { agent, url, calls: 0, failures: 0 }
    }

    /// The RPC endpoint in use (`$SOLANA_RPC`, else mainnet-beta). Surfaced so the
    /// CLI can name it in an error instead of failing opaquely.
    pub fn endpoint(&self) -> &str {
        &self.url
    }

    pub fn call(&mut self, method: &str, params: Value) -> Option<Value> {
        self.calls += 1;
        std::thread::sleep(Duration::from_millis(130)); // be polite to public RPC
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        for attempt in 0..3 {
            match self.agent.post(&self.url).send_json(body.clone()) {
                Ok(resp) => match resp.into_json::<Value>() {
                    Ok(v) => {
                        if let Some(err) = v.get("error") {
                            let msg = err
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("unknown JSON-RPC error");
                            eprintln!("  rpc: {method} -> error: {msg}");
                            self.failures += 1;
                            return None;
                        }
                        return v.get("result").cloned();
                    }
                    Err(_) => {
                        eprintln!("  rpc: {method} -> unparseable response");
                        self.failures += 1;
                        return None;
                    }
                },
                Err(ureq::Error::Status(429, _)) if attempt < 2 => {
                    std::thread::sleep(Duration::from_millis(900 * (attempt as u64 + 1)));
                }
                Err(ureq::Error::Status(code, _)) => {
                    eprintln!("  rpc: {method} -> HTTP {code} from {}", self.url);
                    self.failures += 1;
                    return None;
                }
                Err(e) => {
                    eprintln!("  rpc: {method} -> transport error: {e}");
                    self.failures += 1;
                    return None;
                }
            }
        }
        None
    }

    /// Recent signature count for an address (bounded by our sampling cap).
    pub fn sig_count(&mut self, addr: &str) -> usize {
        self.call(
            "getSignaturesForAddress",
            json!([addr, {"limit": SIG_LIMIT}]),
        )
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
    }

    pub fn signatures(&mut self, addr: &str, limit: usize) -> Vec<String> {
        self.call(
            "getSignaturesForAddress",
            json!([addr, {"limit": limit}]),
        )
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.get("signature").and_then(|x| x.as_str()).map(String::from))
        .collect()
    }

    pub fn transaction(&mut self, sig: &str) -> Option<Value> {
        self.call(
            "getTransaction",
            json!([sig, {"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]),
        )
    }
}

impl Default for Rpc {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed system-program transfers of a transaction, as
/// `(source, destination, lamports)` — **including inner instructions**.
///
/// Reading only top-level instructions misses almost everything that matters:
/// a pool deposit is a CPI from the pool program, so it appears in
/// `meta.innerInstructions`, not in the message. An analyst who skips those sees
/// an empty graph and concludes, wrongly, that there is nothing to trace.
pub fn system_transfers(tx: &Value) -> Vec<(String, String, u64)> {
    let mut instrs: Vec<&Value> = tx
        .pointer("/transaction/message/instructions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if let Some(groups) = tx.pointer("/meta/innerInstructions").and_then(|v| v.as_array()) {
        for g in groups {
            if let Some(inner) = g.get("instructions").and_then(|v| v.as_array()) {
                instrs.extend(inner.iter());
            }
        }
    }

    let mut out = Vec::new();
    for ix in instrs {
        let is_transfer = ix.pointer("/parsed/type").and_then(|v| v.as_str()) == Some("transfer")
            && ix.get("program").and_then(|v| v.as_str()) == Some("system");
        if !is_transfer {
            continue;
        }
        let info = ix.pointer("/parsed/info");
        let src = info.and_then(|i| i.get("source")).and_then(|v| v.as_str());
        let dst = info
            .and_then(|i| i.get("destination"))
            .and_then(|v| v.as_str());
        let lamports = info
            .and_then(|i| i.get("lamports"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if let (Some(s), Some(d)) = (src, dst) {
            out.push((s.to_string(), d.to_string(), lamports));
        }
    }
    out
}

/// The fee payer of a transaction — `accountKeys[0]`.
pub fn fee_payer(tx: &Value) -> Option<String> {
    tx.pointer("/transaction/message/accountKeys/0/pubkey")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            tx.pointer("/transaction/message/accountKeys/0")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
}

/// Incoming SOL funders of `addr` (sources of system transfers whose destination
/// is `addr`), plus whether `addr` looks like a high-activity hub.
///
/// Hubs are terminal: an exchange-like address is treated as an attributable
/// root, and expanding it would blow the budget for no information.
pub fn incoming_funders(
    rpc: &mut Rpc,
    addr: &str,
    tx_budget: &mut usize,
    funders_per_addr: usize,
    scan_tx_per_addr: usize,
) -> (Vec<String>, bool) {
    let sigs = rpc.signatures(addr, SIG_LIMIT);
    if sigs.len() >= HUB_THRESHOLD {
        return (Vec::new(), true);
    }

    let mut funders = Vec::new();
    for (scanned, sig) in sigs.into_iter().enumerate() {
        if *tx_budget == 0 || funders.len() >= funders_per_addr || scanned >= scan_tx_per_addr {
            break;
        }
        *tx_budget -= 1;
        let Some(tx) = rpc.transaction(&sig) else {
            continue;
        };
        for (src, dst, _) in system_transfers(&tx) {
            if dst == addr && src != addr && !funders.contains(&src) {
                funders.push(src);
            }
        }
    }
    (funders, false)
}

/// Trace one wallet's funding graph backward and return its **provenance class**:
/// the sorted set of attributable-origin (hub) addresses it reaches, joined by
/// '+', or the sentinel "rootless" if it reaches none. This is the key two
/// wallets share when the same adversary cannot separate them by provenance.
///
/// Bounded like everything else here — depth, fan-out, transactions — so the
/// class it returns is a floor: a deeper trace can only merge a rootless wallet
/// into a rooted class, never the reverse.
pub fn provenance_class(
    rpc: &mut Rpc,
    target: &str,
    tx_budget: &mut usize,
    depth: usize,
    nodes_per_target: usize,
    funders_per_addr: usize,
    scan_tx_per_addr: usize,
) -> String {
    use std::collections::{BTreeSet, HashSet, VecDeque};

    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut nodes = 0usize;
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((target.to_string(), 0));
    visited.insert(target.to_string());

    while let Some((addr, d)) = queue.pop_front() {
        if d >= depth || nodes >= nodes_per_target || *tx_budget == 0 {
            continue;
        }
        let (funders, is_hub) =
            incoming_funders(rpc, &addr, tx_budget, funders_per_addr, scan_tx_per_addr);
        if is_hub && addr != target {
            roots.insert(addr.clone());
            continue;
        }
        for f in funders {
            nodes += 1;
            if !visited.contains(&f) && nodes < nodes_per_target {
                visited.insert(f.clone());
                queue.push_back((f, d + 1));
            }
            if nodes >= nodes_per_target {
                break;
            }
        }
    }

    if roots.is_empty() {
        "rootless".to_string()
    } else {
        roots.into_iter().collect::<Vec<_>>().join("+")
    }
}
