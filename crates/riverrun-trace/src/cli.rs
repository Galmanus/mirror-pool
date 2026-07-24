//! The `riverrun` command line — one entry point, four verbs.
//!
//! Everything the measurement side of this repo does, behind a single binary with
//! sensible defaults, so a first run is `riverrun preflight <wallet>` and not a
//! hunt through six programs each with its own arguments.
//!
//! ```text
//! riverrun preflight <wallet> [pool] [n]   your anonymity before you act
//! riverrun audit     <pool> [n]            a live pool's true anonymity
//! riverrun trace     <wallet>              one wallet's funding provenance
//! riverrun exhibit                         the metric on riverrun's own designs
//! ```

use std::collections::HashSet;

use crate::rpc::{fee_payer, provenance_class, system_transfers, Rpc, HUB_THRESHOLD};
use crate::rng::SplitMix64;
use crate::{effective_k, evaluate, preflight, scenario, valid_pubkey, SchemeStats, Verdict};

/// Privacy Cash — a live Tornado-style SOL pool, the default when none is given.
const DEFAULT_POOL: &str = "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD";

// bounded-trace parameters, shared by every command
const DEPTH: usize = 3;
const NODES: usize = 14;
const FUNDERS: usize = 4;
const SCAN_TX: usize = 6;
const POOL_SIG_SCAN: usize = 300;
const MIN_DEPOSIT: u64 = 10_000_000; // 0.01 SOL

pub fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = take_flag(&mut args, "--json");
    let cmd = args.first().cloned().unwrap_or_else(|| "help".to_string());
    let rest: &[String] = if args.is_empty() { &[] } else { &args[1..] };
    match cmd.as_str() {
        "preflight" => cmd_preflight(rest, json),
        "audit" => cmd_audit(rest, json),
        "trace" => cmd_trace(rest, json),
        "exhibit" => cmd_exhibit(json),
        "help" | "-h" | "--help" => help(),
        "version" | "-V" | "--version" => version(),
        other => {
            eprintln!("riverrun: unknown command '{other}'\n");
            help();
            std::process::exit(2);
        }
    }
}

/// Remove a `--flag` from the argument list wherever it appears, returning
/// whether it was present. Keeps positional parsing simple and order-free.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn version() {
    println!("riverrun {}", env!("CARGO_PKG_VERSION"));
}

/// Reject a malformed address before spending any RPC calls: a typo would
/// otherwise come back empty and be misread as "rootless" / "no crowd".
fn require_pubkey(kind: &str, s: &str) {
    if !valid_pubkey(s) {
        eprintln!("riverrun: '{s}' is not a valid Solana {kind} (base58, 32 bytes).");
        std::process::exit(2);
    }
}

/// Map an anonymity result to a scanner-style severity, so `audit` reads like a
/// finding and not just a metric. `critical` when any member is alone in their
/// provenance class (fully de-anonymized), then by how far effective k has fallen
/// below the advertised set.
fn severity(effective: f64, advertised: usize, worst_case: usize) -> &'static str {
    if advertised == 0 {
        return "unknown";
    }
    if worst_case <= 1 {
        return "critical";
    }
    match effective / advertised as f64 {
        r if r < 0.5 => "high",
        r if r < 0.8 => "medium",
        _ => "low",
    }
}

/// Exit cleanly when a live command recovered no data, distinguishing a genuine
/// empty result from an RPC that could not be reached — because for a privacy
/// tool a network failure must never be reported as "private".
fn no_data_exit(rpc: &Rpc, empty_reason: &str) -> ! {
    if rpc.failures > 0 {
        eprintln!(
            "\ncould not reach the RPC at {} ({} failed call(s)). Not reporting a\n\
             result: a network failure must never read as 'private'. Point $SOLANA_RPC\n\
             at a reliable endpoint and retry.",
            rpc.endpoint(),
            rpc.failures
        );
    } else {
        eprintln!("\n{empty_reason}");
    }
    std::process::exit(1);
}

fn help() {
    println!(
        "riverrun — measure and defend behavioural anonymity on Solana\n\
         \n\
         USAGE\n\
         \x20 riverrun <command> [args]\n\
         \n\
         COMMANDS\n\
         \x20 preflight <wallet> [pool] [n]   the anonymity YOU would get in a pool,\n\
         \x20                                 before you deposit — the one to run first\n\
         \x20 audit     <pool> [n]            a live pool's effective k vs its advertised k\n\
         \x20 trace     <wallet>              one wallet's funding provenance, one hop at a time\n\
         \x20 exhibit                         the effective-k metric on riverrun's own\n\
         \x20                                 constructions (offline, no RPC)\n\
         \x20 version                         print the version and exit\n\
         \n\
         OPTIONS\n\
         \x20 --json                          emit a machine-readable JSON result on stdout\n\
         \x20                                 (progress stays on stderr; pipe with `| jq`)\n\
         \n\
         DEFAULTS\n\
         \x20 pool  {DEFAULT_POOL}  (Privacy Cash)\n\
         \x20 n     15 depositors sampled\n\
         \x20 RPC   $SOLANA_RPC, else mainnet-beta\n\
         \n\
         Every result from live data is a floor: bounded trace, SOL flows only.\n\
         'safe' means 'no cheap attribution found', never 'anonymous'.\n\
         Exit codes: 0 ok, 1 no data (RPC / empty pool), 2 usage."
    );
}

// --- preflight --------------------------------------------------------------

fn cmd_preflight(args: &[String], json: bool) {
    let Some(wallet) = args.first() else {
        eprintln!("usage: riverrun preflight <wallet> [pool] [n]");
        std::process::exit(2);
    };
    let pool = args.get(1).map(String::as_str).unwrap_or(DEFAULT_POOL);
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);
    require_pubkey("wallet", wallet);
    require_pubkey("pool", pool);

    let mut rpc = Rpc::new();
    let mut budget = 3000;

    eprintln!("wallet : {wallet}\npool   : {pool}\n\ntracing your funding graph backward...");
    let user_class = provenance_class(&mut rpc, wallet, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
    eprintln!("  your provenance class: {}", describe(&user_class));

    eprintln!("\nsampling the pool's current depositors...");
    let depositors = pool_depositors(&mut rpc, pool, n, &mut budget);
    if depositors.is_empty() {
        no_data_exit(&rpc, "no recent SOL deposits found for this pool (inactive, or not a SOL pool).");
    }
    let population: Vec<String> = depositors
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let c = provenance_class(&mut rpc, d, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
            eprintln!("  depositor {:>2}: {}", i + 1, short_class(&c));
            c
        })
        .collect();

    let p = preflight(&user_class, &population);

    if json {
        let verdict = match p.verdict {
            Verdict::Exposed => "exposed",
            Verdict::Weak => "weak",
            Verdict::Ok => "ok",
        };
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "preflight",
            "endpoint": rpc.endpoint(),
            "pool": pool,
            "wallet": wallet,
            "advertised_k": p.advertised_k,
            "pool_effective_k": p.pool_effective_k,
            "personal_k": p.personal_k,
            "verdict": verdict,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== pre-flight anonymity check ===");
    println!("pool                   : {pool}");
    println!("advertised anonymity   : 1 in {}", p.advertised_k);
    println!("pool effective k (now) : {:.1}", p.pool_effective_k);
    println!("YOUR crowd here        : {} of {} share your provenance class", p.personal_k, p.advertised_k);
    print!("VERDICT                : ");
    match p.verdict {
        Verdict::Exposed => println!(
            "EXPOSED\n\nYou would be alone in your provenance class. The pool's size is\n\
             irrelevant to you — an adversary reading the funding graph attributes your\n\
             action at once. Fund a fresh wallet from a source other depositors also use\n\
             (a major exchange withdrawal is the usual one), or wait for a same-origin\n\
             crowd. Anonymity is a crowd of people who look like you, not a large crowd."
        ),
        Verdict::Weak => println!(
            "WEAK\n\nOnly {} of {} depositors share your provenance class, so your real\n\
             anonymity here is far below the advertised {}. Consider funding through a\n\
             more common origin, or waiting for a larger same-class crowd.",
            p.personal_k, p.advertised_k, p.advertised_k
        ),
        Verdict::Ok => println!(
            "OK (within the trace bound)\n\n{} of {} depositors share your provenance class,\n\
             a healthy fraction, so the crowd is genuinely yours. This is a floor: a deeper\n\
             trace can only shrink your class, so 'OK' means 'no cheap attribution found'.",
            p.personal_k, p.advertised_k
        ),
    }
    println!("\n(RPC calls: {})", rpc.calls);
}

// --- audit ------------------------------------------------------------------

fn cmd_audit(args: &[String], json: bool) {
    let pool = args.first().map(String::as_str).unwrap_or(DEFAULT_POOL);
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    require_pubkey("pool", pool);

    let mut rpc = Rpc::new();
    let mut budget = 4000;

    eprintln!("pool : {pool}\n\nenumerating depositors...");
    let depositors = pool_depositors(&mut rpc, pool, n, &mut budget);
    if depositors.is_empty() {
        no_data_exit(&rpc, "no depositors recovered: no recent SOL deposits (inactive, or not a SOL pool).");
    }
    eprintln!("tracing each one's funding graph...");
    let classes: Vec<String> = depositors
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let c = provenance_class(&mut rpc, d, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
            eprintln!("  [{:>2}/{}] {}", i + 1, depositors.len(), short_class(&c));
            c
        })
        .collect();

    // class sizes for the effective-k metric
    let mut seen: Vec<(&String, usize)> = Vec::new();
    for c in &classes {
        if let Some(e) = seen.iter_mut().find(|(k, _)| *k == c) {
            e.1 += 1;
        } else {
            seen.push((c, 1));
        }
    }
    let rooted = classes.iter().filter(|c| *c != "rootless").count();
    let sizes: Vec<usize> = seen.iter().map(|(_, n)| *n).collect();
    let ek = effective_k(&sizes);

    let sev = severity(ek.effective, classes.len(), ek.worst_case);

    if json {
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "audit",
            "endpoint": rpc.endpoint(),
            "pool": pool,
            "severity": sev,
            "depositors_sampled": classes.len(),
            "reach_origin": rooted,
            "reach_origin_pct": (100.0 * rooted as f64 / classes.len() as f64),
            "provenance_classes": ek.classes,
            "advertised_k": classes.len(),
            "effective_k": ek.effective,
            "worst_case": ek.worst_case,
            "residual_bits": ek.residual_bits,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
            "note": "floor: bounded trace, SOL-only; see docs/EFFECTIVE_K.md",
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== funding-graph exposure of a live anonymity set ===");
    println!("pool                   : {pool}");
    println!("severity               : {}", sev.to_uppercase());
    println!("depositors sampled     : {}", classes.len());
    println!("reach an origin        : {rooted}/{} ({:.0}%)", classes.len(), 100.0 * rooted as f64 / classes.len() as f64);
    println!("provenance classes     : {}", ek.classes);
    println!("advertised k           : {}  ->  effective k : {:.1}  (worst case {})", classes.len(), ek.effective, ek.worst_case);
    println!(
        "\nAdvertised anonymity counts members. Effective k is what those members are\n\
         worth once an adversary sorts them by funding provenance. A floor: bounded\n\
         trace, SOL only. See docs/EFFECTIVE_K.md."
    );
    if rpc.failures > 0 {
        println!("WARNING: {} RPC call(s) failed — this is a partial floor, not the full picture.", rpc.failures);
    }
    println!("(RPC calls: {}, failures: {})", rpc.calls, rpc.failures);
}

// --- trace ------------------------------------------------------------------

fn cmd_trace(args: &[String], json: bool) {
    let Some(wallet) = args.first() else {
        eprintln!("usage: riverrun trace <wallet>");
        std::process::exit(2);
    };
    require_pubkey("wallet", wallet);
    let mut rpc = Rpc::new();
    let mut budget = 1500;

    eprintln!("wallet : {wallet}\n\ntracing backward funding graph over mainnet...");
    let class = provenance_class(&mut rpc, wallet, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);

    if json {
        let rootless = class == "rootless";
        let hubs: Vec<String> = if rootless {
            Vec::new()
        } else {
            class.split('+').map(String::from).collect()
        };
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "trace",
            "endpoint": rpc.endpoint(),
            "wallet": wallet,
            "attributable_origin": !rootless,
            "hubs": hubs,
            "trace_depth": DEPTH,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== provenance report ===");
    println!("wallet             : {wallet}");
    if class == "rootless" {
        println!("attributable origin: none within depth {DEPTH} (shallow, SOL-only trace)");
        println!(
            "\nAbsence here is the shallow bound, not proof of rootlessness — a deeper\n\
             trace or SPL-flow following may still reach an origin."
        );
    } else {
        println!("attributable origin: YES");
        for hub in class.split('+') {
            println!("    reaches hub {hub}");
        }
        println!(
            "\nThe funding graph leaks: a shallow, SOL-only backward walk already names\n\
             an attributable origin. This is the axis noise tools leave open."
        );
    }
    println!("(RPC calls: {})", rpc.calls);
}

// --- exhibit (offline) ------------------------------------------------------

fn cmd_exhibit(json: bool) {
    const SEED: u64 = 0x000C_0FFE_ED15_EA5E;
    const N: usize = 2000;

    let mut rng = SplitMix64::new(SEED);
    let rows: [(&str, &str, SchemeStats); 3] = [
        ("rooted_decoy", "rooted decoy (the field)", evaluate(&scenario::rooted_decoy(&mut rng, N, 4))),
        ("cyclic_ambiguous", "cyclic, ambiguous root", evaluate(&scenario::cyclic_ambiguous(&mut rng, N, 60, 8))),
        ("cyclic_rootless", "cyclic, rootless", evaluate(&scenario::cyclic_rootless(&mut rng, N, 60))),
    ];

    if json {
        let constructions: Vec<serde_json::Value> = rows
            .iter()
            .map(|(id, _, s)| {
                serde_json::json!({
                    "construction": id,
                    "members": s.targets,
                    "root_hit_rate": s.root_hit_rate,
                    "mean_nearest_depth": if s.mean_nearest_depth.is_nan() { serde_json::Value::Null } else { serde_json::json!(s.mean_nearest_depth) },
                    "mean_attribution_bits": s.mean_attribution_bits,
                    "cyclic_rate": s.cyclic_rate,
                    "effective_k": s.effective_k.effective,
                })
            })
            .collect();
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "exhibit",
            "offline": true,
            "members_per_row": N,
            "seed": format!("{SEED:#018x}"),
            "constructions": constructions,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    let print_row = |name: &str, s: &SchemeStats| {
        let depth = if s.mean_nearest_depth.is_nan() {
            "  n/a".to_string()
        } else {
            format!("{:5.1}", s.mean_nearest_depth)
        };
        println!(
            "{:<26}  {:>11.1}%  {:>9}  {:>13.2}  {:>9.1}%  {:>11.0}",
            name, s.root_hit_rate * 100.0, depth, s.mean_attribution_bits, s.cyclic_rate * 100.0, s.effective_k.effective
        );
    };

    println!("the funding-graph leak every noise tool leaves open\n");
    println!(
        "{:<26}  {:>12}  {:>9}  {:>13}  {:>10}  {:>11}",
        "construction", "root-hit", "depth", "attrib.(bits)", "in-cycle", "effective k"
    );
    println!("{}", "-".repeat(92));
    for (_, label, s) in &rows {
        print_row(label, s);
    }
    println!(
        "\nSame {N} members each row. The field's decoys still trace to one origin\n\
         (root-hit ~100%, 0 bits of doubt); circularity dissolves it — a root that\n\
         could be any of many, or none at all — worth the full set instead of a\n\
         fraction. 'rootless' holds only while funding sources are unattributable."
    );
}

// --- shared helpers ---------------------------------------------------------

fn describe(class: &str) -> String {
    if class == "rootless" {
        "rootless (no attributable origin found within the trace bound)".to_string()
    } else {
        format!("reaches {}", short_class(class))
    }
}

fn short_class(c: &str) -> String {
    if c == "rootless" {
        return "rootless".to_string();
    }
    c.split('+').map(|a| format!("{}…", &a[..8.min(a.len())])).collect::<Vec<_>>().join("+")
}

/// Distinct non-hub fee payers who moved SOL into the pool recently.
fn pool_depositors(rpc: &mut Rpc, pool: &str, want: usize, budget: &mut usize) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for sig in rpc.signatures(pool, POOL_SIG_SCAN) {
        if out.len() >= want || *budget == 0 {
            break;
        }
        *budget -= 1;
        let Some(tx) = rpc.transaction(&sig) else { continue };
        let Some(payer) = fee_payer(&tx) else { continue };
        if seen.contains(&payer) {
            continue;
        }
        let deposits = system_transfers(&tx)
            .into_iter()
            .any(|(src, dst, l)| src == payer && dst != payer && l >= MIN_DEPOSIT);
        if !deposits {
            continue;
        }
        seen.insert(payer.clone());
        if rpc.sig_count(&payer) >= HUB_THRESHOLD {
            continue; // relayer / exchange, not a user
        }
        out.push(payer);
    }
    out
}
