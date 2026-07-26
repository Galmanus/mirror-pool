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
use crate::{
    effective_k, evaluate, exposure_rank, preflight, scenario, valid_pubkey, EffectiveK,
    SchemeStats, Verdict,
};

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
        "scan" => cmd_scan(rest, json),
        "watch" => cmd_watch(rest, json),
        "trace" => cmd_trace(rest, json),
        "exhibit" => cmd_exhibit(json),
        "id" => cmd_id(rest, json),
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

/// One pool's measured funding-graph exposure. The unit `audit`, `scan`, and
/// `watch` all share — a measurement, never an inference.
struct PoolMeasurement {
    depositors_sampled: usize,
    reach_origin: usize,
    ek: EffectiveK,
    severity: &'static str,
}

/// Measure a pool once: sample depositors, trace each one's provenance, and
/// reduce to effective k. `None` when no depositor crowd was recovered (so the
/// caller can tell "nothing to measure" from a real result). `verbose` prints the
/// per-depositor progress that `audit` wants and `scan`/`watch` do not.
fn measure_pool(
    rpc: &mut Rpc,
    pool: &str,
    n: usize,
    budget: &mut usize,
    verbose: bool,
) -> Option<PoolMeasurement> {
    let depositors = pool_depositors(rpc, pool, n, budget);
    if depositors.is_empty() {
        return None;
    }
    if verbose {
        eprintln!("tracing each one's funding graph...");
    }
    let classes: Vec<String> = depositors
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let c = provenance_class(rpc, d, budget, DEPTH, NODES, FUNDERS, SCAN_TX);
            if verbose {
                eprintln!("  [{:>2}/{}] {}", i + 1, depositors.len(), short_class(&c));
            }
            c
        })
        .collect();

    let mut seen: Vec<(&String, usize)> = Vec::new();
    for c in &classes {
        if let Some(e) = seen.iter_mut().find(|(k, _)| *k == c) {
            e.1 += 1;
        } else {
            seen.push((c, 1));
        }
    }
    let reach_origin = classes.iter().filter(|c| *c != "rootless").count();
    let sizes: Vec<usize> = seen.iter().map(|(_, n)| *n).collect();
    let ek = effective_k(&sizes);
    let severity = severity(ek.effective, classes.len(), ek.worst_case);
    Some(PoolMeasurement { depositors_sampled: classes.len(), reach_origin, ek, severity })
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
         \x20 scan      [pool...]             measure many pools, ranked by exposure (worst first)\n\
         \x20 watch     [pool...] [--interval s]  scan on a loop — the always-on screening agent\n\
         \x20 trace     <wallet>              one wallet's funding provenance, one hop at a time\n\
         \x20 exhibit                         the effective-k metric on riverrun's own\n\
         \x20                                 constructions (offline, no RPC)\n\
         \x20 id <new|show|erosion>          riverrun ID: one secret, a different\n\
         \x20                                 unlinkable identity per context, offline\n\
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
    let Some(m) = measure_pool(&mut rpc, pool, n, &mut budget, true) else {
        no_data_exit(&rpc, "no depositors recovered: no recent SOL deposits (inactive, or not a SOL pool).");
    };
    let PoolMeasurement { depositors_sampled, reach_origin: rooted, ek, severity: sev } = m;
    let classes_len = depositors_sampled;

    if json {
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "audit",
            "endpoint": rpc.endpoint(),
            "pool": pool,
            "severity": sev,
            "depositors_sampled": classes_len,
            "reach_origin": rooted,
            "reach_origin_pct": (100.0 * rooted as f64 / classes_len as f64),
            "provenance_classes": ek.classes,
            "advertised_k": classes_len,
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
    println!("depositors sampled     : {classes_len}");
    println!("reach an origin        : {rooted}/{classes_len} ({:.0}%)", 100.0 * rooted as f64 / classes_len as f64);
    println!("provenance classes     : {}", ek.classes);
    println!("advertised k           : {}  ->  effective k : {:.1}  (worst case {})", classes_len, ek.effective, ek.worst_case);
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

// --- scan / watch (the autonomous screening agent) --------------------------

/// Depositors sampled per pool in a multi-pool sweep — smaller than a single
/// `audit`, because breadth over many pools matters more than depth on one.
const SCAN_N: usize = 12;

/// Positional pool addresses from args, ignoring flags and the value that
/// follows `--interval`. Defaults to the built-in pool when none are given.
fn pools_from_args(args: &[String]) -> Vec<String> {
    let mut pools = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--interval" {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        pools.push(a.clone());
    }
    if pools.is_empty() {
        vec![DEFAULT_POOL.to_string()]
    } else {
        pools
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

/// Measure every pool, rank by exposure (worst first), and report. Unmeasured
/// pools are listed but never counted as private — a pool we could not reach or
/// that has no crowd is not a safe pool, it is an unknown one.
fn run_scan(pools: &[String], json: bool) {
    let mut rpc = Rpc::new();
    let mut ranked: Vec<(String, PoolMeasurement, usize)> = Vec::new();
    let mut unmeasured: Vec<(String, usize)> = Vec::new();
    for p in pools {
        eprintln!("scanning {p} ...");
        let f0 = rpc.failures;
        let mut budget = 2500;
        match measure_pool(&mut rpc, p, SCAN_N, &mut budget, false) {
            Some(m) => ranked.push((p.clone(), m, rpc.failures - f0)),
            None => unmeasured.push((p.clone(), rpc.failures - f0)),
        }
    }
    ranked.sort_by(|a, b| {
        exposure_rank(a.1.severity, a.1.ek.effective)
            .partial_cmp(&exposure_rank(b.1.severity, b.1.ek.effective))
            .unwrap()
    });

    if json {
        let rows: Vec<serde_json::Value> = ranked
            .iter()
            .enumerate()
            .map(|(i, (p, m, f))| {
                serde_json::json!({
                    "rank": i + 1,
                    "pool": p,
                    "severity": m.severity,
                    "advertised_k": m.depositors_sampled,
                    "effective_k": m.ek.effective,
                    "worst_case": m.ek.worst_case,
                    "reach_origin": m.reach_origin,
                    "reliable": *f == 0,
                    "rpc_failures": f,
                })
            })
            .collect();
        let un: Vec<serde_json::Value> = unmeasured
            .iter()
            .map(|(p, f)| {
                serde_json::json!({
                    "pool": p,
                    "measured": false,
                    "reason": if *f > 0 { "rpc_unreachable" } else { "no_deposit_crowd" },
                    "rpc_failures": f,
                })
            })
            .collect();
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "scan",
            "endpoint": rpc.endpoint(),
            "pools_scanned": pools.len(),
            "ranked": rows,
            "unmeasured": un,
            "is_floor": true,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== exposure ranking — most exposed first ===");
    println!("{:>2}  {:<8}  {:>7}  {:>5}  {:>5}  pool", "#", "severity", "eff-k", "adv-k", "worst");
    println!("{}", "-".repeat(74));
    for (i, (p, m, f)) in ranked.iter().enumerate() {
        let flag = if *f > 0 { "  (partial)" } else { "" };
        println!(
            "{:>2}  {:<8}  {:>7.1}  {:>5}  {:>5}  {}{}",
            i + 1, m.severity, m.ek.effective, m.depositors_sampled, m.ek.worst_case, p, flag
        );
    }
    for (p, f) in &unmeasured {
        let why = if *f > 0 { "RPC unreachable — NOT counted as private" } else { "no deposit crowd to measure" };
        println!(" -  {:<8}  {:>7}  {:>5}  {:>5}  {}  [{}]", "unknown", "-", "-", "-", p, why);
    }
    println!(
        "\nA floor: bounded, SOL-only traces. 'critical' = at least one member alone in its\n\
         provenance class. Unmeasured pools are unknown, never private."
    );
}

fn cmd_scan(args: &[String], json: bool) {
    let pools = pools_from_args(args);
    for p in &pools {
        require_pubkey("pool", p);
    }
    run_scan(&pools, json);
}

fn cmd_watch(args: &[String], json: bool) {
    let pools = pools_from_args(args);
    for p in &pools {
        require_pubkey("pool", p);
    }
    let interval: u64 = arg_value(args, "--interval").and_then(|s| s.parse().ok()).unwrap_or(300);
    eprintln!(
        "riverrun watch — screening {} pool(s) every {interval}s. Every pass is a fresh\n\
         measurement, never a cached inference. Ctrl-C to stop.",
        pools.len()
    );
    let mut pass = 1u64;
    loop {
        eprintln!("\n════ pass {pass} ════");
        run_scan(&pools, json);
        pass += 1;
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
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

// ---- id subcommand helpers ----

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A context string becomes an angle by hashing, so a user names contexts by words
/// ("dao-vote", "airdrop") rather than numbers.
fn context_angle(context: &str) -> u64 {
    let h = blake3::hash(context.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// riverrun ID from the command line: one secret, a different unlinkable identity per
/// context, and the erosion ruler that says when to rotate.
fn cmd_id(args: &[String], json: bool) {
    match args.first().map(|s| s.as_str()).unwrap_or("help") {
        "new" => {
            let secret = riverrun_core::commitment::Secret::random();
            let hex = hex_encode(secret.as_bytes());
            if json {
                println!("{{\"tool\":\"riverrun\",\"command\":\"id new\",\"secret\":\"{hex}\"}}");
                return;
            }
            println!("your riverrun ID secret (keep it safe, it is your whole identity):");
            println!("  {hex}");
            println!();
            println!("one secret becomes a different, unlinkable identity in every context.");
            println!("try:  riverrun id show {} dao-vote", &hex[..16]);
        }
        "show" => {
            let (Some(sec_hex), Some(context)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: riverrun id show <secret-hex> <context>");
                std::process::exit(2);
            };
            let Some(bytes) = hex_decode_32(sec_hex) else {
                eprintln!("secret must be 64 hex chars (32 bytes). mint one with: riverrun id new");
                std::process::exit(2);
            };
            let secret = riverrun_core::commitment::Secret::from_bytes(bytes);
            let angle = context_angle(context);
            let piece = secret.piece();
            let shape = hex_encode(&piece.shape(angle));
            let fit = hex_encode(&piece.fit(angle));
            let turn = hex_encode(&piece.turn(angle));
            if json {
                println!("{{\"tool\":\"riverrun\",\"command\":\"id show\",\"context\":\"{context}\",\"angle\":{angle},\"shape\":\"{shape}\",\"fit\":\"{fit}\",\"turn\":\"{turn}\"}}");
                return;
            }
            println!("context: {context}");
            println!("  shape (your identity here) : {shape}");
            println!("  fit   (your one action)    : {fit}");
            println!("  turn  (continuity tag, ZK) : {turn}");
            println!();
            println!("the same secret in another context gives a different, unlinkable shape.");
        }
        "erosion" => {
            use crate::repeated::{repeated_use_effective_k, Use};
            // one persistent identity across three contexts; its crowd intersects down
            // 6 -> 3 -> 1 against a floor of 4.
            let uses = [Use::new(1, 0..6), Use::new(2, 0..3), Use::new(3, [0u32])];
            let e = repeated_use_effective_k(30, &uses, 4.0);
            if json {
                let keff: Vec<String> = e.k_eff.iter().map(|k| format!("{k}")).collect();
                let rot = e
                    .rotate_before
                    .map(|i| (i + 1).to_string())
                    .unwrap_or_else(|| "null".into());
                println!("{{\"tool\":\"riverrun\",\"command\":\"id erosion\",\"k_min\":4,\"k_eff\":[{}],\"rotate_before_use\":{rot}}}", keff.join(","));
                return;
            }
            println!("repeated-use erosion of one persistent identity (floor k_min = 4):");
            println!();
            for (i, k) in e.k_eff.iter().enumerate() {
                let flag = if *k < 4.0 { "  <- below the floor" } else { "" };
                println!("  after use {}: effective anonymity = {:>4.1}{}", i + 1, k, flag);
            }
            println!();
            match e.rotate_before {
                Some(i) => println!("rotate (turn) before use {}: acting again under this secret drops you below the floor.", i + 1),
                None => println!("safe: the identity stays above the floor across every use."),
            }
            println!("turn resets the secret; re-fund from a common origin to reset provenance too.");
        }
        _ => {
            println!("riverrun id — one secret, a different unlinkable identity per context\n");
            println!("USAGE");
            println!("  riverrun id new                       mint a fresh secret");
            println!("  riverrun id show <secret> <context>   your shape/fit/turn in a context");
            println!("  riverrun id erosion                   how a persistent identity erodes, when to rotate");
        }
    }
}

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
