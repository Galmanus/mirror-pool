//! `preflight` — before you act, know the anonymity you'll actually get.
//!
//! Every privacy pool on Solana advertises `1/k`. That number counts members. It
//! says nothing about *you* — where your money came from, and whether the crowd
//! you're about to join shares your provenance or leaves you alone in it. The
//! funding graph is public, so an adversary can sort the pool by it, and the
//! honest question is not "how big is the pool" but "how big is the crowd I
//! disappear into".
//!
//! This runs that check before you deposit, against **any** pool program on
//! mainnet. It is protocol-agnostic — it reads public chain data, not the pool's
//! internals — and it is the defensive dual of `pool-provenance`: that audits a
//! pool, this protects a user.
//!
//! Usage: `preflight <YOUR_WALLET> [POOL_PROGRAM_ID] [POOL_SAMPLE]`
//! RPC via `SOLANA_RPC`, default mainnet-beta.
//!
//! Honesty, up front: the trace is bounded (public RPC, SOL flows, depth 3), so a
//! "rootless / you're fine" verdict is a floor, not a guarantee — a funded
//! analyst with a tag database sees more. Treat a clean result as "no cheap
//! attribution found", never "anonymous".

use std::collections::HashSet;

use riverrun_trace::rpc::{fee_payer, provenance_class, system_transfers, Rpc, HUB_THRESHOLD};
use riverrun_trace::{preflight, Verdict};

const DEFAULT_POOL: &str = "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD";
const POOL_SAMPLE_DEFAULT: usize = 15;
const POOL_SIG_SCAN: usize = 300;
const DEPTH: usize = 3;
const NODES: usize = 14;
const FUNDERS: usize = 4;
const SCAN_TX: usize = 6;
const TX_BUDGET: usize = 3000;

fn main() {
    let wallet = match std::env::args().nth(1) {
        Some(w) => w,
        None => {
            eprintln!("usage: preflight <YOUR_WALLET> [POOL_PROGRAM_ID] [SAMPLE]");
            std::process::exit(2);
        }
    };
    let pool = std::env::args().nth(2).unwrap_or_else(|| DEFAULT_POOL.to_string());
    let sample: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(POOL_SAMPLE_DEFAULT);

    let mut rpc = Rpc::new();
    let mut budget = TX_BUDGET;

    eprintln!("wallet : {wallet}");
    eprintln!("pool   : {pool}");
    eprintln!("\ntracing your funding graph backward...");
    let user_class = provenance_class(&mut rpc, &wallet, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
    eprintln!(
        "  your provenance class: {}",
        if user_class == "rootless" {
            "rootless (no attributable origin found within the trace bound)".to_string()
        } else {
            format!("reaches {}", short_class(&user_class))
        }
    );

    eprintln!("\nsampling the pool's current depositors...");
    let depositors = pool_depositors(&mut rpc, &pool, sample, &mut budget);
    if depositors.is_empty() {
        eprintln!("could not sample this pool's depositors (RPC, or no recent SOL deposits).");
        std::process::exit(1);
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

    println!("\n=== pre-flight anonymity check ===");
    println!("pool                    : {pool}");
    println!("depositors sampled      : {}", population.len());
    println!("advertised anonymity    : 1 in {}", p.advertised_k);
    println!("pool effective k (now)  : {:.1}", p.pool_effective_k);
    println!();
    println!(
        "YOUR crowd in this pool : {} of {} share your provenance class",
        p.personal_k, p.advertised_k
    );
    print!("VERDICT                 : ");
    match p.verdict {
        Verdict::Exposed => {
            println!("EXPOSED");
            println!(
                "\nYou would be alone in your provenance class here. The pool's size is\n\
                 irrelevant to you: an adversary who reads the funding graph attributes\n\
                 your action immediately. Depositing now buys you almost nothing.\n\
                 \n\
                 What helps: fund a fresh wallet from a source that other depositors also\n\
                 use (a major exchange withdrawal is the usual one), or wait until members\n\
                 who share your funding origin are in the pool. Anonymity is a crowd of\n\
                 people who look like you, not a large crowd."
            );
        }
        Verdict::Weak => {
            println!("WEAK");
            println!(
                "\nOnly {} of {} depositors share your provenance class, so your real\n\
                 anonymity here is far below the advertised {}. It is not zero, but the\n\
                 headline number is not yours. Consider funding through a more common\n\
                 origin, or waiting for a larger same-class crowd.",
                p.personal_k, p.advertised_k, p.advertised_k
            );
        }
        Verdict::Ok => {
            println!("OK (within the trace bound)");
            println!(
                "\n{} of {} depositors share your provenance class, a healthy fraction, so\n\
                 the pool's crowd is genuinely yours to hide in. Remember this is a floor:\n\
                 a deeper trace or a tag database can only shrink your class, never grow\n\
                 it, so 'ok' means 'no cheap attribution found', not 'anonymous'.",
                p.personal_k, p.advertised_k
            );
        }
    }
    println!("\n(RPC calls: {})", rpc.calls);
}

fn short_class(c: &str) -> String {
    if c == "rootless" {
        return "rootless".to_string();
    }
    c.split('+')
        .map(|a| format!("{}…", &a[..8.min(a.len())]))
        .collect::<Vec<_>>()
        .join("+")
}

/// Distinct non-hub fee payers who moved SOL into the pool recently.
fn pool_depositors(rpc: &mut Rpc, pool: &str, want: usize, budget: &mut usize) -> Vec<String> {
    const MIN_DEPOSIT: u64 = 10_000_000;
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
