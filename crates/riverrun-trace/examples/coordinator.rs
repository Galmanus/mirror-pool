//! The provenance-aware coordinator, as an agent loop.
//!
//! An autonomous agent watches members arrive wanting to act. Each tick it runs
//! the round policy: it fires a synchronized round for the members whose funding
//! origin is well-populated, and it holds back the ones who would be exposed,
//! telling each exactly what to do. This is the coordination layer the mirror-pool
//! brief asks for --- and the agent can run it only because riverrun can *measure*
//! a crowd's anonymity, so "form a good round" becomes an objective, not a guess.
//!
//! The scene is deterministic and offline: no network, no keys. Provenance classes
//! are synthetic labels; on live data they come from `riverrun trace`.
//!
//! Run: `cargo run --release --example coordinator`

use riverrun_trace::coordinator::{coordinate, naive_effective_k, PendingIntent};

fn main() {
    const K_MIN: usize = 3;

    println!("riverrun coordinator --- an agent that forms private crowds\n");
    println!(
        "policy: admit a member only if >= {K_MIN} pending members share their funding\n\
         origin, so no admitted member is alone in their provenance class. Defer the\n\
         rest with a remedy. Fire a round when a crowd is ready.\n"
    );

    // Intents arrive over five ticks. Each is (member, funding origin).
    let ticks: Vec<Vec<(&str, &str)>> = vec![
        vec![("alice", "coinbase"), ("bob", "coinbase"), ("carol", "kraken")],
        vec![("dave", "coinbase"), ("erin", "kraken"), ("frank", "self-mined")],
        vec![("grace", "kraken"), ("heidi", "coinbase")],
        vec![("ivan", "kraken"), ("judy", "binance")],
        vec![("mallory", "kraken")],
    ];

    // The agent's waiting room: members who have arrived but not yet acted.
    let mut pending: Vec<PendingIntent> = Vec::new();

    for (t, arrivals) in ticks.iter().enumerate() {
        for (m, origin) in arrivals {
            pending.push(PendingIntent::new(*m, *origin));
        }
        let arrived: Vec<&str> = arrivals.iter().map(|(m, _)| *m).collect();
        println!("── tick {} ─ arrived: {}", t + 1, arrived.join(", "));

        let plan = coordinate(&pending, K_MIN);

        if plan.admitted.is_empty() {
            println!("   no crowd ready yet ({} waiting)\n", pending.len());
            continue;
        }

        let naive = naive_effective_k(&pending);
        println!(
            "   FIRE ROUND: {} members  |  effective-k {:.1}  (worst member {})",
            plan.advertised_k(),
            plan.effective_k,
            plan.worst_personal_k
        );
        println!(
            "     admitted: {}",
            plan.admitted.join(", ")
        );
        println!(
            "     vs batching all {} waiting: effective-k {:.1}  --  the smaller round is more private",
            pending.len(),
            naive
        );
        for d in &plan.deferred {
            println!("     hold {} ({}): {}", d.member, d.class, short(&d.reason));
        }
        println!();

        // members who acted leave the waiting room; deferred members stay.
        let acted: std::collections::HashSet<String> = plan.admitted.into_iter().collect();
        pending.retain(|p| !acted.contains(&p.member));
    }

    if !pending.is_empty() {
        let names: Vec<&str> = pending.iter().map(|p| p.member.as_str()).collect();
        println!("── still waiting for a same-origin crowd: {}", names.join(", "));
        println!(
            "   These members each have a rare funding origin. The agent will not put\n\
             them in a round that would expose them; it waits, or they re-fund from a\n\
             common origin. Refusing to act is the privacy-preserving choice."
        );
    }
}

/// Trim the remedy to one clause for the compact per-line display.
fn short(reason: &str) -> String {
    reason.split(';').next().unwrap_or(reason).trim().to_string()
}
