//! End-to-end demo of the behavioral pool: **Tornado Cash for actions, not funds.**
//!
//! Five members commit the *same* action, then all execute it in one synchronized
//! round. The public transcript is printed — identical actions, distinct
//! nullifiers, one root — and the point is what is *absent*: any way to map an
//! executed action back to the member who committed it. Then two guards fire: a
//! double-execution and a tampered action, both rejected.
//!
//! Run: `cargo run -p riverrun-core --example behavior_pool`

use riverrun_core::commitment::Secret;
use riverrun_core::nullifier::RoundId;
use riverrun_core::pool::{ActionSpec, BehaviorPool};

fn main() {
    // A public action. Amount/target are NOT hidden — the *author* is.
    // (In practice this is the hash of e.g. "withdraw 1 SOL from protocol P".)
    let action = ActionSpec(*blake3::hash(b"withdraw 1 SOL from protocol P").as_bytes());
    let round = RoundId::from_bytes(*blake3::hash(b"round-2026-07-22T17:00Z").as_bytes());

    let mut pool = BehaviorPool::new();

    // --- Commit phase ("deposits") ---------------------------------------
    // Five distinct members each commit the identical action.
    let members: Vec<(Secret, usize)> = (0u8..5)
        .map(|i| {
            let secret = Secret::from_bytes(*blake3::hash(&[i; 32]).as_bytes());
            let idx = pool.commit(&secret, &action);
            (secret, idx)
        })
        .collect();

    println!("riverrun — Tornado for behavior (not funds)\n");
    println!("committed members : {}", pool.len());
    println!("set root          : {}\n", hex8(&pool.root().unwrap()));

    // --- Execute + settle phase ("withdrawals" / saques) -----------------
    // All members execute the same action in one synchronized round.
    println!("synchronized round — public transcript the observer sees:");
    println!("{:<4}  {:<20}  {:<18}", "#", "action (public)", "nullifier");
    println!("{}", "-".repeat(48));
    for (n, (secret, idx)) in members.iter().enumerate() {
        let exec = pool
            .prove_execution(secret, &action, *idx, round)
            .expect("member can prove");
        let settled = pool.settle(&exec).expect("settles");
        println!(
            "{:<4}  {:<20}  {}",
            n + 1,
            hex8(settled.as_bytes()),
            hex8(exec.statement.nullifier.as_bytes())
        );
    }

    println!(
        "\nEvery row is the SAME action with a DISTINCT nullifier, all under one\n\
         root. The nullifier is H(secret‖round) — unlinkable to any commitment.\n\
         An observer's chance of mapping any execution to its author is 1/{}.\n",
        members.len()
    );

    // --- Guards ----------------------------------------------------------
    // 1. A member cannot execute twice in the same round (anti-replay).
    let (secret0, idx0) = &members[0];
    let replay = pool
        .prove_execution(secret0, &action, *idx0, round)
        .unwrap();
    println!(
        "double execution, same round  -> {:?}",
        pool.settle(&replay).unwrap_err()
    );

    // 2. The public action cannot be swapped after proving (action binding).
    let mut tampered = pool
        .prove_execution(
            &members[1].0,
            &action,
            members[1].1,
            RoundId::from_bytes([9; 32]),
        )
        .unwrap();
    tampered.action = ActionSpec([0xAA; 32]);
    println!(
        "tampered action after proof   -> {:?}",
        pool.settle(&tampered).unwrap_err()
    );
}

/// First 8 bytes of a 32-byte value as hex, for compact display.
fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "…"
}
