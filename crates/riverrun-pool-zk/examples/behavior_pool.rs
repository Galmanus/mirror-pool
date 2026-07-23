//! End-to-end demo of the behavioral pool: **Tornado Cash for actions, not funds.**
//!
//! Four members commit the *same* action, then all execute it in one synchronized
//! round. The public transcript is printed — identical actions, distinct
//! nullifiers, one root — and the point is what is *absent*: any way to map an
//! executed action back to the member who committed it. Then two guards fire, and
//! both are enforced by the post-quantum STARK rather than by a field comparison:
//! a double execution, and an execution that swaps in an action the member never
//! committed.
//!
//! Run: `cargo run --manifest-path crates/riverrun-pool-zk/Cargo.toml --example behavior_pool`

use riverrun_pool_zk::{Action, Secret, ZkPool};
use riverrun_stark::{BaseElement, Hash};

fn main() {
    // A public action. Amount/target are NOT hidden — the *author* is.
    // (In practice this is the hash of e.g. "withdraw 1 SOL from protocol P".)
    let action: Action = [BaseElement::new(0x5749_5448_4452_4157), BaseElement::new(1)];
    let round: u64 = 2026_07_23;

    let mut pool = ZkPool::new();

    // --- Commit phase ("deposits") ---------------------------------------
    // Four distinct members each commit the identical action.
    let members: Vec<(Secret, usize)> = (1u128..=4)
        .map(|i| {
            let secret: Secret = [BaseElement::new(0xA11CE * i), BaseElement::new(0xB0B * i)];
            let idx = pool.commit(secret, action);
            (secret, idx)
        })
        .collect();

    println!("riverrun — Tornado for behavior (not funds)\n");
    println!("committed members : {}", pool.len());
    println!("set root          : {}\n", hex8(&pool.root().unwrap()));

    // --- Execute + settle phase ("withdrawals" / saques) -----------------
    println!("synchronized round — public transcript the observer sees:");
    println!("{:<4}  {:<20}  {:<18}  {}", "#", "action (public)", "nullifier", "proof");
    println!("{}", "-".repeat(66));
    for (n, (secret, idx)) in members.iter().enumerate() {
        let exec = pool.prove_execution(*secret, *idx, round, action);
        let bytes = exec.proof.len();
        pool.settle(&exec).expect("settles");
        println!(
            "{:<4}  {:<20}  {:<18}  {} B",
            n + 1,
            hex8(&Hash::new(action[0], action[1])),
            hex8(&exec.nullifier),
            bytes
        );
    }

    println!(
        "\nEvery row is the SAME action with a DISTINCT nullifier, all under one\n\
         root. The nullifier is Rescue(secret‖round), unlinkable to any commitment,\n\
         and the proof carries no witness — settle never sees a secret.\n\
         An observer's chance of mapping any execution to its author is 1/{}.\n",
        members.len()
    );

    // --- Guards ----------------------------------------------------------
    // 1. A member cannot execute twice in the same round (anti-replay).
    let (secret0, idx0) = &members[0];
    let replay = pool.prove_execution(*secret0, *idx0, round, action);
    println!("double execution, same round  -> {:?}", pool.settle(&replay).unwrap_err());

    // 2. An action the member never committed. The leaf is Rescue(secret, action),
    //    and the action is a public input of the same proof, so this is caught by
    //    the proof failing to verify — not by comparing a field.
    let mut swapped = pool.prove_execution(members[1].0, members[1].1, round + 1, action);
    swapped.action = [BaseElement::new(0xDEAD), BaseElement::new(0xBEEF)];
    println!("action the member never committed -> {:?}", pool.settle(&swapped).unwrap_err());
}

/// First 8 bytes of a digest as hex, for compact display.
fn hex8(h: &Hash) -> String {
    h.to_bytes()[..8].iter().map(|b| format!("{b:02x}")).collect::<String>() + "…"
}
