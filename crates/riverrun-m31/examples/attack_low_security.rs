//! Adversarial probe: does the on-chain gate let the CALLER choose the
//! security level? Generates a genuine crowd binding proof at a deliberately
//! weak FRI parameterisation (few queries, small blowup). If a contract that
//! takes `num_queries` from its caller accepts this, the security level of
//! the whole gate is attacker-chosen, and at low query counts a forged proof
//! passes with non-negligible probability.
//!
//! Run: cargo run --release --example attack_low_security --features wire-postcard -- <queries> <log_blowup> <outdir>

use riverrun_m31::{prove_binding_crowd, BLINDER_LEN, CONTEXT_LEN, SECRET_LEN};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let queries: usize = a[1].parse().unwrap();
    let log_blowup: usize = a[2].parse().unwrap();
    let outdir = &a[3];
    std::fs::create_dir_all(outdir).unwrap();

    let secret = [13u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [77u64; CONTEXT_LEN];
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 4242 + i as u64);
    // Smallest legal height for this query count (hiding margin q + 2).
    let log_rows = ((queries + 2).next_power_of_two().trailing_zeros() as usize).max(2);

    let (proof, c, _leaf, nullifier) = prove_binding_crowd(
        secret, action, round, blinder, queries, log_blowup, log_rows, riverrun_m31::zk::Seed::reproducible(999),
    );
    let mut pubs = Vec::new();
    for v in action.iter().chain(&round).chain(&c).chain(&nullifier) {
        pubs.extend_from_slice(&v.to_le_bytes());
    }
    let bytes = proof.to_postcard();
    std::fs::write(format!("{outdir}/weak.postcard"), &bytes).unwrap();
    std::fs::write(format!("{outdir}/weak_publics.le64"), &pubs).unwrap();
    println!("queries={queries} log_blowup={log_blowup} rows={} proof={} bytes", 1<<log_rows, bytes.len());
}
