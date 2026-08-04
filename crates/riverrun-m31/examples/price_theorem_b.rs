//! What does the unconditional hiding guarantee cost?
//!
//! Theorem B (examples/hiding_theory.rs) gives surjectivity of the blinding
//! map with no genericity and no computation, provided the verifier opens at
//! most N/2 evaluations. The deployed configuration opens k = 22 against
//! N = 32, which is above half: safe by computed rank, not by theorem.
//!
//! Doubling the trace to N = 64 puts the same k inside Theorem B. This prices
//! that, so the choice is made against numbers.
use riverrun_m31::{prove_binding_crowd, BLINDER_LEN, CONTEXT_LEN, SECRET_LEN};

fn main() {
    let secret = [7u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [5u64; CONTEXT_LEN];
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 4242 + i as u64);
    for (log_rows, q, lb) in [(5usize, 20usize, 2usize), (6, 20, 2), (6, 30, 2)] {
        let n = 1usize << log_rows;
        let k = q + 1;
        let (proof, _, _, _) = prove_binding_crowd(
            secret, action, round, blinder, q, lb, log_rows,
            riverrun_m31::zk::Seed::reproducible(42),
        );
        let bytes = proof.to_postcard();
        println!(
            "N = {n:3}, {q} queries, blowup {}: k = {k}, N/2 = {}, {} — proof {} B ({:.0}% of the 132,096 envelope)",
            1 << lb,
            n / 2,
            if k <= n / 2 { "THEOREM B: unconditional" } else { "middle band: computed" },
            bytes.len(),
            bytes.len() as f64 / 1_320.96,
        );
    }
}
