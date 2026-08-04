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
    // The soundness budget (examples/soundness_budget.rs) says bits scale as
    // queries x log_blowup while envelope scales with queries alone, so the
    // blowup is the lever. These points test that: same or fewer queries at a
    // higher blowup, against both the envelope and the bit target.
    for (log_rows, q, lb) in [
        (6usize, 20usize, 2usize),
        (7, 20, 2),
        (7, 16, 6),
        (7, 12, 7),
    ] {
        let n = 1usize << log_rows;
        let k = q + 1;
        let (proof, _, _, _) = prove_binding_crowd(
            secret, action, round, blinder, q, lb, log_rows,
            riverrun_m31::zk::Seed::reproducible(42),
        );
        let bytes = proof.to_postcard();
        let conj = q * lb + 8;
        println!(
            "N={n:3} q={q:2} blowup=2^{lb}: hiding {} | soundness ~2^{conj} conjectured, ~2^{} provable | proof {} B ({:.0}% envelope){}",
            if k <= n / 2 { "UNCONDITIONAL" } else { "computed    " },
            q * lb / 2 + 8,
            bytes.len(),
            bytes.len() as f64 / 1_320.96,
            if bytes.len() as f64 <= 132_096.0 { "" } else { "  OVER" },
        );
    }
}
