//! The axis the parameter search forgot: prover time.
//!
//! `examples/fri_zk_budget.rs` concluded that 128 rows at 12 queries and
//! blowup 128 beats the deployed point "on every axis at once", having
//! measured soundness, the zero-knowledge margin, verifier CPU and envelope.
//! It did not measure the prover, and it described the blowup as buying
//! security "in prover time rather than transaction bytes" as though prover
//! time were free. The LDE is `blowup x` the trace: at blowup 128 that is a
//! 128-fold increase in the dominant prover cost.
//!
//! This measures it, so the recommendation stands on four axes rather than
//! three. The interesting question is whether the same soundness and the same
//! zero-knowledge margin can be bought with MORE queries at LOWER blowup,
//! since soundness depends on the product `Q · b` while prover cost depends on
//! `2^b` alone.
//!
//! Run: cargo run --release --example prover_cost --features wire-postcard
use riverrun_m31::zk::Seed;
use riverrun_m31::{prove_binding_crowd, BLINDER_LEN, CONTEXT_LEN, SECRET_LEN};
use std::time::Instant;

/// The FRI zero-knowledge margin of `examples/fri_zk_budget.rs`.
fn zk_margin(log_rows: usize, queries: usize, log_blowup: usize) -> isize {
    let n = 1isize << log_rows;
    let layers = (log_rows + 1 + log_blowup) as isize;
    3 * n - queries as isize * layers
}

fn main() {
    let secret = [7u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [5u64; CONTEXT_LEN];
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 4242 + i as u64);

    println!(
        "{:<28} {:>7} {:>8} {:>9} {:>10} {:>9}",
        "configuration", "bits", "zk margin", "proof B", "prove ms", "verdict"
    );
    for (log_rows, q, lb) in [
        (6usize, 20usize, 2usize),  // the previous point
        (7, 12, 7),                 // what fri_zk_budget recommended
        (7, 28, 3),                 // same soundness, far lower blowup
        (7, 24, 4),
        (7, 16, 6),
        (7, 46, 2),                 // same soundness at the lowest blowup
    ] {
        let t0 = Instant::now();
        let (proof, _, _, _) = prove_binding_crowd(
            secret, action, round, blinder, q, lb, log_rows, Seed::reproducible(42),
        );
        let ms = t0.elapsed().as_millis();
        let bytes = proof.to_postcard().len();
        let bits = q * lb + 8;
        let margin = zk_margin(log_rows, q, lb);
        println!(
            "{:<28} {:>7} {:>9} {:>9} {:>10} {:>9}",
            format!("{} rows, {}q, blowup 2^{}", 1 << log_rows, q, lb),
            format!("2^{bits}"),
            margin,
            bytes,
            ms,
            if margin > 0 && bytes <= 132_096 { "ok" } else { "REJECT" }
        );
    }
    println!(
        "\nSoundness is the PRODUCT Q x log_blowup; prover cost is exponential in\n\
         log_blowup alone. So the same security is reachable at many points, and the\n\
         cheap ones are the high-query, low-blowup end — the opposite of what the\n\
         soundness budget alone suggested, and the reason a recommendation made on\n\
         three axes had to be remade on four."
    );
}
