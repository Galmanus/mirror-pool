//! Prove and size an ASP root-history attestation, so the cost is measured
//! rather than assumed before anyone points the on-chain verifier at it.
use riverrun_m31::asp_history::{prove_asp_history, verify_asp_history, RootStep, ROOT_LIMBS};
use std::time::Instant;

fn root(seed: u64) -> [u64; ROOT_LIMBS] {
    core::array::from_fn(|i| (seed.wrapping_mul(1000).wrapping_add(i as u64)) % ((1 << 31) - 1))
}

fn main() {
    for (events, log_rows) in [(6usize, 3usize), (60, 6), (250, 8)] {
        let steps: Vec<RootStep> = (0..events)
            .map(|i| RootStep { index: i as u64, root: root(i as u64 + 1) })
            .collect();
        let t = Instant::now();
        let proof = prove_asp_history(&steps, log_rows, 20);
        let ms = t.elapsed().as_millis();
        let ok = verify_asp_history(&proof, steps[0].index, steps[0].root,
            steps[events - 1].root, events, 20);
        let bytes = proof.to_postcard().len();
        println!("{events} events (2^{log_rows} rows): verify={ok}  prove {ms}ms  proof {bytes} B ({:.0}% of 132KB envelope)",
            bytes as f64 / 1320.96);
    }
}
