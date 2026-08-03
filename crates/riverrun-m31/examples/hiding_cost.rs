//! Price the hiding machinery natively, and emit proofs for the on-chain
//! measurement. See `src/hiding.rs` for what this does and does not build.
//!
//! Run: cargo run --release --example hiding_cost --features wire-postcard -- [outdir]

use riverrun_m31::hiding::{prove_binding_hiding_cost, verify_binding_hiding_cost};
use riverrun_m31::{CONTEXT_LEN, SECRET_LEN};

fn main() {
    let outdir = std::env::args().nth(1);
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 2000 + i as u64);
    let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 3000 + i as u64);

    // Random COLUMNS are not swept here: `BaseAir::width` fixes the trace
    // width, so appending unconstrained columns makes verification fail
    // (measured: 64 rows + 4 columns verifies false). Blinding columns need
    // the AIR to declare them, which is part of the AIR work this instrument
    // deliberately does not fake. Their cost is small anyway next to the
    // ~700-column Poseidon2 trace.
    // (log_rows, queries). Hiding needs the committed trace to hold at least
    // `queries` random rows beside the real ones, so a 2^k-row commitment
    // supports about 2^(k-1) queries. These are the pairs that satisfy that
    // and the ones that bracket the transaction-size cap.
    for (log_rows, queries) in [(2usize, 40usize), (6, 40), (7, 40), (6, 32), (6, 26)] {
        let random_cols = 0;
        let (proof, leaf, nullifier) =
            prove_binding_hiding_cost(secret, action, round, queries, log_rows, random_cols);
        let ok = verify_binding_hiding_cost(&proof, action, round, leaf, nullifier, queries);
        let bytes = proof.to_postcard();
        println!(
            "{} rows, {} queries: verify={ok}, degree_bits={}, proof {} B ({:.0}% of the 132,096 B tx cap)",
            1 << log_rows,
            queries,
            proof.degree_bits(),
            bytes.len(),
            bytes.len() as f64 / 1_320.96
        );
        assert!(ok, "the hiding-cost config must still prove and verify");

        if let Some(dir) = &outdir {
            let tag = format!("{}r{}q", 1 << log_rows, queries);
            std::fs::write(format!("{dir}/hiding_{tag}.postcard"), &bytes).unwrap();
            let mut publics = Vec::new();
            for v in action.iter().chain(&round).chain(&leaf).chain(&nullifier) {
                publics.extend_from_slice(&v.to_le_bytes());
            }
            std::fs::write(format!("{dir}/hiding_{tag}_publics.le64"), &publics).unwrap();
        }
    }

    // The soundness of the statement must survive the config change: a wrong
    // public value has to be rejected exactly as in the production config.
    let (proof, leaf, mut nullifier) =
        prove_binding_hiding_cost(secret, action, round, 40, 6, 0);
    nullifier[0] ^= 1;
    assert!(
        !verify_binding_hiding_cost(&proof, action, round, leaf, nullifier, 40),
        "tampered public values must be rejected under the hiding config too"
    );
    println!("tampered publics rejected: soundness survives the salted MMCS");
}
