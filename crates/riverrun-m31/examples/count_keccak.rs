//! Count keccak calls/bytes inside a binding verify, per query count.
//!
//! Run: cargo run --release --example count_keccak --features keccak-count

use riverrun_m31::keccak::count;
use riverrun_m31::{prove_binding_tuned, verify_binding_tuned, CONTEXT_LEN, SECRET_LEN};

fn main() {
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 2000 + i as u64);
    let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 3000 + i as u64);

    for q in [4usize, 26, 40] {
        let (proof, leaf, nullifier) = prove_binding_tuned(secret, action, round, q);
        count::reset();
        let ok = verify_binding_tuned(&proof, action, round, leaf, nullifier, q);
        let (calls, bytes) = count::snapshot();
        println!(
            "q={q}: verify={ok} keccak_calls={calls} keccak_input_bytes={bytes} avg={:.1} B/call",
            bytes as f64 / calls as f64
        );
    }
}
