//! Generate a real binding proof in the postcard wire format, plus its public
//! values as 48 little-endian u64s (action ‖ round ‖ leaf ‖ nullifier), for
//! feeding the Soroban m31-verify contract's CU measurement harness.
//!
//! Run: cargo run --release --example gen_binding_postcard --features wire-postcard -- <outdir> [num_queries]
//!
//! `num_queries` defaults to 40 (production). 26 is the measured maximum that
//! verifies inside one Soroban transaction (400M instruction cap).

use riverrun_m31::{prove_binding_tuned, CONTEXT_LEN, SECRET_LEN};

fn main() {
    let outdir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let num_queries: usize = std::env::args()
        .nth(2)
        .map(|s| s.parse().expect("num_queries must be a number"))
        .unwrap_or(40);
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 2000 + i as u64);
    let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 3000 + i as u64);

    let (proof, leaf, nullifier) = prove_binding_tuned(secret, action, round, num_queries);

    let mut publics = Vec::with_capacity((2 * CONTEXT_LEN + 2 * leaf.len()) * 8);
    for v in action.iter().chain(&round).chain(&leaf).chain(&nullifier) {
        publics.extend_from_slice(&v.to_le_bytes());
    }

    let proof_bytes = proof.to_postcard();
    std::fs::write(format!("{outdir}/binding_proof.postcard"), &proof_bytes).unwrap();
    std::fs::write(format!("{outdir}/binding_publics.le64"), &publics).unwrap();
    println!(
        "proof: {} bytes, publics: {} bytes -> {outdir}",
        proof_bytes.len(),
        publics.len()
    );
}
