//! Prove one authorized action for the pq402 flow: a binding proof that a
//! credential secret stands behind a registered leaf (secret ‖ action) and a
//! fresh nullifier (secret ‖ round), in the postcard wire format the Soroban
//! m31-verify contract reads.
//!
//! Run: cargo run --release --example prove_action --features wire-postcard -- \
//!        <secret_hex> <action_hex> <round_hex> <num_queries> <outdir>
//!
//! Each hex argument is 64 bytes: 8 little-endian u64s, every value expected
//! to already be a valid Mersenne-31 element (< 2^31 - 1); the caller owns
//! that reduction so prover and verifier agree on the public values byte for
//! byte. Prints a JSON line with the output paths and the leaf/nullifier as
//! hex of 16 little-endian u64s (the credential registry format).

use riverrun_m31::{prove_binding_tuned, CONTEXT_LEN, SECRET_LEN};

fn parse8(name: &str, hex: &str) -> [u64; 8] {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), 64, "{name} must be 64 bytes (8 LE u64s) of hex");
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()))
}

fn hex16(vals: &[u64; 16]) -> String {
    let mut s = String::new();
    for v in vals {
        for b in v.to_le_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: prove_action <secret_hex> <action_hex> <round_hex> <num_queries> <outdir>");
        std::process::exit(2);
    }
    let secret: [u64; SECRET_LEN] = parse8("secret", &args[1]);
    let action: [u64; CONTEXT_LEN] = parse8("action", &args[2]);
    let round: [u64; CONTEXT_LEN] = parse8("round", &args[3]);
    let num_queries: usize = args[4].parse().expect("num_queries must be a number");
    let outdir = &args[5];

    let (proof, leaf, nullifier) = prove_binding_tuned(secret, action, round, num_queries);

    let mut publics = Vec::with_capacity((2 * CONTEXT_LEN + 2 * leaf.len()) * 8);
    for v in action.iter().chain(&round).chain(&leaf).chain(&nullifier) {
        publics.extend_from_slice(&v.to_le_bytes());
    }
    let proof_bytes = proof.to_postcard();
    let proof_path = format!("{outdir}/proof.postcard");
    let publics_path = format!("{outdir}/publics.le64");
    std::fs::write(&proof_path, &proof_bytes).unwrap();
    std::fs::write(&publics_path, &publics).unwrap();

    println!(
        "{{\"proof\":\"{proof_path}\",\"publics\":\"{publics_path}\",\"proof_bytes\":{},\"leaf\":\"{}\",\"nullifier\":\"{}\"}}",
        proof_bytes.len(),
        hex16(&leaf),
        hex16(&nullifier)
    );
}
