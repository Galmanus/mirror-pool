//! Prove one authorized action WITNESS-HIDING: the zk binding proof
//! (`HidingCirclePcs`: blinded trace commitment, salted MMCS, randomized
//! quotient chunks) in the postcard wire format the Soroban hiding-probe
//! contract's `verify_zk` entry reads. Unlike `prove_action`, a published
//! proof does not leak the credential secret.
//!
//! Run: cargo run --release --example prove_action_zk --features wire-postcard -- \
//!        <secret_hex> <action_hex> <round_hex> <num_queries> <log_blowup> <outdir>
//!
//! The hiding configuration that fits one Stellar transaction, measured on
//! testnet (tx d9193714): 20 queries, log_blowup 2, 32 rows. Prover-side
//! randomness (blinding polynomials, leaf salts) is seeded from the OS
//! entropy pool, NOT a fixed test seed.

use riverrun_m31::zk::{prove_binding_zk_tuned, Seed};
use riverrun_m31::{CONTEXT_LEN, SECRET_LEN};

fn parse8(name: &str, hex: &str) -> [u64; 8] {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), 64, "{name} must be 64 bytes (8 LE u64s) of hex");
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()))
}

/// Hex of the little-endian bytes of `vals`. A slice, not a fixed `[u64; 16]`:
/// the leaf and nullifier are truncated digests now, because publishing a
/// permutation's full output let anyone invert it and recover the secret.
fn hex_limbs(vals: &[u64]) -> String {
    let mut s = String::new();
    for v in vals {
        for b in v.to_le_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

fn os_entropy_seed() -> Seed {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("reading /dev/urandom for the blinding seed must succeed");
    Seed::from_bytes(bytes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: prove_action_zk <secret_hex> <action_hex> <round_hex> <num_queries> <log_blowup> <outdir>"
        );
        std::process::exit(2);
    }
    let secret: [u64; SECRET_LEN] = parse8("secret", &args[1]);
    let action: [u64; CONTEXT_LEN] = parse8("action", &args[2]);
    let round: [u64; CONTEXT_LEN] = parse8("round", &args[3]);
    let num_queries: usize = args[4].parse().expect("num_queries must be a number");
    let log_blowup: usize = args[5].parse().expect("log_blowup must be a number");
    let outdir = &args[6];

    // The smallest power-of-two trace height satisfying the hiding margin
    // (rows >= queries + 2 for this AIR).
    let log_rows = (num_queries + 2).next_power_of_two().trailing_zeros() as usize;

    let (proof, leaf, nullifier) = prove_binding_zk_tuned(
        secret,
        action,
        round,
        num_queries,
        log_blowup,
        log_rows.max(2),
        os_entropy_seed(),
    );

    let mut publics = Vec::with_capacity((2 * CONTEXT_LEN + 2 * leaf.len()) * 8);
    for v in action.iter().chain(&round).chain(&leaf).chain(&nullifier) {
        publics.extend_from_slice(&v.to_le_bytes());
    }
    let proof_bytes = proof.to_postcard();
    let proof_path = format!("{outdir}/proof_zk.postcard");
    let publics_path = format!("{outdir}/publics_zk.le64");
    std::fs::write(&proof_path, &proof_bytes).unwrap();
    std::fs::write(&publics_path, &publics).unwrap();

    println!(
        "{{\"proof\":\"{proof_path}\",\"publics\":\"{publics_path}\",\"proof_bytes\":{},\"leaf\":\"{}\",\"nullifier\":\"{}\"}}",
        proof_bytes.len(),
        hex_limbs(&leaf),
        hex_limbs(&nullifier)
    );
}
