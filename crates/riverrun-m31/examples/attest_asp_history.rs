//! Attest an ASP root history from JSON, for the compliance-layer CLI.
//!
//! Reads `[{"index": u64, "root": "0x…"}]` on argv[1] (a file), proves the
//! append-only-chain property with the Layer-3 AIR, and writes the proof plus
//! the public values (start index, first root, last root) so a verifier — or
//! an on-chain contract — can check it. The root hex is a BN254 root; it is
//! split into the tag limbs the AIR carries.
//!
//! Run: cargo run --release --example attest_asp_history --features wire-postcard -- <steps.json> <outdir>

use riverrun_m31::asp_history::{prove_asp_history, root_to_limbs, RootStep, ROOT_LIMBS};
use std::fs;

fn parse_root_hex(h: &str) -> [u64; ROOT_LIMBS] {
    let h = h.trim_start_matches("0x");
    let mut be = [0u8; 32];
    let bytes: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or(0))
        .collect();
    // right-align into 32 bytes big-endian
    let start = 32usize.saturating_sub(bytes.len());
    be[start..start + bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    root_to_limbs(&be)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: attest_asp_history <steps.json> <outdir>");
        std::process::exit(2);
    }
    let raw = fs::read_to_string(&args[1]).expect("read steps json");
    let outdir = &args[2];
    fs::create_dir_all(outdir).unwrap();

    // Minimal JSON parse: array of {"index":N,"root":"0x.."}.
    let mut steps: Vec<RootStep> = Vec::new();
    for chunk in raw.split('{').skip(1) {
        let idx = chunk
            .split("\"index\"").nth(1)
            .and_then(|s| s.split(|c: char| c == ':' || c == ',' || c == '}').nth(1))
            .and_then(|s| s.trim().parse::<u64>().ok());
        let root = chunk
            .split("\"root\"").nth(1)
            .and_then(|s| s.split('"').nth(1))
            .map(parse_root_hex);
        if let (Some(index), Some(root)) = (idx, root) {
            steps.push(RootStep { index, root });
        }
    }
    assert!(!steps.is_empty(), "no steps parsed");

    let events = steps.len();
    let log_rows = (events.next_power_of_two().trailing_zeros() as usize).max(2);
    let proof = prove_asp_history(&steps, log_rows, 20);
    let bytes = proof.to_postcard();

    let proof_path = format!("{outdir}/attestation.postcard");
    fs::write(&proof_path, &bytes).unwrap();

    let hex = |limbs: &[u64; ROOT_LIMBS]| limbs.iter().map(|l| format!("{l:08x}")).collect::<String>();
    println!(
        "{{\"proof\":\"{proof_path}\",\"proof_bytes\":{},\"events\":{events},\"start_index\":{},\"first_root_limbs\":\"{}\",\"last_root_limbs\":\"{}\"}}",
        bytes.len(),
        steps[0].index,
        hex(&steps[0].root),
        hex(&steps[events - 1].root),
    );
}
