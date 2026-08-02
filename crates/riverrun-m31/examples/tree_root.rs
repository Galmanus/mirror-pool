//! Compute the Merkle root of a credential tree, the issuer-side counterpart
//! of `prove_relation`. Reads a leaves file (one 64-byte-hex digest per line,
//! exactly 16 lines for DEPTH = 4) and prints the root as 64-byte hex.
//!
//! Run: cargo run --release --example tree_root -- <leaves_file>

use riverrun_m31::{compress, DEPTH, DIGEST_LEN};

fn main() {
    let path = std::env::args().nth(1).expect("usage: tree_root <leaves_file>");
    let raw = std::fs::read_to_string(&path).expect("read leaves file");
    let leaves: Vec<[u64; DIGEST_LEN]> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let l = l.trim();
            assert_eq!(l.len(), DIGEST_LEN * 16, "each digest line must be {} hex chars", DIGEST_LEN * 16);
            let bytes: Vec<u8> = (0..l.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&l[i..i + 2], 16).unwrap())
                .collect();
            let v: Vec<u64> =
                bytes.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            v.try_into().unwrap()
        })
        .collect();
    assert_eq!(leaves.len(), 1 << DEPTH, "need exactly {} digests", 1 << DEPTH);

    let mut level = leaves;
    while level.len() > 1 {
        level = level.chunks(2).map(|p| compress(p[0], p[1])).collect();
    }
    let root_hex: String = level[0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{root_hex}");
}
