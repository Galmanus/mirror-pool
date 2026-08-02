//! Prove the FULL riverrun relation against an EXTERNAL credential tree, for
//! the pq402 relation mode: binding (secret behind the leaf, bound to action
//! and round) plus membership (that leaf's digest under the issuer's root via
//! a private path), both in the postcard wire format.
//!
//! Run: cargo run --release --example prove_relation --features wire-postcard -- \
//!        <secret_hex> <action_hex> <round_hex> <leaves_file> <binding_q> <outdir>
//!
//! `leaves_file` holds the issuer's full leaf-digest list, one 64-byte hex
//! digest (8 LE u64s) per line, exactly 16 lines (DEPTH = 4). The prover
//! derives its own digest from the binding leaf, finds its index, builds the
//! authentication path, and proves. The tree is public registry data; what
//! stays private is the secret and, inside the proof, the path position.
//!
//! Writes binding.postcard, membership.postcard, relation_publics.le64
//! (56 LE u64s: action[8] ‖ round[8] ‖ leaf[16] ‖ nullifier[16] ‖ root[8]).

use riverrun_m31::{
    compress, prove_binding_tuned, prove_membership, PathStep, CONTEXT_LEN, DEPTH, DIGEST_LEN,
    SECRET_LEN,
};

fn parse_hex_u64s(hex: &str, n: usize, what: &str) -> Vec<u64> {
    let hex = hex.trim();
    assert_eq!(hex.len(), n * 16, "{what} must be {} hex chars", n * 16);
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

fn arr8(v: &[u64]) -> [u64; 8] {
    v.try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!("usage: prove_relation <secret_hex> <action_hex> <round_hex> <leaves_file> <binding_q> <outdir>");
        std::process::exit(2);
    }
    let secret: [u64; SECRET_LEN] = arr8(&parse_hex_u64s(&args[1], 8, "secret"));
    let action: [u64; CONTEXT_LEN] = arr8(&parse_hex_u64s(&args[2], 8, "action"));
    let round: [u64; CONTEXT_LEN] = arr8(&parse_hex_u64s(&args[3], 8, "round"));
    let leaves_raw = std::fs::read_to_string(&args[4]).expect("read leaves file");
    let binding_q: usize = args[5].parse().expect("binding_q must be a number");
    let outdir = &args[6];

    let leaves: Vec<[u64; DIGEST_LEN]> = leaves_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| arr8(&parse_hex_u64s(l, 8, "leaf digest")))
        .collect();
    assert_eq!(leaves.len(), 1 << DEPTH, "leaves file must have exactly {} digests", 1 << DEPTH);

    let (binding, leaf, nullifier) = prove_binding_tuned(secret, action, round, binding_q);
    let mut digest = [0u64; DIGEST_LEN];
    digest.copy_from_slice(&leaf[..DIGEST_LEN]);
    let mut idx = leaves
        .iter()
        .position(|l| *l == digest)
        .expect("our credential digest is not in the issuer's tree");

    let mut level = leaves.clone();
    let mut path = Vec::new();
    while level.len() > 1 {
        let sib = if idx % 2 == 0 { level[idx + 1] } else { level[idx - 1] };
        path.push(PathStep { sibling: sib, node_on_right: idx % 2 == 1 });
        level = level.chunks(2).map(|p| compress(p[0], p[1])).collect();
        idx /= 2;
    }
    let path: [PathStep; DEPTH] = path.try_into().ok().unwrap();
    let (membership, root) = prove_membership(digest, path);

    let mut publics = Vec::new();
    for v in action.iter().chain(&round).chain(&leaf).chain(&nullifier).chain(&root) {
        publics.extend_from_slice(&v.to_le_bytes());
    }
    let b = binding.to_postcard();
    let m = membership.to_postcard();
    std::fs::write(format!("{outdir}/binding.postcard"), &b).unwrap();
    std::fs::write(format!("{outdir}/membership.postcard"), &m).unwrap();
    std::fs::write(format!("{outdir}/relation_publics.le64"), &publics).unwrap();
    println!(
        "{{\"binding\":\"{outdir}/binding.postcard\",\"membership\":\"{outdir}/membership.postcard\",\"publics\":\"{outdir}/relation_publics.le64\",\"binding_bytes\":{},\"membership_bytes\":{},\"root\":\"{}\"}}",
        b.len(),
        m.len(),
        level[0].iter().map(|v| v.to_le_bytes().map(|b| format!("{b:02x}")).join("")).collect::<String>()
    );
}
