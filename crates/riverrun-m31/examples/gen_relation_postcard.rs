//! Generate the FULL riverrun relation for on-chain verification: a binding
//! proof (leaf and nullifier share one secret, bound to action and round), a
//! membership proof (that leaf, truncated to the digest width, under a real
//! 16-leaf tree via a private path), and the composed public values, all in
//! the postcard wire format the Soroban m31-verify contract reads.
//!
//! Run: cargo run --release --example gen_relation_postcard --features wire-postcard -- \
//!        <outdir> [binding_q] [round_base]
//!
//! `binding_q` defaults to 40 (production; membership is always 40).
//! `round_base` varies the round, giving a fresh nullifier per run.
//! Writes binding.postcard, membership.postcard, relation_publics.le64
//! (56 LE u64s: action[8] ‖ round[8] ‖ leaf[16] ‖ nullifier[16] ‖ root[8]).

use riverrun_m31::{
    compress, prove_binding_tuned, prove_membership, PathStep, CONTEXT_LEN, DEPTH, DIGEST_LEN,
    SECRET_LEN,
};

fn main() {
    let outdir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let binding_q: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(40);
    let round_base: u64 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(3000);
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 2000 + i as u64);
    let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| round_base + i as u64);

    let (binding, leaf, nullifier) = prove_binding_tuned(secret, action, round, binding_q);

    let mut leaf_digest = [0u64; DIGEST_LEN];
    leaf_digest.copy_from_slice(&leaf[..DIGEST_LEN]);
    let mut level: Vec<[u64; DIGEST_LEN]> = vec![leaf_digest];
    level.extend((1..16u64).map(|i| core::array::from_fn::<u64, DIGEST_LEN, _>(|j| 500 + i * 8 + j as u64)));
    let mut path = Vec::new();
    let mut idx = 0usize;
    while level.len() > 1 {
        let sib = if idx % 2 == 0 { level[idx + 1] } else { level[idx - 1] };
        path.push(PathStep { sibling: sib, node_on_right: idx % 2 == 1 });
        level = level.chunks(2).map(|p| compress(p[0], p[1])).collect();
        idx /= 2;
    }
    let path: [PathStep; DEPTH] = path.try_into().ok().unwrap();
    let (membership, root) = prove_membership(leaf_digest, path);

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
        "binding: {} B, membership: {} B, publics: {} B -> {outdir}",
        b.len(),
        m.len(),
        publics.len()
    );
}
