//! Prove ONE unlinkable use of a credential: the two leaf-committed hiding
//! relations that share a commitment `C = compress(leaf ‖ blinder)`, in the
//! postcard wire format the Soroban crowd contract reads.
//!
//! Run: cargo run --release --example prove_crowd --features wire-postcard -- \
//!        <secret_hex> <action_hex> <round_hex> <tree_seed> <outdir>
//!
//! Writes four files: `crowd_binding.postcard` + `crowd_binding_publics.le64`
//! (for `act` or `verify_crowd_binding`) and `crowd_membership.postcard` +
//! `crowd_membership_publics.le64` (for `verify_crowd_membership`). Prints a
//! JSON line with the shared commitment, the nullifier, and the Merkle root.
//!
//! The blinder is drawn from `/dev/urandom` on every run, which is what makes
//! two uses of one secret unlinkable: same secret, same context, different
//! blinder, unrelated commitments. Run this twice with the same arguments and
//! compare the printed `commitment` fields — they will differ, and nothing
//! published on-chain connects them.
//!
//! **The tree is synthesised from `tree_seed` for demonstration.** A real
//! deployment takes the authentication path from a registry whose root is
//! already published; here the path is generated and the resulting root
//! printed, so the demo has a root to verify against without shipping a
//! registry. That is a property of this example, not of the relation: the AIR
//! is indifferent to where the siblings came from.

use riverrun_m31::{
    compress, prove_binding_crowd, prove_membership_crowd, zk::Seed, PathStep, BLINDER_LEN, CONTEXT_LEN,
    CROWD_DEPTH, DIGEST_LEN, SECRET_LEN,
};

/// The configuration that clears every budget at once, each of them computed
/// rather than assumed: 128 rows, 12 queries, blowup 128.
///
///  - soundness 2^92 conjectured, 2^50 proved (`examples/soundness_budget.rs`)
///  - hiding unconditional, `k <= N/2` (Theorem B, `examples/hiding_theory.rs`)
///  - FRI zero-knowledge margin +204 (`examples/fri_zk_budget.rs`)
///  - 206.3M verifier instructions (52% of cap), 106,491 B (81% of envelope)
///
/// It beats the previous 64-row, 20-query, blowup-4 point on every one of
/// those axes simultaneously. The earlier point was not a tradeoff; it was the
/// wrong corner of a parameter space nobody had mapped.
const QUERIES: usize = 12;
const LOG_BLOWUP: usize = 7;
const LOG_ROWS: usize = 7;

fn parse8(name: &str, hex: &str) -> [u64; 8] {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), 64, "{name} must be 64 bytes (8 LE u64s) of hex");
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()))
}

fn hex_of(vals: &[u64]) -> String {
    let mut s = String::new();
    for v in vals {
        for b in v.to_le_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

/// A full-width seed for the hiding randomness, straight from the OS. The
/// blinding polynomials and the leaf salts are drawn from this, and the salts
/// are published inside the proof, so its width is a security parameter: see
/// `Seed`'s own documentation for the attack that a 64-bit seed leaves open.
fn os_seed() -> Seed {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("reading /dev/urandom must succeed");
    Seed::from_bytes(bytes)
}

/// `N` independent canonical Mersenne-31 limbs, each drawn from the OS.
///
/// The blinder is the whole unlinkability mechanism, so the entropy behind it
/// is a security parameter rather than a convenience. An earlier version of
/// this file drew ONE u64 and expanded it with an LCG: the blinder occupied
/// 248 bits of space and carried 64 bits of entropy, while the documentation
/// claimed a "uniform 248-bit blinder". The gap was found by an adversarial
/// audit (docs/AUDIT-2026-08-03.md, M1) and is closed here.
///
/// Rejection sampling rather than a modulo, so the distribution is uniform
/// over the field instead of merely close to it. A draw is rejected with
/// probability 2^-31, so the loop terminates immediately in practice.
fn os_entropy_limbs<const N: usize>() -> [u64; N] {
    use std::io::Read;
    const P: u32 = (1 << 31) - 1;
    let mut f = std::fs::File::open("/dev/urandom").expect("opening /dev/urandom must succeed");
    core::array::from_fn(|_| loop {
        let mut b = [0u8; 4];
        f.read_exact(&mut b)
            .expect("reading /dev/urandom must succeed");
        let v = u32::from_le_bytes(b) & P;
        if v != P {
            return v as u64;
        }
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 && args.len() != 8 {
        eprintln!("usage: prove_crowd <secret_hex> <action_hex> <round_hex> <tree_seed> <outdir> [queries] [log_blowup]");
        std::process::exit(2);
    }
    let queries: usize = if args.len() == 8 { args[6].parse().unwrap() } else { QUERIES };
    let log_blowup: usize = if args.len() == 8 { args[7].parse().unwrap() } else { LOG_BLOWUP };
    let secret: [u64; SECRET_LEN] = parse8("secret", &args[1]);
    let action: [u64; CONTEXT_LEN] = parse8("action", &args[2]);
    let round: [u64; CONTEXT_LEN] = parse8("round", &args[3]);
    let tree_seed: u64 = args[4].parse().expect("tree_seed must be a number");
    let outdir = &args[5];
    std::fs::create_dir_all(outdir).unwrap();

    // A fresh blinder per use. This is the whole unlinkability mechanism; a
    // fixed value here would silently undo it, and so would a value that
    // merely LOOKS wide. Every limb is drawn independently from the OS, so the
    // 248 bits of space the blinder occupies carry 248 bits of entropy.
    let blinder: [u64; BLINDER_LEN] = os_entropy_limbs();

    let (bproof, c, leaf_digest, nullifier) = prove_binding_crowd(
        secret,
        action,
        round,
        blinder,
        queries,
        log_blowup,
        LOG_ROWS,
        os_seed(),
    );

    // The synthesised authentication path (see the module doc).
    let path: [PathStep; CROWD_DEPTH] = core::array::from_fn(|i| PathStep {
        sibling: core::array::from_fn(|j| {
            (tree_seed.wrapping_add(i as u64 + 1)).wrapping_mul(4001).wrapping_add(j as u64)
                % ((1u64 << 31) - 1)
        }),
        node_on_right: (tree_seed.wrapping_add(i as u64)) % 3 == 1,
    });
    let (mproof, c2, root) =
        prove_membership_crowd(leaf_digest, blinder, &path, queries, log_blowup, os_seed());
    assert_eq!(c, c2, "one (leaf, blinder) pair must commit identically in both relations");

    // Sanity: the prover's root is the hand fold of the same path.
    let mut node = leaf_digest;
    for step in &path {
        node = if step.node_on_right {
            compress(step.sibling, node)
        } else {
            compress(node, step.sibling)
        };
    }
    assert_eq!(node, root, "the proved root must equal the hand-folded one");

    let mut bpub = Vec::new();
    for v in action.iter().chain(&round).chain(&c).chain(&nullifier) {
        bpub.extend_from_slice(&v.to_le_bytes());
    }
    let mut mpub = Vec::new();
    for v in c.iter().chain(&root) {
        mpub.extend_from_slice(&v.to_le_bytes());
    }

    let bp = format!("{outdir}/crowd_binding.postcard");
    let bpp = format!("{outdir}/crowd_binding_publics.le64");
    let mp = format!("{outdir}/crowd_membership.postcard");
    let mpp = format!("{outdir}/crowd_membership_publics.le64");
    let bbytes = bproof.to_postcard();
    let mbytes = mproof.to_postcard();
    std::fs::write(&bp, &bbytes).unwrap();
    std::fs::write(&bpp, &bpub).unwrap();
    std::fs::write(&mp, &mbytes).unwrap();
    std::fs::write(&mpp, &mpub).unwrap();

    println!(
        "{{\"binding_proof\":\"{bp}\",\"binding_publics\":\"{bpp}\",\"membership_proof\":\"{mp}\",\"membership_publics\":\"{mpp}\",\"binding_bytes\":{},\"membership_bytes\":{},\"commitment\":\"{}\",\"nullifier\":\"{}\",\"root\":\"{}\",\"queries\":{queries},\"log_blowup\":{log_blowup}}}",
        bbytes.len(),
        mbytes.len(),
        hex_of(&c),
        hex_of(&nullifier),
        hex_of(&root),
    );
}
