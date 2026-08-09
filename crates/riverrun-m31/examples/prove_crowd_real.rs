//! Prove one unlinkable use of a credential **against a real issuer set**.
//!
//! `prove_crowd` synthesises the authentication path from a `tree_seed`: the
//! path is a formula and the printed root commits to nothing. This example is
//! the honest version. An issuer authorises `set_size` members (a roster); each
//! member's leaf is the real `permute(secret ‖ action)`; those leaves are placed
//! in a genuine depth-127 sparse Merkle tree; the root is the real fold of that
//! tree, and the authentication path handed to the membership relation is the
//! real path of one member. The root now *is* a commitment to the membership
//! set, so a proof against it is a proof of membership in a real set, not a
//! proof that some formula folds to some number.
//!
//! Run:
//!   cargo run --release --example prove_crowd_real --features wire-postcard -- \
//!     <roster_seed> <set_size> <prover_index> <action_hex> <round_hex> <outdir>
//!
//! Writes the same four files as `prove_crowd` and prints a JSON line whose
//! `root` is the real roster root. `roster_seed` fixes the whole member set
//! deterministically so the run is reproducible; in a deployment the issuer's
//! members bring their own secrets and only their leaves reach the tree.

use std::collections::BTreeMap;

use riverrun_m31::{
    compress, permute, prove_binding_crowd, prove_membership_crowd, zk::Seed, PathStep,
    BLINDER_LEN, CONTEXT_LEN, CROWD_DEPTH, DIGEST_LEN, SECRET_LEN, WIDTH,
};

const QUERIES: usize = 12;
const LOG_BLOWUP: usize = 7;
const LOG_ROWS: usize = 7;
const P: u64 = (1 << 31) - 1; // Mersenne-31 prime

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

/// The pack the binding relation uses: secret in the low limbs, context in the
/// high limbs, of a width-16 permutation input. Kept identical to the crate's
/// private `pack`, and cross-checked at runtime against the `leaf_digest` the
/// prover returns, so a divergence is a hard failure, not a silent wrong tree.
fn pack(secret: [u64; SECRET_LEN], context: [u64; CONTEXT_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..SECRET_LEN].copy_from_slice(&secret);
    out[SECRET_LEN..].copy_from_slice(&context);
    out
}

/// A member's stable tree leaf for a given action context.
fn leaf_of(secret: [u64; SECRET_LEN], action: [u64; CONTEXT_LEN]) -> [u64; DIGEST_LEN] {
    let out = permute(pack(secret, action));
    core::array::from_fn(|i| out[i])
}

/// splitmix64: a deterministic stream so a roster_seed fixes the whole set.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A member secret: eight canonical Mersenne-31 limbs derived from
/// (roster_seed, member_index). Deterministic and reproducible; in a real
/// deployment each member draws their own from the OS.
fn member_secret(roster_seed: u64, member: u64) -> [u64; SECRET_LEN] {
    let mut st = roster_seed
        .wrapping_mul(0x1000_0000_1)
        .wrapping_add(member.wrapping_add(1));
    core::array::from_fn(|_| loop {
        let v = splitmix64(&mut st) % P;
        if v != P - 1 {
            return v;
        }
    })
}

/// The blinder, from the OS: the whole unlinkability mechanism. Rejection-sampled
/// to be uniform over the field, each limb 31 bits of real entropy.
fn os_blinder() -> [u64; BLINDER_LEN] {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    core::array::from_fn(|_| loop {
        let mut b = [0u8; 4];
        f.read_exact(&mut b).expect("read /dev/urandom");
        let v = (u32::from_le_bytes(b) as u64) & P;
        if v != P {
            return v;
        }
    })
}

fn os_seed() -> Seed {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("read /dev/urandom");
    Seed::from_bytes(bytes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: prove_crowd_real <roster_seed> <set_size> <prover_index> <action_hex> <round_hex> <outdir>"
        );
        std::process::exit(2);
    }
    let roster_seed: u64 = args[1].parse().expect("roster_seed number");
    let set_size: u64 = args[2].parse().expect("set_size number");
    let prover_index: u64 = args[3].parse().expect("prover_index number");
    let action: [u64; CONTEXT_LEN] = parse8("action", &args[4]);
    let round: [u64; CONTEXT_LEN] = parse8("round", &args[5]);
    let outdir = &args[6];
    assert!(set_size >= 1 && prover_index < set_size, "prover_index must be in the set");
    std::fs::create_dir_all(outdir).unwrap();

    // 1. The issuer's roster: every authorised member's real leaf, placed at its
    //    index in a depth-127 sparse Merkle tree.
    let mut level: BTreeMap<u128, [u64; DIGEST_LEN]> = BTreeMap::new();
    for m in 0..set_size {
        level.insert(m as u128, leaf_of(member_secret(roster_seed, m), action));
    }

    // Empty-subtree roots: E[0] is the canonical empty leaf, E[k] two E[k-1]s.
    let mut empty = [[0u64; DIGEST_LEN]; CROWD_DEPTH + 1];
    for k in 1..=CROWD_DEPTH {
        empty[k] = compress(empty[k - 1], empty[k - 1]);
    }
    let get = |lvl: &BTreeMap<u128, [u64; DIGEST_LEN]>, idx: u128, k: usize| -> [u64; DIGEST_LEN] {
        lvl.get(&idx).copied().unwrap_or(empty[k])
    };

    // 2. Fold the tree, recording the prover's real authentication path.
    let mut path: Vec<PathStep> = Vec::with_capacity(CROWD_DEPTH);
    let mut cur = prover_index as u128;
    for k in 0..CROWD_DEPTH {
        let sibling = get(&level, cur ^ 1, k);
        path.push(PathStep {
            sibling,
            node_on_right: (cur & 1) == 1,
        });
        // Build the parent level over every occupied pair.
        let mut parents: BTreeMap<u128, [u64; DIGEST_LEN]> = BTreeMap::new();
        let mut seen: BTreeMap<u128, ()> = BTreeMap::new();
        for &idx in level.keys() {
            let p = idx >> 1;
            if seen.insert(p, ()).is_none() {
                let l = get(&level, p << 1, k);
                let r = get(&level, (p << 1) | 1, k);
                parents.insert(p, compress(l, r));
            }
        }
        level = parents;
        cur >>= 1;
    }
    let root: [u64; DIGEST_LEN] = get(&level, 0, CROWD_DEPTH);
    let path: [PathStep; CROWD_DEPTH] = path.try_into().unwrap_or_else(|_| unreachable!());

    // 3. Prove, for the prover's own secret, against the roster.
    let secret = member_secret(roster_seed, prover_index);
    let blinder = os_blinder();
    let (bproof, c, leaf_digest, nullifier) =
        prove_binding_crowd(secret, action, round, blinder, QUERIES, LOG_BLOWUP, LOG_ROWS, os_seed());
    assert_eq!(
        leaf_digest,
        leaf_of(secret, action),
        "the crate's leaf must equal the one this tree was built from"
    );
    let (mproof, c2, proved_root) =
        prove_membership_crowd(leaf_digest, blinder, &path, QUERIES, LOG_BLOWUP, os_seed());
    assert_eq!(c, c2, "one (leaf, blinder) commits identically in both relations");
    assert_eq!(proved_root, root, "the proved root must equal the real roster root");

    // 4. Write the wire files, exactly as prove_crowd does.
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
        "{{\"set_size\":{set_size},\"prover_index\":{prover_index},\"binding_proof\":\"{bp}\",\"membership_proof\":\"{mp}\",\"binding_bytes\":{},\"membership_bytes\":{},\"commitment\":\"{}\",\"nullifier\":\"{}\",\"root\":\"{}\",\"queries\":{QUERIES},\"log_blowup\":{LOG_BLOWUP}}}",
        bbytes.len(),
        mbytes.len(),
        hex_of(&c),
        hex_of(&nullifier),
        hex_of(&root),
    );
}
