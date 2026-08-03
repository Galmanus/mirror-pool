//! Measure what a published riverrun proof reveals about its own witness.
//!
//! riverrun's thesis on Solana was that an advertised anonymity set is not the
//! delivered one, and only measurement tells them apart. This example turns
//! that instrument on riverrun's own artifact: it reports the committed
//! polynomial degree, the size of the low-degree-extension domain the FRI
//! queries sample from, and how many query openings the proof publishes, and
//! from those the probability that EVERY point of that domain is opened.
//!
//! Why that probability matters: each FRI query opening publishes a full row
//! of the committed LDE matrix. A trace column of height `n` is a polynomial
//! with `n` coefficients; publishing `n` or more of its evaluations determines
//! it uniquely by interpolation, and evaluating it back on the trace domain
//! recovers every cell of the witness, including the Poseidon2 permutation
//! inputs (the credential secret). Nothing here is a cryptanalytic break: it
//! is what a non-hiding polynomial commitment is defined to do.
//!
//! Run: cargo run --release --example privacy_audit --features wire-postcard

use riverrun_m31::{
    compress, prove_binding_tuned, prove_membership, PathStep, CONTEXT_LEN, DEPTH, DIGEST_LEN,
    SECRET_LEN,
};

// From binding.rs / membership.rs `make_config*`: CirclePcs with log_blowup 1.
const LOG_BLOWUP: usize = 1;

fn report(name: &str, degree_bits: usize, num_queries: usize) {
    let trace_height = 1usize << degree_bits;
    let lde_points = 1usize << (degree_bits + LOG_BLOWUP);
    // P(at least one of the `lde_points` positions is never sampled by
    // `num_queries` uniform draws), union bound: m * ((m-1)/m)^q.
    let m = lde_points as f64;
    let p_miss = m * ((m - 1.0) / m).powi(num_queries as i32);
    let p_all = (1.0 - p_miss).max(0.0);
    println!(
        "{name}: trace {trace_height} rows (degree_bits {degree_bits}), LDE domain {lde_points} points, \
{num_queries} query openings"
    );
    println!(
        "  openings/domain = {:.1}x; P(every domain point opened) >= {:.4}; \
interpolation needs {trace_height} of them",
        num_queries as f64 / m,
        p_all
    );
    if lde_points <= num_queries {
        println!(
            "  VERDICT: the domain is smaller than the query count. The witness is \
recoverable from the published proof by interpolation."
        );
    } else {
        println!("  VERDICT: domain exceeds query count; recovery needs the degree/query analysis.");
    }
}

fn main() {
    let secret = [7u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [5u64; CONTEXT_LEN];
    let (binding, leaf, _nullifier) = prove_binding_tuned(secret, action, round, 40);
    report("binding (40 queries)", binding.degree_bits(), 40);

    let mut digest = [0u64; DIGEST_LEN];
    digest.copy_from_slice(&leaf[..DIGEST_LEN]);
    let mut level: Vec<[u64; DIGEST_LEN]> = vec![digest];
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
    let (membership, _root) = prove_membership(digest, path);
    report("membership (40 queries)", membership.degree_bits(), 40);

    println!();
    println!("Cause, not conjecture: p3-circle's CirclePcs sets `const ZK: bool = false`");
    println!("(vendor/p3-circle-0.6.2-cutrace-patch/src/pcs.rs:122), so p3-uni-stark's");
    println!("`is_zk()` is 0 and the prover skips the randomization it applies in the ZK");
    println!("setting (prover.rs:144: \"If zk is enabled, we double the trace length by");
    println!("adding random values\"). Plonky3's hiding PCS (HidingFriPcs, ZK = true) wraps");
    println!("TwoAdicFriPcs, which Mersenne-31 cannot use: M31 has no large two-adic");
    println!("subgroup, which is the entire reason this path uses circle domains.");
}
