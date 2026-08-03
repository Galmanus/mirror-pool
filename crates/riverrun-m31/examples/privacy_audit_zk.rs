//! The instrument that found the leak, re-run against the fix.
//!
//! `privacy_audit.rs` measured what a published riverrun proof reveals about
//! its own witness and returned a verdict nobody wanted: the non-hiding
//! configuration publishes more evaluations than the committed polynomial has
//! coefficients, so interpolation recovers the witness. This example runs the
//! same arithmetic against the hiding configuration (`HidingCirclePcs`) and
//! against the leaf-committed "crowd" relations, and reports the same
//! quantities so the two can be compared line by line.
//!
//! Three separate properties are audited, because they fail independently:
//!
//! 1. **Determinacy.** Does the proof publish enough evaluations to pin the
//!    committed polynomial down? Under hiding the committed polynomial has
//!    twice the trace's dimension — it is `T + Z_D·R` — so the count the
//!    attacker must beat doubles while the query count does not.
//! 2. **Recoverability of the witness even if determinacy failed.** Suppose an
//!    attacker did reconstruct the committed polynomial exactly. On the trace
//!    domain it evaluates to `T`, so this is the property hiding does NOT
//!    provide by itself, and the margin in (1) is the whole defence. Stated
//!    explicitly so nobody reads the fix as stronger than it is.
//! 3. **Linkage.** Independently of the proof system: does the public input
//!    vector carry a value that recurs across uses of one credential? This is
//!    what the crowd relations remove, and it is measured here by proving the
//!    same statement twice and diffing the public values.
//!
//! Run: cargo run --release --example privacy_audit_zk --features wire-postcard

use riverrun_m31::zk::prove_binding_zk_tuned;
use riverrun_m31::{
    prove_binding_crowd, prove_binding_tuned, BLINDER_LEN, CONTEXT_LEN, DIGEST_LEN, SECRET_LEN,
    WIDTH,
};

/// Report the determinacy margin for one configuration.
///
/// `committed_dims` is how many coefficients the committed polynomial has:
/// the trace height for a non-hiding commitment, twice that under hiding,
/// since `T' = T + Z_D·R` carries the trace's dimensions plus the blinder's.
/// `opened` is what the verifier learns: one row per FRI query, plus the
/// out-of-domain point (and its successor when the AIR has transition
/// constraints).
fn determinacy(name: &str, committed_dims: usize, opened: usize, lde_points: usize) {
    let m = lde_points as f64;
    let p_miss = m * ((m - 1.0) / m).powi(opened as i32);
    let p_all = (1.0 - p_miss).max(0.0);
    println!("{name}");
    println!(
        "  committed dimensions {committed_dims}, evaluations published {opened}, \
LDE domain {lde_points} points"
    );
    println!(
        "  openings/domain = {:.2}x; P(every domain point opened) >= {:.4}",
        opened as f64 / m,
        p_all
    );
    if opened >= committed_dims {
        println!(
            "  VERDICT: LEAKS. {opened} evaluations determine a {committed_dims}-dimensional \
polynomial; interpolate and read the witness off the trace domain."
        );
    } else {
        println!(
            "  VERDICT: UNDERDETERMINED by {} dimensions. Half of these {committed_dims} \
dimensions belong to the blinding polynomial R, and the published evaluations do not \
pin them down; every consistent completion stays equally likely.",
            committed_dims - opened
        );
    }
    println!();
}

fn main() {
    let secret = [7u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [5u64; CONTEXT_LEN];

    println!("=== 1. determinacy: can the committed polynomial be reconstructed? ===\n");

    // The shipped non-hiding configuration, for comparison: 4 rows, 40
    // queries, blowup 2. This is the line privacy_audit.rs already reported.
    let (legacy, _, _) = prove_binding_tuned(secret, action, round, 40);
    let legacy_rows = 1usize << legacy.degree_bits();
    determinacy(
        "legacy non-hiding binding (40 queries, blowup 2)",
        legacy_rows,
        40 + 1,
        legacy_rows * 2,
    );

    // The hiding configuration measured on-chain: 32 rows, 20 queries,
    // blowup 4. degree_bits records the DOUBLED commitment.
    let (hiding, _, _) = prove_binding_zk_tuned(secret, action, round, 20, 2, 5, 42);
    let hiding_committed = 1usize << hiding.degree_bits();
    determinacy(
        "hiding binding (20 queries, blowup 4)",
        hiding_committed,
        20 + 1,
        hiding_committed * 4,
    );

    println!("=== 2. what hiding does NOT do ===\n");
    println!(
        "If an attacker somehow reconstructed the committed polynomial anyway, it still\n\
         evaluates to the trace on the trace domain: T' restricted to D is T, by\n\
         construction. Hiding buys the margin measured above, not immunity to a\n\
         reconstruction that beats it. The margin is {} dimensions against {} published\n\
         evaluations, and it is statistical, not information-theoretic.\n",
        hiding_committed - 21,
        21
    );

    println!("=== 3. linkage: does the public input vector recur across uses? ===\n");

    // Legacy publics: action | round | leaf(16) | nullifier(16). The leaf is
    // a deterministic function of (secret, action), so it is identical in
    // every use with the same context.
    let (_, leaf_a, _) = prove_binding_tuned(secret, action, round, 4);
    let (_, leaf_b, _) = prove_binding_tuned(secret, action, [9u64; CONTEXT_LEN], 4);
    println!("legacy binding, two uses of one credential in one context:");
    println!(
        "  leaf identical across uses: {}  <- the linking value",
        leaf_a == leaf_b
    );
    println!("  leaf is {} of {} public field elements\n", WIDTH, 2 * CONTEXT_LEN + 2 * WIDTH);

    // Crowd publics: action | round | C(8) | nullifier(16). No leaf. C is a
    // fresh commitment per use.
    let blinder_a: [u64; BLINDER_LEN] = core::array::from_fn(|i| 7000 + i as u64);
    let blinder_b: [u64; BLINDER_LEN] = core::array::from_fn(|i| 8000 + i as u64);
    let (_, c_a, _, n_a) =
        prove_binding_crowd(secret, action, round, blinder_a, 20, 2, 5, 42);
    let (_, c_b, _, n_b) = prove_binding_crowd(
        secret,
        action,
        [9u64; CONTEXT_LEN],
        blinder_b,
        20,
        2,
        5,
        43,
    );
    println!("crowd binding, two uses of one credential in one context:");
    println!("  commitment identical across uses: {}", c_a == c_b);
    println!("  nullifier identical across uses:  {}", n_a == n_b);
    println!(
        "  leaf present in public values at all: false ({} public field elements: \
action {CONTEXT_LEN} | round {CONTEXT_LEN} | C {DIGEST_LEN} | nullifier {WIDTH})",
        2 * CONTEXT_LEN + DIGEST_LEN + WIDTH
    );
    println!();

    if c_a == c_b || n_a == n_b {
        println!("VERDICT: LINKABLE. Some public value recurs across uses.");
        std::process::exit(1);
    }
    println!(
        "VERDICT: no public value recurs across the two uses. Linkage through the proof's\n\
         own outputs is closed. Linkage through everything else — funding origin, timing,\n\
         the submitting key, network metadata — is untouched by cryptography and is the\n\
         subject riverrun's effective-k instruments measure."
    );
}
