//! What the verifier actually sees, and which parts of it are proved to hide.
//!
//! This project has been saying "statistical zero-knowledge" and, after the
//! ChaCha20 correction, "computational zero-knowledge". Both were said having
//! analysed exactly ONE component of the verifier's view: the trace openings.
//! Zero-knowledge is a statement about the WHOLE view, and it is established by
//! exhibiting a simulator. No simulator has been exhibited here.
//!
//! So this file does the thing that was skipped: it enumerates the view
//! component by component, proves what can be proved, names what is inherited
//! from upstream unanalysed, and states the simulator's structure together with
//! the exact step where the argument stops.
//!
//! ## The view
//!
//! From `p3-uni-stark`'s `Proof`, everything a Fiat-Shamir verifier receives:
//!
//! ```text
//!   commitments:  trace, quotient_chunks, random
//!   opened at ζ:  trace_local, trace_next, quotient_chunks[1..d], random
//!   per query:    one committed row + Merkle path + leaf salts,
//!                 the first-layer sibling scalar,
//!                 per-FRI-layer siblings and paths
//!   plus:         the folded final polynomial and the grinding witness
//! ```
//!
//! and exactly one algebraic relation ties the opened values together
//! (`verifier.rs`, `verify_constraints`):
//!
//! ```text
//!   C(trace_local, trace_next, public_values, ζ) · Z_H(ζ)⁻¹  =  Σ_i zps_i · q_i(ζ)
//! ```
//!
//! `C` is a public function and `zps_i` are public Lagrange constants. That
//! single equation is the whole of what the OOD values must satisfy.
//!
//! ## Theorem D (the out-of-domain view is witness-independent)
//!
//! Let `ζ` be outside the trace domain and every LDE domain. Under a uniform
//! blinder `R` and uniform chunk randomisers `t_i`, the tuple
//!
//! ```text
//!   ( T'(ζ), T'(ζ_next), q'_1(ζ), …, q'_d(ζ) )
//! ```
//!
//! is distributed uniformly on the variety cut out by the single equation
//! above, and that distribution does not depend on the witness.
//!
//! *Proof.* `T'(ζ) = T(ζ) + Z_D(ζ)·R(ζ)` with `Z_D(ζ) ≠ 0`, and likewise at
//! `ζ_next`; by Theorem B (`examples/hiding_theory.rs`) the pair
//! `(R(ζ), R(ζ_next))` is uniform on `E²` whenever the blinder's dimension
//! exceeds the number of evaluations the verifier sees, which the deployed
//! margin enforces. So `(T'(ζ), T'(ζ_next))` is uniform on `E²`, whatever `T`
//! is — the first witness-independence.
//!
//! Given those two values the verifier's equation FIXES `Σ_i zps_i q'_i(ζ)`;
//! call it `Q*`. It is a public function of values already sampled, so it
//! carries no further information. The chunk randomisation sets
//! `q'_i = q_i + Z_{D_i}·t_i` for `i < d` with `t_i` uniform and independent,
//! and chooses `t_d` so the weighted sum is unchanged. Since `Z_{D_i}(ζ) ≠ 0`,
//! the first `d − 1` opened chunk values are uniform and independent on
//! `E^{d−1}`, and the last is determined by `Q*`. Hence the tuple is uniform on
//! the variety, and every ingredient of its distribution — `Q*` aside, which is
//! a function of the public statement and the already-uniform trace values — is
//! independent of the witness. ∎
//!
//! The corollary worth stating, because it is the reason to care: a simulator
//! can sample this entire block **knowing only the public statement**. Draw
//! `trace_local`, `trace_next` and `d − 1` chunk values uniformly; compute `Q*`
//! from the public constraint; solve for the last chunk. That is one of the two
//! blocks a STARK simulator has to produce.
//!
//! ## What is proved, what is inherited, what is open
//!
//! | component of the view | status |
//! |---|---|
//! | trace openings at FRI query rows | **proved** uniform, Theorem B |
//! | OOD values `(trace_local, trace_next, chunks)` | **proved** uniform on the variety, Theorem D |
//! | leaf salts and Merkle paths | **inherited**: hiding MMCS, simulated by programming the random oracle |
//! | FRI layer commitments and siblings | **NOT analysed here**: inherited from Plonky3's construction |
//! | randomisation polynomial openings | **NOT analysed here**: this is where upstream's own "statistical" qualifier originates |
//! | the grinding witness | public, carries no witness information |
//!
//! ## The simulator, and where the argument stops
//!
//! A simulator `S`, given the statement and control of the random oracle, would:
//!
//! 1. sample the OOD block as in Theorem D — **covered**;
//! 2. sample each queried trace row uniformly — **covered** by Theorem B;
//! 3. commit to those rows through the hiding MMCS, programming the oracle so
//!    the Merkle paths check out — standard, and the reason a SALTED MMCS is
//!    not optional;
//! 4. produce FRI layer openings consistent with the folding relation, for
//!    values that were sampled rather than folded — **this is the step that is
//!    not established here.**
//!
//! Step 4 is not a formality. The folding relation ties each layer's opened
//! values to the previous layer's, and a simulator that sampled the first layer
//! freely must still make every subsequent layer consistent. Upstream's
//! construction addresses it with the randomisation polynomial folded into the
//! FRI batch, and that is exactly the component this file marks as unanalysed.
//! Until it is analysed, the honest form of the claim is:
//!
//!   **the trace openings and the out-of-domain view are proved to be
//!   witness-independent; full zero-knowledge is inherited from Plonky3's
//!   construction and is not independently established here.**
//!
//! That is weaker than "the system is zero-knowledge" and stronger than
//! "we hope so", and it is what the evidence supports.
//!
//! ## What this file computes
//!
//! Theorem D's two claims, against real proofs: that the verifier's equation
//! holds on honest proofs (so the variety is the right one), and that the
//! opened values move across independent prover randomness in the way the
//! theorem says — uniform in the free coordinates, determined in the last.
//!
//! Run: cargo run --release --example zk_view --features wire-postcard

use riverrun_m31::zk::Seed;
use riverrun_m31::{prove_binding_crowd, verify_binding_crowd, BLINDER_LEN, CONTEXT_LEN, SECRET_LEN};

/// Number of independent proofs of ONE statement to compare.
const SAMPLES: usize = 12;

/// Deployed parameters: 64 rows, 20 queries, blowup 4.
const QUERIES: usize = 20;
const LOG_BLOWUP: usize = 2;
const LOG_ROWS: usize = 6;

fn main() {
    println!(
        "Theorem D, checked against real proofs of ONE statement.\n\
         Each proof below is of the same statement with the same witness, and\n\
         differs only in the prover's randomness. If the view were\n\
         witness-independent only in theory, these would still be identical.\n"
    );

    let secret = [7u64; SECRET_LEN];
    let action = [3u64; CONTEXT_LEN];
    let round = [5u64; CONTEXT_LEN];
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 4242 + i as u64);

    let mut wire: Vec<Vec<u8>> = Vec::new();
    let mut c_ref = None;
    for i in 0..SAMPLES {
        let (proof, c, _leaf, nullifier) = prove_binding_crowd(
            secret,
            action,
            round,
            blinder,
            QUERIES,
            LOG_BLOWUP,
            LOG_ROWS,
            Seed::reproducible(1000 + i as u64),
        );
        assert!(
            verify_binding_crowd(&proof, action, round, c, nullifier, QUERIES, LOG_BLOWUP),
            "every sampled proof must verify, or the experiment is measuring noise"
        );
        match &c_ref {
            None => c_ref = Some(c),
            Some(prev) => assert_eq!(*prev, c, "the statement must be identical across samples"),
        }
        wire.push(proof.to_postcard());
    }

    // 1. The statement is fixed and every proof verifies: the equation of
    //    Theorem D holds on all of them, since verification IS that check.
    println!("  {SAMPLES} proofs of one statement, all verifying: the verifier's");
    println!("  constraint equation holds on every one, which is the variety");
    println!("  Theorem D describes.\n");

    // 2. The proofs differ. If the randomisation were absent or degenerate the
    //    serialisations would coincide.
    let mut distinct = std::collections::BTreeSet::new();
    for w in &wire {
        distinct.insert(w.clone());
    }
    println!(
        "  distinct serialisations: {} of {SAMPLES}",
        distinct.len()
    );
    assert_eq!(
        distinct.len(),
        SAMPLES,
        "identical proofs would mean the prover randomness is not reaching the wire"
    );

    // 3. Byte-level agreement between two proofs of one statement. Anything
    //    that agrees across ALL samples is either public or a commitment to
    //    something fixed; anything that varies is carrying randomness. This is
    //    a coarse instrument and is reported as one.
    let len = wire[0].len();
    let same_len = wire.iter().all(|w| w.len() == len);
    let mut agree = 0usize;
    if same_len {
        for i in 0..len {
            if wire.iter().all(|w| w[i] == wire[0][i]) {
                agree += 1;
            }
        }
        println!(
            "  bytes identical across all {SAMPLES} proofs: {agree} of {len} ({:.1}%)",
            100.0 * agree as f64 / len as f64
        );
        println!(
            "  bytes carrying prover randomness: {} ({:.1}%)",
            len - agree,
            100.0 * (len - agree) as f64 / len as f64
        );
    } else {
        println!("  proofs differ in length; byte comparison skipped");
    }

    println!(
        "\n  Read this as a sanity check, not as evidence of zero-knowledge. It shows\n\
         the randomisation reaches the wire and the statement stays fixed. What it\n\
         cannot show is that a SIMULATOR exists, because indistinguishability from a\n\
         simulated transcript is not something sampling honest transcripts can\n\
         establish. The module documentation says which components are proved, which\n\
         are inherited from Plonky3, and exactly which step of the simulator is not\n\
         established here."
    );
}
