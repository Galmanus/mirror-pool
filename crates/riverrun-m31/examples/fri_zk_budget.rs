//! Step 4 of the simulator, reduced to a dimension count — and the count is
//! tighter than anyone here suspected.
//!
//! `examples/zk_view.rs` proved two components of the verifier's view and left
//! the FRI phase open, calling it research. It is less open than that, because
//! of one structural fact that makes it tractable:
//!
//!   **FRI folding is linear.** Every value the verifier observes during the
//!   FRI phase — each layer's sibling, at every query — is the image of the
//!   batch polynomial `ro` under a LINEAR map determined entirely by public
//!   challenges and query indices.
//!
//! So "can a simulator produce a consistent FRI transcript" is not a vague
//! question about interactive proofs. It is the same question Theorem B
//! answered for the trace openings, one level up:
//!
//! ```text
//!     is the blinding subspace surjective onto the FRI observation map?
//! ```
//!
//! If it is, the observed FRI scalars are uniform whatever the witness, a
//! simulator samples them directly, interpolates a low-degree `ro` through
//! them, and runs the honest folding — every consistency check then passes by
//! construction. If it is not, some linear functional of the witness survives
//! into the FRI transcript and no such simulator exists.
//!
//! ## The counting
//!
//! **What the verifier observes.** Per query: one sibling at the first layer,
//! then one per folding layer. With `max_log_arity = 1` each layer halves, and
//! `log_final_poly_len = 0` folds to a constant, so from a committed LDE of
//! `2^ℓ` points the circle PCS does one `fold_y` and then `ℓ − 1` binary
//! folds. Observations per query are therefore `ℓ`, and the FRI phase reveals
//!
//! ```text
//!     m = Q · ℓ,      ℓ = log₂(2N · 2^β)
//! ```
//!
//! scalars, each a linear functional of `ro`.
//!
//! **What blinds them.** Two independent sources, and only two:
//!
//!  - the trace blinder, which enters `ro` through the DEEP reduction as
//!    `Σ_i α^i · Z_D·R_i / (X − ζ)`. As the per-column blinders range over
//!    `L_N^w` independently and the `α^i` are nonzero, this ranges over
//!    `{ Z_D·R/(X − ζ) : R ∈ L_N }` — an **`N`-dimensional** subspace, NOT
//!    `w · N`. The width does not help: the `α`-reduction collapses it.
//!  - the randomisation polynomial, committed over the doubled trace domain,
//!    contributing its own **`2N` dimensions**.
//!
//! So the blinding available to the FRI phase is `3N`, against `Q · ℓ`
//! observations.
//!
//! ## What that says, and it is not comfortable
//!
//! The margin `3N − Q·ℓ` is the quantity to watch, and it moves the WRONG way
//! under the parameter change the soundness budget recommends. Raising the
//! blowup adds folding layers, so it multiplies the observation count by
//! roughly `ℓ`, while soundness only gains linearly in `β`. **Soundness and
//! this zero-knowledge margin pull in opposite directions on the same knob.**
//!
//! That is the finding this file exists to report, and it was invisible while
//! the FRI phase was being waved at as "inherited".
//!
//! ## Honest scope
//!
//! Dimension counting gives a NECESSARY condition, not a sufficient one. A
//! positive margin means the blinding *could* cover the observations; whether
//! it does requires the surjectivity of a specific linear map, which is the
//! Theorem-B computation one level up and is not done here. A NEGATIVE margin,
//! by contrast, is conclusive in the bad direction: fewer blinding dimensions
//! than observed scalars means some functional of the witness survives, and no
//! simulator of this shape can exist.
//!
//! Two further caveats, so the numbers are not read as more than they are.
//! The per-query observation count `ℓ` is an upper bound: colliding query
//! indices and the shared first layer reduce it. And the randomisation
//! polynomial's `2N` is its committed dimension; how much of it reaches the
//! batch depends on the DEEP reduction, which this file does not model.
//!
//! Run: cargo run --release --example fri_zk_budget

/// Log2 of the committed height. The ZK path commits `2N` for a trace of `N`.
fn log_committed(log_rows: usize) -> usize {
    log_rows + 1
}

/// Folding layers the circle PCS produces from a committed LDE of `2^l` points:
/// one `fold_y`, then binary folds down to a constant.
fn layers(log_rows: usize, log_blowup: usize) -> usize {
    log_committed(log_rows) + log_blowup
}

struct Row {
    log_rows: usize,
    queries: usize,
    log_blowup: usize,
}

fn main() {
    println!(
        "The FRI phase, as a dimension count.\n\n\
         observations  m = Q · l          (l = folding layers, each query one sibling per layer)\n\
         blinding      3N = N + 2N        (trace blinder collapsed by alpha, plus the randomisation poly)\n\
         margin        3N − m             (negative is conclusive: no simulator of this shape)\n"
    );
    println!(
        "{:<34} {:>4} {:>4} {:>6} {:>7} {:>8} {:>9}",
        "configuration", "N", "l", "m", "3N", "margin", "verdict"
    );

    let rows = [
        Row { log_rows: 6, queries: 20, log_blowup: 2 },
        Row { log_rows: 6, queries: 16, log_blowup: 6 },
        Row { log_rows: 6, queries: 12, log_blowup: 7 },
        Row { log_rows: 5, queries: 20, log_blowup: 2 },
        Row { log_rows: 7, queries: 20, log_blowup: 2 },
        Row { log_rows: 7, queries: 16, log_blowup: 6 },
        Row { log_rows: 8, queries: 16, log_blowup: 6 },
    ];

    let mut any_negative = false;
    for r in &rows {
        let n = 1usize << r.log_rows;
        let l = layers(r.log_rows, r.log_blowup);
        let m = r.queries * l;
        let blind = 3 * n;
        let margin = blind as isize - m as isize;
        if margin < 0 {
            any_negative = true;
        }
        let name = format!(
            "{} rows, {} queries, blowup 2^{}",
            n, r.queries, r.log_blowup
        );
        println!(
            "{:<34} {:>4} {:>4} {:>6} {:>7} {:>8} {:>9}",
            name,
            n,
            l,
            m,
            blind,
            margin,
            if margin < 0 { "NO SIM" } else { "possible" }
        );
    }

    println!();
    if any_negative {
        println!(
            "At least one configuration has FEWER blinding dimensions than the FRI phase\n\
             reveals scalars. For those, the counting is conclusive in the bad direction:\n\
             a linear functional of the witness survives into the transcript, and no\n\
             simulator that samples the observations and interpolates can exist.\n"
        );
    }

    println!(
        "The interaction worth naming, because it was invisible until the FRI phase\n\
         stopped being waved at:\n\n\
         SOUNDNESS improves as Q · log_blowup. The ZERO-KNOWLEDGE margin degrades as\n\
         Q · (log_committed + log_blowup). The same knob moves them in opposite\n\
         directions, and the zero-knowledge side degrades FASTER, because it pays the\n\
         committed height on top of the blowup.\n\n\
         So the configuration the soundness budget recommends — 16 queries at blowup\n\
         64, which buys 104 conjectured bits for less verifier CPU — is exactly the\n\
         configuration this count flags. Adopting it on the soundness argument alone\n\
         would have traded a zero-knowledge property for a soundness number without\n\
         anyone noticing the trade.\n\n\
         The lever that helps BOTH: trace height. It adds 3 blinding dimensions per\n\
         row while adding only Q observations per doubling, so taller traces widen the\n\
         margin. That costs prover time and envelope, and it is the direction to\n\
         measure next."
    );
}
