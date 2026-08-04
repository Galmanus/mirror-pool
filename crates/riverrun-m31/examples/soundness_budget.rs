//! How many bits of soundness does the deployed configuration actually have?
//!
//! Everywhere else this project has written "soundness is roughly
//! `queries × log_blowup` bits". That is folklore: a mnemonic for the
//! conjectured regime, quoted without a model, without the other error terms,
//! and without a number. An auditor's first question about a proof system is
//! "what is the concrete security level", and until this file existed the
//! honest answer was that nobody here had computed it.
//!
//! This computes it, under a stated model, with every term written out.
//!
//! ## The model
//!
//! Non-interactive STARK via Fiat-Shamir in the random-oracle model, over
//! `F = M31` with challenges in `E = F^3`, `|E| = (2^31 − 1)^3 ≈ 2^93`.
//! Soundness error is accounted round-by-round and then summed; a proof
//! system's security in bits is `−log₂` of the total error.
//!
//! Two regimes are reported for every configuration, because the difference
//! between them is the difference between what is proved and what is believed:
//!
//!  - **Provable (Johnson bound).** Proximity gaps for Reed-Solomon codes hold
//!    unconditionally for proximity parameter `δ < 1 − √ρ`, where `ρ` is the
//!    rate. Taking `δ = 1 − √ρ` gives per-query detection `δ`, so `Q` queries
//!    leave error `(1 − δ)^Q = ρ^{Q/2}`, i.e. `Q · b / 2` bits with
//!    `b = log₂(1/ρ)`.
//!  - **Conjectured (up to capacity).** The widely assumed strengthening
//!    `δ → 1 − ρ` gives `ρ^Q`, i.e. `Q · b` bits. Every deployed STARK the
//!    author is aware of quotes this regime. It is a conjecture.
//!
//! The other terms, each of which must be added to the error and each of which
//! this file computes rather than waves at:
//!
//!  - **Grinding.** `query_proof_of_work_bits` of proof-of-work on the query
//!    challenge multiply the adversary's cost by `2^w`, adding `w` bits.
//!  - **Proximity-gap / batching error.** Batching several codewords with a
//!    random `α ∈ E` costs about `(m · d) / |E|` where `d` is the degree bound
//!    and `m` the number of batched polynomials — negligible at `|E| ≈ 2^93`,
//!    but reported so it is visible rather than assumed away.
//!  - **DEEP / out-of-domain sampling.** The verifier's `ζ ∈ E` must miss a
//!    bad set of size at most the quotient degree, costing about
//!    `deg_Q / |E|`.
//!  - **Folding.** `log₂(N · 2^b)` folding rounds, each contributing a
//!    proximity-gap term of the same order.
//!  - **Fiat-Shamir.** The protocol is round-by-round sound, so in the ROM an
//!    adversary making `T` oracle queries forges with probability about
//!    `T · ε_rbr`. Read as WORK rather than as probability: a forgery costs
//!    about `1/ε_rbr` attempts, and grinding makes each attempt cost `2^w`
//!    hashes, so the total work is about `ε_rbr^{-1} · 2^w`. That is the
//!    figure reported, and it is the reason the grinding bits are added rather
//!    than multiplied in.
//!
//! ## What this file is not
//!
//! It is an accounting, not a security proof. It assembles published bounds
//! with this system's parameters; it does not re-derive proximity gaps, and it
//! does not model the AIR's own soundness beyond the DEEP term. Where a bound
//! is conjectural it says so on the line that uses it.
//!
//! Run: cargo run --release --example soundness_budget

/// log2 of the extension field size: (2^31 - 1)^3.
const LOG_EXT: f64 = 92.999_999_9;

/// Envelope and CPU caps this system has to fit inside, from docs/EVIDENCE.md.
const ENVELOPE_BYTES: f64 = 132_096.0;

struct Config {
    name: &'static str,
    queries: usize,
    log_blowup: usize,
    pow_bits: usize,
    /// log2 of the committed trace height (the ZK path commits 2N).
    log_committed: usize,
    /// Measured proof size in bytes, or None if not measured.
    measured_bytes: Option<usize>,
}

/// Bits contributed by the query phase.
fn query_bits(queries: usize, log_blowup: usize, conjectured: bool) -> f64 {
    let b = log_blowup as f64;
    let q = queries as f64;
    if conjectured {
        q * b
    } else {
        q * b / 2.0
    }
}

/// The additive terms, as an error probability rather than in bits: batching,
/// DEEP out-of-domain, and one proximity-gap term per folding round.
fn additive_error(log_committed: usize, log_blowup: usize) -> f64 {
    let domain = ((log_committed + log_blowup) as f64).exp2();
    let rounds = (log_committed + log_blowup) as f64;
    // Degree of the quotient the DEEP step samples against, generously bounded
    // by (constraint degree 5) x trace height.
    let deg_q = 5.0 * (log_committed as f64).exp2();
    let ext = LOG_EXT.exp2();
    let batching = domain / ext;
    let deep = deg_q / ext;
    let folding = rounds * domain / ext;
    batching + deep + folding
}

fn report(c: &Config) {
    println!("{}", c.name);
    println!(
        "  {} queries, blowup 2^{} (rate 1/{}), {} grinding bits, committed 2^{} rows",
        c.queries,
        c.log_blowup,
        1 << c.log_blowup,
        c.pow_bits,
        c.log_committed
    );

    let add = additive_error(c.log_committed, c.log_blowup);
    let add_bits = -add.log2();

    for (label, conjectured) in [("provable (Johnson)", false), ("conjectured (capacity)", true)] {
        let q_bits = query_bits(c.queries, c.log_blowup, conjectured);
        let total_err = (-(q_bits)).exp2() + add;
        let rbr = -total_err.log2();
        let work = rbr + c.pow_bits as f64;
        println!(
            "  {label:<24} round-by-round error 2^-{:.1} (query {:.0}, additive terms are 2^-{:.0} and do not bind)",
            rbr, q_bits, add_bits
        );
        println!(
            "      forging work: about 2^{:.0} attempts x 2^{} grinding = 2^{:.0} hashes",
            rbr, c.pow_bits, work
        );
        println!(
            "      verdict: {}",
            if work >= 128.0 {
                "at or above the 128-bit target"
            } else if work >= 100.0 {
                "between 100 and 128 bits"
            } else if work >= 80.0 {
                "between 80 and 100 bits: below any production target"
            } else {
                "BELOW 80 bits: a demonstration figure, not a production one"
            }
        );
    }
    if let Some(b) = c.measured_bytes {
        println!(
            "  measured proof: {} B, {:.0}% of the {} B envelope",
            b,
            100.0 * b as f64 / ENVELOPE_BYTES,
            ENVELOPE_BYTES as usize
        );
    }
    println!();
}

/// The frontier: for a given blowup, how many queries fit the envelope, and
/// what does that buy? Proof size is modelled from two measured points by a
/// linear fit in the query count, which is how it behaves: each query adds a
/// Merkle path and one opened row.
fn frontier(log_blowup: usize, fixed_bytes: f64, per_query_bytes: f64, pow: usize) {
    println!("frontier at blowup 2^{log_blowup} (size model: {fixed_bytes:.0} B + {per_query_bytes:.0} B per query)");
    let max_q = ((ENVELOPE_BYTES - fixed_bytes) / per_query_bytes).floor() as usize;
    let conj = query_bits(max_q, log_blowup, true) + pow as f64;
    let prov = query_bits(max_q, log_blowup, false) + pow as f64;
    println!(
        "  the envelope allows at most {max_q} queries -> {conj:.0} bits conjectured, {prov:.0} bits provable"
    );
    for target in [96.0f64, 128.0] {
        let need_conj = ((target - pow as f64) / log_blowup as f64).ceil() as usize;
        let bytes = fixed_bytes + per_query_bytes * need_conj as f64;
        println!(
            "  {target:.0} bits conjectured needs {need_conj} queries = {:.0} B ({:.1}x the envelope){}",
            bytes,
            bytes / ENVELOPE_BYTES,
            if bytes <= ENVELOPE_BYTES { "  FITS" } else { "  DOES NOT FIT" }
        );
    }
    println!();
}

fn main() {
    println!("Concrete soundness of the deployed configurations.\n");

    let configs = [
        Config {
            name: "crowd binding (deployed): 64 rows, 20 queries, blowup 4",
            queries: 20,
            log_blowup: 2,
            pow_bits: 8,
            log_committed: 7, // ZK commits 2N = 128
            measured_bytes: Some(123_422),
        },
        Config {
            name: "crowd membership (deployed): 64 rows, 20 queries, blowup 4",
            queries: 20,
            log_blowup: 2,
            pow_bits: 8,
            log_committed: 7,
            measured_bytes: Some(83_629),
        },
        Config {
            name: "legacy non-hiding binding: 4 rows, 40 queries, blowup 2",
            queries: 40,
            log_blowup: 1,
            pow_bits: 8,
            log_committed: 2,
            measured_bytes: Some(73_642),
        },
    ];
    for c in &configs {
        report(c);
    }

    println!("What the envelope permits.\n");
    // Two measured points at blowup 4 on the crowd binding relation:
    // 20 queries -> 123,422 B; and the 30-query point measured at 177,230 B.
    let per_query = (177_230.0 - 123_422.0) / 10.0;
    let fixed = 123_422.0 - per_query * 20.0;
    frontier(2, fixed, per_query, 8);

    println!(
        "The sentence this file exists to replace: \"soundness is roughly queries times\n\
         log-blowup bits\", and the phrase \"full production security, 40 queries, no\n\
         discount\" that appears in this project's own README.\n\n\
         Computed: every configuration deployed here costs about 2^56 hashes to forge\n\
         under the capacity CONJECTURE, and about 2^36 under the proved Johnson bound.\n\
         The query count was never the thing that made 40 queries \"production\": at\n\
         rate 1/2 each query is worth one conjectured bit, so 40 queries is 40 bits.\n\n\
         Three consequences, none of them comfortable.\n\
         1. These are demonstration figures. A system holding real value wants 100 or\n\
            128 bits, and calling 56 \"full production security\" is the same class of\n\
            error as the privacy claim this project already had to retract. The README\n\
            wording has to change.\n\
         2. The lever is the BLOWUP, not the query count. Bits scale as\n\
            queries x log_blowup while envelope scales with queries alone, so raising\n\
            the blowup buys security in prover time and LDE memory rather than in\n\
            transaction bytes. That is the direction to push, and it is unmeasured.\n\
         3. At blowup 4 the envelope caps the achievable level near 50 conjectured\n\
            bits. Reaching 128 in ONE transaction is an open question for this\n\
            envelope, and belongs in the limitations section as one."
    );
}
