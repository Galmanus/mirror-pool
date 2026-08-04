//! Does a degree-4 challenge field lift the soundness ceiling?
//!
//! `examples/soundness_budget.rs` found that at high blowup the additive error
//! terms bind: they are `domain / |E|`, the domain grows with the blowup, and
//! `|E|` does not. With the degree-3 extension `|E| ≈ 2^93`, and the adopted
//! configuration's round-by-round error floors at `2^-74` while its query phase
//! offers 84 bits — ten bits thrown away by the field.
//!
//! `p3-mersenne-31` ships `QM31`, the degree-4 extension `M31[i][u]` with
//! `i² = -1` and `u² = 2 + i`, at `4 · 31 = 124` bits. This computes what that
//! would buy, using the same accounting, before anyone spends a day rewiring
//! the config types.
//!
//! Run: cargo run --release --example qm31_ceiling

/// Round-by-round error in bits, as `soundness_budget.rs` computes it.
fn rbr_bits(queries: usize, log_blowup: usize, log_committed: usize, log_ext: f64) -> f64 {
    let q_bits = (queries * log_blowup) as f64;
    let domain = ((log_committed + log_blowup) as f64).exp2();
    let rounds = (log_committed + log_blowup) as f64;
    let deg_q = 5.0 * (log_committed as f64).exp2();
    let ext = log_ext.exp2();
    let additive = domain / ext + deg_q / ext + rounds * domain / ext;
    -((-q_bits).exp2() + additive).log2()
}

fn main() {
    const POW: f64 = 8.0;
    println!(
        "{:<30} {:>10} {:>10} {:>10} {:>10}",
        "configuration", "query bits", "deg-3", "deg-4", "recovered"
    );
    for (name, q, lb, lc) in [
        ("128 rows, 12q, blowup 128", 12usize, 7usize, 8usize),
        ("128 rows, 16q, blowup 64", 16, 6, 8),
        ("128 rows, 24q, blowup 16", 24, 4, 8),
        ("256 rows, 16q, blowup 64", 16, 6, 9),
        ("256 rows, 20q, blowup 128", 20, 7, 9),
        ("256 rows, 24q, blowup 128", 24, 7, 9),
    ] {
        let q_bits = (q * lb) as f64;
        let d3 = rbr_bits(q, lb, lc, 92.999_999_9) + POW;
        let d4 = rbr_bits(q, lb, lc, 123.999_999_9) + POW;
        println!(
            "{:<30} {:>10.0} {:>10.0} {:>10.0} {:>10.0}",
            name,
            q_bits + POW,
            d3,
            d4,
            d4 - d3
        );
    }
    println!(
        "\nThe columns are classical work in bits. Halve them for a Grover adversary.\n\
         'query bits' is what the query phase offers; 'deg-3' and 'deg-4' are what the\n\
         field lets through. Where deg-3 falls short of the query bits, the ceiling is\n\
         the field and not the protocol, and the degree-4 column is what removing that\n\
         ceiling recovers.\n\n\
         QM31 is already in p3-mersenne-31 (M31[i][u], i^2 = -1, u^2 = 2 + i, 124 bits)\n\
         with the ExtensionField<Mersenne31> impls a challenge field needs. So this is\n\
         a change of one type alias and whatever the change breaks, not new\n\
         cryptography — and the table says whether it is worth doing before anyone\n\
         finds out how much it breaks."
    );
}
