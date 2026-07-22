//! `provenance-tracer` — run the adversary over the three constructions and print
//! the exhibit: the funding-graph leak the field leaves open, and how circularity
//! closes it.

use riverrun_trace::rng::SplitMix64;
use riverrun_trace::{evaluate, scenario, SchemeStats};

fn row(name: &str, s: SchemeStats) {
    let depth = if s.mean_nearest_depth.is_nan() {
        "  n/a".to_string()
    } else {
        format!("{:5.1}", s.mean_nearest_depth)
    };
    println!(
        "{:<26}  {:>11.1}%  {:>9}  {:>13.2}  {:>9.1}%",
        name,
        s.root_hit_rate * 100.0,
        depth,
        s.mean_attribution_bits,
        s.cyclic_rate * 100.0,
    );
}

fn main() {
    const SEED: u64 = 0x_C0FF_EE_D1_5EA5E;
    const N: usize = 2000;

    println!("provenance-tracer — the funding-graph leak every noise tool leaves open\n");
    println!(
        "{:<26}  {:>12}  {:>9}  {:>13}  {:>10}",
        "construction", "root-hit", "depth", "attrib.(bits)", "in-cycle"
    );
    println!("{}", "-".repeat(78));

    let mut rng = SplitMix64::new(SEED);
    row(
        "rooted decoy (the field)",
        evaluate(&scenario::rooted_decoy(&mut rng, N, 4)),
    );
    row(
        "cyclic, ambiguous root",
        evaluate(&scenario::cyclic_ambiguous(&mut rng, N, 60, 8)),
    );
    row(
        "cyclic, rootless",
        evaluate(&scenario::cyclic_rootless(&mut rng, N, 60)),
    );

    println!(
        "\nRead: the field's decoys still trace back to one origin (root-hit ~100%,\n\
         0 bits of doubt). Circularity dissolves it two ways — a root that could be\n\
         any of many (high attribution entropy), or no attributable root at all —\n\
         and puts the target inside a cycle with no source to name.\n\
         Honest caveat: 'rootless' holds only while the pool's funding sources are\n\
         themselves unattributable; one known CEX entry degrades it to 'ambiguous'."
    );
}
