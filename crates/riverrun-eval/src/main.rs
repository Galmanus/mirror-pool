//! `riverrun-eval` — run the adversarial evaluation and print the exhibit.
//!
//! For a range of pool sizes it reports the clustering attacker's attribution
//! accuracy against the unprotected trace vs the `riverrun` (protected) trace,
//! alongside the chance baseline `1/k`. The story is the two columns: unprotected
//! stays high, protected sits on chance.

use riverrun_eval::{run_experiment, self_fill_degradation};

fn main() {
    const SEED: u64 = 0x000C_0FFE_ED15_EA5E; // fixed seed → reproducible
    const ROUNDS: usize = 4000;
    let pool_sizes = [4usize, 8, 16, 32, 64];

    println!("riverrun — adversarial evaluation");
    println!("same clustering attacker, {ROUNDS} rounds per pool size\n");
    println!(
        "{:>6}  {:>18}  {:>18}  {:>10}",
        "k", "unprotected acc.", "protected acc.", "chance 1/k"
    );
    println!("{}", "-".repeat(60));
    for &k in &pool_sizes {
        let r = run_experiment(k, ROUNDS, SEED ^ (k as u64).wrapping_mul(0x9E37_79B9));
        println!(
            "{:>6}  {:>17.1}%  {:>17.1}%  {:>9.1}%",
            r.k,
            r.unprotected_accuracy * 100.0,
            r.protected_accuracy * 100.0,
            r.chance * 100.0,
        );
    }
    println!(
        "\nRead: the clustering attacker deanonymizes the unprotected trace, but\n\
         riverrun drives it to chance, attribution is no better than guessing."
    );

    // The second exhibit: the advertised k is not what the honest user gets if the
    // adversary self-fills the round. An honest mix measures this floor.
    const ADVERTISED_K: usize = 17;
    println!("\n\nriverrun — self-fill degradation (a fully protected round of k = {ADVERTISED_K})");
    println!("what the honest user actually gets as the adversary owns more slots\n");
    println!(
        "{:>14}  {:>12}  {:>12}",
        "adversary owns", "honest slots", "effective-k"
    );
    println!("{}", "-".repeat(42));
    for row in self_fill_degradation(ADVERTISED_K) {
        // print the endpoints and a few interior points, not all 17 rows
        let a = row.adversary_owned;
        if a == 0 || a == 4 || a == 8 || a == 12 || a == ADVERTISED_K - 1 {
            println!(
                "{:>14}  {:>12}  {:>12.1}",
                a,
                ADVERTISED_K - a,
                row.effective_k
            );
        }
    }
    println!(
        "\nRead: k = {ADVERTISED_K} is a ceiling, not a guarantee. Every slot the adversary\n\
         self-fills is one they subtract; owning all but one leaves the honest user\n\
         alone (effective-k 1). riverrun reports this floor instead of advertising\n\
         the gross count. The defense is a per-participant deposit cap and a funding\n\
         graph the tracer measures, not a larger headline number."
    );
}
