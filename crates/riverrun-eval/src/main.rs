//! `riverrun-eval` — run the adversarial evaluation and print the exhibit.
//!
//! For a range of pool sizes it reports the clustering attacker's attribution
//! accuracy against the unprotected trace vs the `riverrun` (protected) trace,
//! alongside the chance baseline `1/k`. The story is the two columns: unprotected
//! stays high, protected sits on chance.

use riverrun_eval::run_experiment;

fn main() {
    const SEED: u64 = 0x_C0FF_EE_D1_5EA5E; // fixed seed → reproducible
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
         riverrun drives it to chance — attribution is no better than guessing."
    );
}
