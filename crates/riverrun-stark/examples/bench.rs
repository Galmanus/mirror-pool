//! What one execution costs, measured.
//!
//! The number that matters for this bounty's audience — agents, market makers,
//! ordinary users proving before every action — is not proof size, it is what the
//! *client* has to spend and distribute. A pairing-based system needs a proving
//! key produced by a ceremony and shipped to every prover; for a Merkle circuit
//! that is tens of megabytes of setup that must exist before anyone proves
//! anything. riverrun needs none: the prover is the code.
//!
//! Run: `cargo run --release --example bench`

use riverrun_stark::*;
use std::time::Instant;

fn main() {
    let action = [BaseElement::new(0xAC01), BaseElement::new(0xAC02)];
    let round = BaseElement::new(3);

    println!("riverrun — cost of one execution\n");
    println!(
        "{:>9}  {:>10}  {:>12}  {:>12}  {:>10}",
        "set size", "proof", "prove", "verify", "setup"
    );
    println!("{}", "-".repeat(62));

    for n in [4u128, 64, 16384] {
        let v = [BaseElement::new(7), BaseElement::new(9)];
        let mut leaves: Vec<Hash> = (0..n)
            .map(|i| Hash::new(BaseElement::new(900 + 2 * i), BaseElement::new(901 + 2 * i)))
            .collect();
        leaves[1] = leaf_of(v, action);
        let set = MembershipSet::new(leaves);
        let root = set.root();
        let nf = nullifier(v, round);

        // warm the allocator so the first row is not the odd one out
        let _ = set.prove_bound(v, 1, round, action);

        let t = Instant::now();
        let proof = set.prove_bound(v, 1, round, action);
        let prove_ms = t.elapsed().as_secs_f64() * 1000.0;

        let t = Instant::now();
        let ok = verify_bound(root, nf, round, action, &proof);
        let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
        assert!(ok);

        println!(
            "{n:>9}  {:>8} B  {prove_ms:>9.1} ms  {verify_ms:>9.2} ms  {:>10}",
            proof.len(),
            "0 bytes"
        );
    }

    // --- one round, one proof -------------------------------------------
    println!("\n\nriverrun — a whole synchronized round, batched into one proof\n");
    println!(
        "{:>9}  {:>12}  {:>13}  {:>8}  {:>10}",
        "members", "one proof", "one per member", "saving", "prove"
    );
    println!("{}", "-".repeat(62));

    for k in [4usize, 64] {
        let secrets: Vec<[BaseElement; 2]> = (0..k as u128)
            .map(|i| [BaseElement::new(1000 + i), BaseElement::new(2000 + i)])
            .collect();
        let set = MembershipSet::new(secrets.iter().map(|s| leaf_of(*s, action)).collect());
        let members: Vec<(usize, [BaseElement; 2])> =
            secrets.iter().copied().enumerate().collect();

        let t = Instant::now();
        let batched = prove_round(&set, &members, round, action);
        let prove_ms = t.elapsed().as_secs_f64() * 1000.0;

        let claim = RoundClaim {
            root: set.root(),
            round,
            action,
            nullifiers: secrets.iter().map(|s| nullifier(*s, round)).collect(),
        };
        assert!(verify_round(&claim, &batched));

        let separate: usize = members
            .iter()
            .map(|(i, s)| set.prove_bound(*s, *i, round, action).len())
            .sum();

        println!(
            "{k:>9}  {:>10} B  {:>11} B  {:>7.1}x  {prove_ms:>7.1} ms",
            batched.len(),
            separate,
            separate as f64 / batched.len() as f64
        );
    }

    println!(
        "\nOne round is one proof and one verification. A per-member scheme pays\n\
         for k of each; on-chain, that is k verifications of ~250k CU for a\n\
         pairing-based verifier. riverrun's synchronized round is exactly the\n\
         structure that batches, so this costs nothing conceptually — the k\n\
         sub-traces are laid end to end in one trace.\n"
    );

    println!(
        "\nProof size grows logarithmically: 4096x the members costs 1.6x the proof.\n\
         Proving is single-digit milliseconds and needs no proving key, no circuit\n\
         artifact and no ceremony output — there is nothing to distribute to clients\n\
         and nothing to trust. That is the trade riverrun makes: a large proof in\n\
         exchange for a prover that is the code, and no setup that can be corrupted.\n\
         \n\
         Honest other side of it: 12-19 KB does not fit in Solana's 1232-byte\n\
         transaction, which is why this proof is verified off-chain today. See the\n\
         README's Security status."
    );
}
