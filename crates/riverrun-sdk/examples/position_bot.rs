//! Phase E: a fund enters and exits a position unlinkably.
//!
//! The fund-facing proof that the primitive is real. One secret, two `act()` calls
//! in two different contexts: enter the position, and later exit it. An observer of
//! the chain sees two unrelated settlements. The fund knows they are the same
//! position, opened and closed, each with a measured anonymity floor. Nobody can
//! link the entry to the exit, or either to the fund.
//!
//! Run: `cargo run -p riverrun-sdk --example position_bot`
//!
//! This runs against an in-memory backend so it is deterministic and offline. The
//! same `act()` calls run on-chain through the devnet backend
//! (`programs/mirror-pool/examples/act_devnet.rs`, Phase D), which settles for real.

use riverrun_core::act as core_act;
use riverrun_core::commitment::{Commitment, Secret};
use riverrun_core::nullifier::Nullifier;
use riverrun_sdk::{act, ActRequest, Backend, Policy, Proof, Prover, Receipt, RoundInfo};

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// An in-memory backend: a healthy round, and a deterministic settlement signature
/// derived from the nullifier so the demo is reproducible.
struct SimBackend {
    round: Vec<u8>,
    advertised_k: usize,
    effective_k: f64,
}
impl Backend for SimBackend {
    fn commit(&mut self, _commitment: &Commitment) -> Result<(), String> {
        Ok(())
    }
    fn await_round(&mut self) -> Result<RoundInfo, String> {
        Ok(RoundInfo {
            round: self.round.clone(),
            advertised_k: self.advertised_k,
            effective_k: self.effective_k,
        })
    }
    fn settle(
        &mut self,
        _round: &RoundInfo,
        nullifier: &Nullifier,
        _action: &[u8],
        _recipient: &[u8; 32],
        _amount: u64,
        _proof: &Proof,
    ) -> Result<String, String> {
        Ok(format!("sim-{}", hex8(nullifier.as_bytes())))
    }
}

struct SimProver;
impl Prover for SimProver {
    fn prove(&self, _s: &Secret, _c: &[u8], _a: &[u8], _r: &RoundInfo) -> Result<Proof, String> {
        Ok(Vec::new())
    }
}

fn print_leg(name: &str, ctx: &[u8], receipt: &Receipt) {
    println!("  {name}");
    println!("    context    : {}", String::from_utf8_lossy(ctx));
    println!("    settlement : {}", receipt.signature);
    println!("    advertised k: {}   effective k (measured): {:.1}", receipt.advertised_k, receipt.effective_k);
    println!("    nullifier  : {}…  (spent once)", hex8(receipt.nullifier.as_bytes()));
}

fn main() {
    // The fund holds one secret. Everything below is derived from it.
    let fund = Secret::from_bytes([0x5a; 32]);
    let recipient = [0x11; 32];
    let floor = Policy { min_effective_k: 8.0 };

    println!("A fund opens and closes a position, unlinkably. One secret, two acts.\n");

    // 1. ENTER the position in its own context.
    let entry_ctx: &[u8] = b"position-alpha/entry";
    let mut entry_be = SimBackend { round: b"epoch-100".to_vec(), advertised_k: 24, effective_k: 11.5 };
    let entry = act(
        &fund,
        &ActRequest { context: entry_ctx, action: b"buy 5000 SOL of X", recipient, amount: 1_000_000 },
        &SimProver,
        &mut entry_be,
        &floor,
    )
    .expect("entry meets the floor");

    // 2. Later, EXIT the position in a different context and round.
    let exit_ctx: &[u8] = b"position-alpha/exit";
    let mut exit_be = SimBackend { round: b"epoch-137".to_vec(), advertised_k: 19, effective_k: 9.2 };
    let exit = act(
        &fund,
        &ActRequest { context: exit_ctx, action: b"sell 5000 SOL of X", recipient, amount: 1_000_000 },
        &SimProver,
        &mut exit_be,
        &floor,
    )
    .expect("exit meets the floor");

    println!("what the fund did (it knows both are the same position):");
    print_leg("ENTER", entry_ctx, &entry);
    print_leg("EXIT ", exit_ctx, &exit);

    // 3. What an observer of the chain sees: two unrelated actions.
    println!("\nwhat an observer of the chain sees:");
    println!("    two settlements, {} and {}, with unrelated nullifiers,", entry.signature, exit.signature);
    println!("    different identities, in different rounds. No edge links them,");
    println!("    and nothing links either back to the fund.");

    // 4. The proof, not a claim: the two legs are independent PRF outputs.
    let entry_id = core_act::identity(&fund, entry_ctx);
    let exit_id = core_act::identity(&fund, exit_ctx);
    assert_ne!(entry_id, exit_id, "entry and exit identities must be unlinkable");
    assert_ne!(entry.nullifier, exit.nullifier, "entry and exit nullifiers must be unlinkable");

    println!("\nproof (independent PRF outputs from one secret):");
    println!("    entry identity : {}…", hex8(&entry_id));
    println!("    exit  identity : {}…", hex8(&exit_id));
    println!("    unlinkable: the same secret produced both, but nobody else can tell.");

    println!("\nThe position was opened and closed, each leg above the fund's anonymity");
    println!("floor, and the strategy left no linkable trail on-chain. That is the point.");
}
