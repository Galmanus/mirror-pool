//! Measure what verifying riverrun's own M31 binding relation on-chain
//! actually costs, in CU. Mirrors `programs/stark-verifier/tests/cu.rs`'s
//! honesty: the real Circle-STARK verifier, run inside LiteSVM's simulated
//! Solana runtime, priced, not asserted.
use litesvm::LiteSVM;
use riverrun_m31::{prove_binding_tuned, prove_preimage, CONTEXT_LEN, SECRET_LEN, WIDTH};
use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, signature::{Keypair, Signer},
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("r1Vrrunm31VeriFier1111111111111111111111111");

// Production is 40 FRI queries (~78 KB proof, measured). A Solana legacy
// transaction message caps at a u16 length (65535 bytes) for the whole
// serialized message, so a 78 KB proof cannot ride inline in one
// instruction's data at all, on LiteSVM or a real cluster; this is exactly
// the buffer-account requirement docs/M31_CIRCLE_STARK.md already names.
// 4 queries (the practical floor) is a reduced-security point picked only to
// fit that limit and to isolate whether the on-chain memory ceiling
// (see the #[ignore] reason below) scales with query count. It measurably
// does not: CU-consumed-before-OOM stayed ~1.54M at both 4 and 12 queries.
// This is not the production parameter and the discrepancy is the point.
const MEASURED_QUERIES: u16 = 4;

fn ctx_bytes(v: [u64; CONTEXT_LEN]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn wide_bytes(v: [u64; WIDTH]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn instruction_data() -> Vec<u8> {
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| i as u64 + 1);
    let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| i as u64 + 100);
    let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| i as u64 + 200);
    let (proof, leaf, nullifier) =
        prove_binding_tuned(secret, action, round, MEASURED_QUERIES as usize);

    let mut d = vec![0u8]; // discriminator 0: BindingProof
    d.extend_from_slice(&MEASURED_QUERIES.to_le_bytes());
    d.extend_from_slice(&ctx_bytes(action));
    d.extend_from_slice(&ctx_bytes(round));
    d.extend_from_slice(&wide_bytes(leaf));
    d.extend_from_slice(&wide_bytes(nullifier));
    d.extend_from_slice(&proof.to_bytes());
    d
}

/// Instruction data for the simpler, single-block, non-vectorized preimage
/// AIR (`permutation.rs`), added purely to compare its on-chain peak
/// `verify()` memory against `BindingProof`'s two-block vectorized one.
fn preimage_instruction_data() -> Vec<u8> {
    let input: [u64; WIDTH] = core::array::from_fn(|i| i as u64 + 1);
    let (proof, output) = prove_preimage(input);
    let mut d = vec![1u8]; // discriminator 1: PreimageProof
    d.extend_from_slice(&wide_bytes(output));
    d.extend_from_slice(&proof.to_bytes());
    d
}

// PASSES as of 2026-07-29: the 256 KB heap wall is closed and the proof
// VERIFIES on-chain. Root cause was p3_uni_stark's symbolic AIR
// re-evaluation (deriving one constant, ~440 KB of transient heap), removed
// by the vendored p3-uni-stark heap patch + the pinned
// `binding::LOG_NUM_QUOTIENT_CHUNKS`; full story in src/lib.rs's module doc
// and the patch's PATCH.md. Measured here: 2,384,277 CU at 4 FRI queries
// (with syscall keccak and opt-level 3), ACCEPTED — still over a real
// transaction's 1.4M CU cap, and the slope is per-query (~348k CU/query,
// measured 4 vs 12 queries), so production 40-query verification in one
// transaction needs per-query cost work (arity/blowup tuning, column
// reduction, or staged verification across transactions). #[ignore] only
// because this needs the `cargo build-sbf` artifact to exist first; run
// `cargo build-sbf`, then
// `cargo test --release --test cu -- --ignored --nocapture`.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: run cargo build-sbf first, then --ignored"]
fn measure_on_chain_binding_verification_cost() {
    let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
    budget.compute_unit_limit = 50_000_000; // for measurement; real cap is 1.4M/tx
    budget.heap_size = 256 * 1024; // Solana's max requestable heap frame
    let mut svm = LiteSVM::new().with_compute_budget(budget);
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_m31_verifier.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load .so (run cargo build-sbf first)");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let data = instruction_data();
    let proof_bytes = data.len() - (1 + 2 + 2 * CONTEXT_LEN * 8 + 2 * WIDTH * 8);
    let heap_ix = solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data };
    let msg = Message::new(&[heap_ix, ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

    match svm.send_transaction(tx) {
        Ok(meta) => {
            for l in &meta.logs {
                println!("    {l}");
            }
            println!(
                "riverrun-m31 binding proof: {proof_bytes} B proof, {} CU {}",
                meta.compute_units_consumed,
                if meta.compute_units_consumed <= 1_400_000 { "(fits one real tx's CU budget)" } else { "(OVER a real tx's 1.4M CU budget)" }
            );
        }
        Err(e) => {
            for l in &e.meta.logs {
                println!("    {l}");
            }
            panic!("on-chain M31 binding verification failed: {:?}", e.err);
        }
    }
}

#[test]
fn a_tampered_proof_is_rejected_on_chain() {
    let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
    budget.compute_unit_limit = 50_000_000;
    budget.heap_size = 256 * 1024;
    let mut svm = LiteSVM::new().with_compute_budget(budget);
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_m31_verifier.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load .so (run cargo build-sbf first)");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let mut data = instruction_data();
    // Flip one byte inside the claimed nullifier (a public value, not the
    // proof itself): the on-chain verifier must reject it.
    let nullifier_offset = 1 + 2 + 2 * CONTEXT_LEN * 8 + WIDTH * 8;
    data[nullifier_offset] ^= 1;
    let heap_ix = solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data };
    let msg = Message::new(&[heap_ix, ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

    match svm.send_transaction(tx) {
        Ok(_) => panic!("a tampered public value must not verify on-chain"),
        Err(e) => {
            println!("rejected as expected: {:?}", e.err);
        }
    }
}

/// Diagnostic comparison, real answer found: does the SIMPLER, single-block,
/// non-vectorized preimage AIR (`permutation.rs`, one Poseidon2 permutation,
/// the smallest AIR in this crate) fit Solana's 256 KB heap ceiling where
/// `BindingProof`'s two-block vectorized AIR does not? **No.** It OOMs too,
/// consuming even MORE CU before failing (~3.05M vs ~1.5-2M), and with 58,932
/// bytes of heap gone by `verify_preimage`'s internal `deserialize` step
/// alone (before this path's own checkpoint hook, not yet added, would show
/// what `verify()` itself needs on top of that). This ruled out "AIR
/// complexity" as the driver, which is exactly what pointed the later native
/// heap profiling at the shared fixed setup — and the culprit it found there
/// (p3-uni-stark's symbolic AIR re-evaluation, see src/lib.rs) explains this
/// test's result too. PASSES as of 2026-07-29 with the heap patch + pinned
/// `permutation::LOG_NUM_QUOTIENT_CHUNKS`: this is the crate's **production
/// security point completing on-chain** — a 40-FRI-query, 48,749 B
/// `PreimageProof`, ACCEPTED at 9,457,190 CU inside the 256 KB heap. That CU
/// figure is the measured size of the remaining per-query cost problem the
/// binding test's comment names.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: run cargo build-sbf first, then --ignored"]
fn measure_on_chain_preimage_verification_cost() {
    let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
    budget.compute_unit_limit = 50_000_000;
    budget.heap_size = 256 * 1024;
    let mut svm = LiteSVM::new().with_compute_budget(budget);
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_m31_verifier.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load .so (run cargo build-sbf first)");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let data = preimage_instruction_data();
    let proof_bytes = data.len() - (1 + WIDTH * 8);
    let heap_ix = solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data };
    let msg = Message::new(&[heap_ix, ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

    match svm.send_transaction(tx) {
        Ok(meta) => {
            println!(
                "riverrun-m31 preimage proof: {proof_bytes} B proof, {} CU (fits 256KB heap)",
                meta.compute_units_consumed,
            );
        }
        Err(e) => {
            for l in &e.meta.logs {
                println!("    {l}");
            }
            panic!("on-chain M31 preimage verification failed: {:?}", e.err);
        }
    }
}
