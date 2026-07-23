//! Measure what verifying a riverrun STARK on-chain actually costs, in CU.
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, signature::{Keypair, Signer},
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("5tArKVr1verrunProof111111111111111111111111");

fn elem_bytes(e: riverrun_stark::BaseElement) -> [u8; 16] {
    use winterfell::math::StarkField;
    e.as_int().to_le_bytes()
}
fn hash_bytes(h: riverrun_stark::Hash) -> [u8; 32] {
    let e = h.to_elements();
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&elem_bytes(e[0]));
    b[16..].copy_from_slice(&elem_bytes(e[1]));
    b
}

fn instruction_data(k: u128) -> Vec<u8> {
    use riverrun_stark::*;
    let v = [BaseElement::new(7), BaseElement::new(9)];
    let action = [BaseElement::new(0xAC01), BaseElement::new(0xAC02)];
    let round = BaseElement::new(3);
    let mut leaves: Vec<Hash> = (0..k)
        .map(|i| Hash::new(BaseElement::new(900 + 2 * i), BaseElement::new(901 + 2 * i)))
        .collect();
    leaves[1] = leaf_of(v, action);
    let set = MembershipSet::new(leaves);
    let proof = set.prove_bound(v, 1, round, action);

    let mut d = Vec::new();
    d.extend_from_slice(&hash_bytes(set.root()));
    d.extend_from_slice(&hash_bytes(nullifier(v, round)));
    d.extend_from_slice(&elem_bytes(round));
    d.extend_from_slice(&elem_bytes(action[0]));
    d.extend_from_slice(&elem_bytes(action[1]));
    d.extend_from_slice(&proof);
    d
}

#[test]
fn measure_on_chain_verification_cost() {
    let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
    budget.compute_unit_limit = 50_000_000; // for measurement; real cap is 1.4M/tx
    budget.heap_size = 256 * 1024; // Solana's max requestable heap frame
    let mut svm = LiteSVM::new().with_compute_budget(budget);
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_stark_verifier.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load .so (run cargo build-sbf first)");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    for k in [4u128, 64] {
        let data = instruction_data(k);
        let proof_bytes = data.len() - 112;
        let heap_ix = solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024);
        let ix = Instruction { program_id: PROGRAM_ID, accounts: vec![], data };
        let msg = Message::new(&[heap_ix, ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
        match svm.send_transaction(tx) {
            Ok(meta) => println!(
                "CU  k={k:<5}  proof={proof_bytes:>6} B  ->  {} compute units  (verified on-chain)",
                meta.compute_units_consumed
            ),
            Err(e) => {
                for l in &e.meta.logs { println!("    {l}"); }
                panic!("on-chain verification failed at k={k}: {:?}", e.err);
            }
        }
    }
}
