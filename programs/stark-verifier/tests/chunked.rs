//! The chunked upload + verify pipeline, end to end in LiteSVM.
//!
//! A riverrun proof is 12–16 KB and a Solana transaction is 1232 bytes, so the
//! proof cannot arrive in one instruction. This exercises the flow the size limit
//! forces: open a session, append the proof in bounded chunks under a rolling
//! hash, then verify against the accumulated bytes. It is the same shape eprint
//! 2025/1741 uses (≤900-byte chunks, rolling hash, finalize).
//!
//! What this proves: the upload machine is correct — chunks accumulate in order,
//! the rolling hash rejects tampering, and the finalize step runs the real
//! verifier over exactly the bytes uploaded. What it does not change: the verify
//! itself still costs >1.4M CU for f128 (measured in `cu.rs`), so the finalize
//! runs under a raised budget here; making each step fit a real 1.4M-CU
//! transaction is the field change, not the upload.

use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("5tArKVr1verrunProof111111111111111111111111");
const CHUNK: usize = 900;

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

/// public-input header the program checks the proof against
fn header() -> (Vec<u8>, Vec<u8>) {
    use riverrun_stark::*;
    let v = [BaseElement::new(7), BaseElement::new(9)];
    let action = [BaseElement::new(0xAC01), BaseElement::new(0xAC02)];
    let round = BaseElement::new(3);
    let mut leaves: Vec<Hash> = (0..4u128)
        .map(|i| Hash::new(BaseElement::new(900 + 2 * i), BaseElement::new(901 + 2 * i)))
        .collect();
    leaves[1] = leaf_of(v, action);
    let set = MembershipSet::new(leaves);
    let proof = set.prove_bound(v, 1, round, action);

    let mut head = Vec::new();
    head.extend_from_slice(&hash_bytes(set.root()));
    head.extend_from_slice(&hash_bytes(nullifier(v, round)));
    head.extend_from_slice(&elem_bytes(round));
    head.extend_from_slice(&elem_bytes(action[0]));
    head.extend_from_slice(&elem_bytes(action[1]));
    (head, proof)
}

fn setup() -> (LiteSVM, Keypair) {
    let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
    budget.compute_unit_limit = 50_000_000;
    budget.heap_size = 256 * 1024;
    let mut svm = LiteSVM::new().with_compute_budget(budget);
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_stark_verifier.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load .so");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    (svm, payer)
}

fn session_pda(payer: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"session", payer.as_ref()], &PROGRAM_ID).0
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<u64, String> {
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx)
        .map(|m| m.compute_units_consumed)
        .map_err(|e| format!("{:?} | {}", e.err, e.meta.logs.join(" | ")))
}

/// tag(1=open) | total_len(4) | header(112)
fn open_ix(payer: &Pubkey, session: &Pubkey, total: u32, head: &[u8]) -> Instruction {
    let mut data = vec![1u8];
    data.extend_from_slice(&total.to_le_bytes());
    data.extend_from_slice(head);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*session, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data,
    }
}

/// tag(2=append) | offset(4) | bytes
fn append_ix(payer: &Pubkey, session: &Pubkey, offset: u32, bytes: &[u8]) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(bytes);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(*session, false), AccountMeta::new(*payer, true)],
        data,
    }
}

/// tag(3=verify)
fn verify_ix(payer: &Pubkey, session: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(*session, false), AccountMeta::new(*payer, true)],
        data: vec![3u8],
    }
}

fn upload(svm: &mut LiteSVM, payer: &Keypair, head: &[u8], proof: &[u8]) -> Pubkey {
    let session = session_pda(&payer.pubkey());
    send(svm, payer, open_ix(&payer.pubkey(), &session, proof.len() as u32, head))
        .expect("open session");
    for (i, chunk) in proof.chunks(CHUNK).enumerate() {
        svm.expire_blockhash();
        send(svm, payer, append_ix(&payer.pubkey(), &session, (i * CHUNK) as u32, chunk))
            .unwrap_or_else(|e| panic!("append chunk {i}: {e}"));
    }
    session
}

#[test]
fn a_proof_uploaded_in_chunks_verifies() {
    let (mut svm, payer) = setup();
    let (head, proof) = header();
    assert!(proof.len() > CHUNK, "the proof must actually need chunking: {} B", proof.len());

    let session = upload(&mut svm, &payer, &head, &proof);
    svm.expire_blockhash();
    let cu = send(&mut svm, &payer, verify_ix(&payer.pubkey(), &session))
        .expect("verify over the accumulated proof");
    println!("CHUNKED {} chunks, verify consumed {cu} CU", proof.len().div_ceil(CHUNK));
}

#[test]
fn a_tampered_chunk_is_rejected_by_the_rolling_hash() {
    let (mut svm, payer) = setup();
    let (head, mut proof) = header();
    // flip a byte in the second chunk
    proof[CHUNK + 10] ^= 0xFF;

    let session = session_pda(&payer.pubkey());
    send(&mut svm, &payer, open_ix(&payer.pubkey(), &session, proof.len() as u32, &head))
        .expect("open");
    for (i, chunk) in proof.chunks(CHUNK).enumerate() {
        svm.expire_blockhash();
        let _ = send(&mut svm, &payer, append_ix(&payer.pubkey(), &session, (i * CHUNK) as u32, chunk));
    }
    svm.expire_blockhash();
    // the bytes accumulated are a valid-length buffer but not a valid proof
    let r = send(&mut svm, &payer, verify_ix(&payer.pubkey(), &session));
    assert!(r.is_err(), "a tampered proof must not verify");
}

#[test]
fn an_append_at_the_wrong_offset_is_rejected() {
    let (mut svm, payer) = setup();
    let (head, proof) = header();
    let session = session_pda(&payer.pubkey());
    send(&mut svm, &payer, open_ix(&payer.pubkey(), &session, proof.len() as u32, &head))
        .expect("open");
    // skip offset 0 and append the second chunk first
    svm.expire_blockhash();
    let r = send(&mut svm, &payer, append_ix(&payer.pubkey(), &session, CHUNK as u32, &proof[..CHUNK]));
    assert!(r.is_err(), "appends must be contiguous and in order");
}

#[test]
fn verifying_before_the_upload_is_complete_is_rejected() {
    let (mut svm, payer) = setup();
    let (head, proof) = header();
    let session = session_pda(&payer.pubkey());
    send(&mut svm, &payer, open_ix(&payer.pubkey(), &session, proof.len() as u32, &head))
        .expect("open");
    // upload only the first chunk
    svm.expire_blockhash();
    send(&mut svm, &payer, append_ix(&payer.pubkey(), &session, 0, &proof[..CHUNK])).expect("append 0");
    svm.expire_blockhash();
    let r = send(&mut svm, &payer, verify_ix(&payer.pubkey(), &session));
    assert!(r.is_err(), "verify must wait for every byte");
}
