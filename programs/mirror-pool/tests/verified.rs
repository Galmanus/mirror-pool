//! `execute_verified` — the committee-free, STARK-verified settlement path.
//!
//! This exercises the on-chain *seam* that replaces the Ed25519 committee with a
//! Circle-STARK verifier buffer (`docs/M31_CIRCLE_STARK.md`). It does not run the
//! STARK — that is the off-chain prover + on-chain verifier still to be built — so
//! here the buffer is a **mock** owned by a stand-in verifier program: the point is
//! to prove the consumer logic is correct and safe, i.e. that a settlement happens
//! only when a buffer owned by the pool's named verifier is finalized and its
//! verified public inputs are exactly the settled tuple. When the real M31 verifier
//! is deployed, `set_stark_verifier` points at it and nothing else changes.

use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

use litesvm::LiteSVM;

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");
const ENTRY_FEE: u64 = 5_000_000;
const K_MIN: u32 = 2;
const PAYOUT: u64 = 1_000_000;

// Buffer offsets — must mirror the program's B_* constants / the design doc §2.
const B_FINALIZED: usize = 40;
const B_ROOT: usize = 41;
const B_NULLIFIER: usize = 73;
const B_ROUND: usize = 105;
const B_ACTION: usize = 121;
const B_RECIPIENT: usize = 153;
const B_LEN: usize = 185;

fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize()[..8]);
    out
}

fn pool_pda(authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"pool", authority.as_ref()], &PROGRAM_ID).0
}
fn nullifier_pda(pool: &Pubkey, nf: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), nf], &PROGRAM_ID).0
}
fn vault_pda(pool: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", pool.as_ref()], &PROGRAM_ID).0
}

fn load() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_program.so");
    svm.add_program_from_file(PROGRAM_ID, so)
        .expect("load program .so (run `cargo build-sbf` first)");
    let authority = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    (svm, authority)
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ix: Instruction) -> Result<(), String> {
    let payer = signers[0].pubkey();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer), signers, svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?} | {}", e.err, e.meta.logs.join(" | ")))
}

/// A pool that has published `root`, cleared the anonymity floor, funded its vault,
/// and named `verifier_id` as its STARK verifier — ready for `execute_verified`.
fn pool_verified_ready(verifier_id: &Pubkey) -> (LiteSVM, Keypair, Pubkey, [u8; 32]) {
    let (mut svm, authority) = load();
    let pool = pool_pda(&authority.pubkey());
    let root = [0x5A; 32];

    // initialize (a committee of one is required by initialize; execute_verified ignores it)
    let dummy_verifier = Keypair::new();
    let mut data = disc("initialize").to_vec();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(dummy_verifier.pubkey().as_ref());
    data.push(1);
    data.extend_from_slice(&ENTRY_FEE.to_le_bytes());
    data.extend_from_slice(&K_MIN.to_le_bytes());
    send(&mut svm, &[&authority], Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }).expect("initialize");

    // publish_root
    let mut data = disc("publish_root").to_vec();
    data.extend_from_slice(&root);
    send(&mut svm, &[&authority], Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data,
    }).expect("publish_root");

    // commit K_MIN members
    for i in 0..K_MIN {
        svm.expire_blockhash();
        let mut data = disc("commit").to_vec();
        data.extend_from_slice(&[(i + 1) as u8; 32]);
        send(&mut svm, &[&authority], Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        }).expect("commit");
    }

    // set_stark_verifier(verifier_id)
    svm.expire_blockhash();
    let mut data = disc("set_stark_verifier").to_vec();
    data.extend_from_slice(verifier_id.as_ref());
    send(&mut svm, &[&authority], Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data,
    }).expect("set_stark_verifier");

    svm.airdrop(&vault_pda(&pool), 1_000_000_000).unwrap();
    svm.expire_blockhash();
    (svm, authority, pool, root)
}

/// A finalized verifier buffer carrying `{root, nullifier, round, action, recipient}`.
fn make_buffer(
    root: &[u8; 32], nf: &[u8; 32], round: u64, action: &[u8; 32], finalized: bool, recipient: &Pubkey,
) -> Vec<u8> {
    let mut b = vec![0u8; B_LEN];
    b[B_FINALIZED] = finalized as u8;
    b[B_ROOT..B_ROOT + 32].copy_from_slice(root);
    b[B_NULLIFIER..B_NULLIFIER + 32].copy_from_slice(nf);
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&round.to_le_bytes());
    b[B_ROUND..B_ROUND + 16].copy_from_slice(&r);
    b[B_ACTION..B_ACTION + 32].copy_from_slice(action);
    b[B_RECIPIENT..B_RECIPIENT + 32].copy_from_slice(recipient.as_ref());
    b
}

/// Install a buffer account at a fresh key, owned by `owner`.
fn install_buffer(svm: &mut LiteSVM, owner: &Pubkey, data: Vec<u8>) -> Pubkey {
    let key = Keypair::new().pubkey();
    svm.set_account(key, Account {
        lamports: 1_000_000_000,
        data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }).unwrap();
    key
}

fn relayer(svm: &mut LiteSVM) -> Keypair {
    let r = Keypair::new();
    svm.airdrop(&r.pubkey(), 10_000_000_000).unwrap();
    r
}

fn execute_verified_ix(
    pool: Pubkey, relayer: &Keypair, buffer: Pubkey, recipient: Pubkey,
    root: [u8; 32], action: [u8; 32], nf: [u8; 32], round: u64,
) -> Instruction {
    let mut data = disc("execute_verified").to_vec();
    data.extend_from_slice(&action);
    data.extend_from_slice(&nf);
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&root);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(nullifier_pda(&pool, &nf), false),
            AccountMeta::new(relayer.pubkey(), true),
            AccountMeta::new(vault_pda(&pool), false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(buffer, false),
        ],
        data,
    }
}

#[test]
fn a_finalized_matching_buffer_settles_without_a_committee() {
    let verifier_id = Keypair::new().pubkey();
    let (mut svm, _auth, pool, root) = pool_verified_ready(&verifier_id);
    let action = [0xA1; 32];
    let nf = [0x11; 32];
    let recipient = Pubkey::new_from_array([0x9C; 32]);

    let buffer = install_buffer(&mut svm, &verifier_id, make_buffer(&root, &nf, 0, &action, true, &recipient));
    let r = relayer(&mut svm);

    let before = svm.get_account(&recipient).map(|a| a.lamports).unwrap_or(0);
    send(&mut svm, &[&r], execute_verified_ix(pool, &r, buffer, recipient, root, action, nf, 0))
        .expect("a finalized, matching proof buffer must settle");
    let after = svm.get_account(&recipient).unwrap().lamports;
    assert_eq!(after - before, PAYOUT, "the payout must have moved from the vault");
}

#[test]
fn an_unfinalized_buffer_is_rejected() {
    let verifier_id = Keypair::new().pubkey();
    let (mut svm, _auth, pool, root) = pool_verified_ready(&verifier_id);
    let action = [0xA1; 32];
    let nf = [0x22; 32];
    let recipient = Pubkey::new_unique();
    // finalized = false: the verifier never certified this proof
    let buffer = install_buffer(&mut svm, &verifier_id, make_buffer(&root, &nf, 0, &action, false, &recipient));
    let r = relayer(&mut svm);
    let err = send(&mut svm, &[&r], execute_verified_ix(pool, &r, buffer, recipient, root, action, nf, 0))
        .expect_err("an unfinalized buffer must not settle");
    assert!(err.contains("FINALIZED") || err.contains("ProofNotFinalized"), "{err}");
}

#[test]
fn a_buffer_for_a_different_action_is_rejected() {
    let verifier_id = Keypair::new().pubkey();
    let (mut svm, _auth, pool, root) = pool_verified_ready(&verifier_id);
    let nf = [0x33; 32];
    let recipient = Pubkey::new_unique();
    // buffer certifies action 0xAA, but we settle action 0xBB
    let buffer = install_buffer(&mut svm, &verifier_id, make_buffer(&root, &nf, 0, &[0xAA; 32], true, &recipient));
    let r = relayer(&mut svm);
    let err = send(&mut svm, &[&r], execute_verified_ix(pool, &r, buffer, recipient, root, [0xBB; 32], nf, 0))
        .expect_err("public inputs must match the settled tuple");
    assert!(err.contains("public inputs") || err.contains("ProofPublicInputMismatch"), "{err}");
}

#[test]
fn a_relayer_cannot_redirect_the_payout_on_the_verified_path() {
    // The buffer binds the payout to `intended`; the relayer submits it but names
    // its own account as recipient, trying to steal the denomination. The recipient
    // is a verified public input, so the settlement must be rejected.
    let verifier_id = Keypair::new().pubkey();
    let (mut svm, _auth, pool, root) = pool_verified_ready(&verifier_id);
    let action = [0xA1; 32];
    let nf = [0x55; 32];
    let intended = Pubkey::new_from_array([0x9C; 32]);
    let buffer = install_buffer(&mut svm, &verifier_id, make_buffer(&root, &nf, 0, &action, true, &intended));
    let r = relayer(&mut svm);
    // the attacker (the relayer) redirects to itself, keeping every other field valid
    let err = send(&mut svm, &[&r], execute_verified_ix(pool, &r, buffer, r.pubkey(), root, action, nf, 0))
        .expect_err("a relayer must not redirect the payout to an unbound recipient");
    assert!(err.contains("public inputs") || err.contains("ProofPublicInputMismatch"), "{err}");
}

#[test]
fn a_buffer_owned_by_the_wrong_program_is_rejected() {
    let verifier_id = Keypair::new().pubkey();
    let (mut svm, _auth, pool, root) = pool_verified_ready(&verifier_id);
    let action = [0xA1; 32];
    let nf = [0x44; 32];
    let recipient = Pubkey::new_unique();
    // correct contents, but owned by an impostor, not the pool's named verifier
    let impostor = Keypair::new().pubkey();
    let buffer = install_buffer(&mut svm, &impostor, make_buffer(&root, &nf, 0, &action, true, &recipient));
    let r = relayer(&mut svm);
    let err = send(&mut svm, &[&r], execute_verified_ix(pool, &r, buffer, recipient, root, action, nf, 0))
        .expect_err("a buffer not owned by the named verifier must not settle");
    assert!(err.contains("owned") || err.contains("WrongVerifierOwner"), "{err}");
}
