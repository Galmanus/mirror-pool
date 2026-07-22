//! End-to-end test of the on-chain program via LiteSVM (in-process Solana VM).
//!
//! Loads the compiled `.so` and asserts the full Tornado-for-behavior lifecycle
//! against real program execution: initialize the pool, commit two members,
//! execute an action, reject a double-execution (nullifier reuse), reject a
//! stale round, and advance the round. These are on-chain assertions — the
//! program's actual state transitions, not host mocks.

use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

use litesvm::LiteSVM;

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");

/// Anchor instruction discriminator: first 8 bytes of sha256("global:<name>").
fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize()[..8]);
    out
}

fn pool_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"pool", authority.as_ref()], &PROGRAM_ID)
}

fn nullifier_pda(pool: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), nullifier], &PROGRAM_ID)
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

fn send(svm: &mut LiteSVM, signers: &[&Keypair], ix: Instruction) -> bool {
    let payer = signers[0].pubkey();
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer), signers, svm.latest_blockhash());
    svm.send_transaction(tx).is_ok()
}

fn pool_member_count(svm: &LiteSVM, pool: &Pubkey) -> u32 {
    let data = svm.get_account(pool).unwrap().data;
    u32::from_le_bytes(data[72..76].try_into().unwrap())
}

fn pool_round(svm: &LiteSVM, pool: &Pubkey) -> u64 {
    let data = svm.get_account(pool).unwrap().data;
    u64::from_le_bytes(data[76..84].try_into().unwrap())
}

#[test]
fn full_lifecycle() {
    let (mut svm, authority) = load();
    let (pool, _) = pool_pda(&authority.pubkey());

    // 1. initialize
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: disc("initialize").to_vec(),
    };
    assert!(send(&mut svm, &[&authority], ix), "initialize should succeed");
    assert_eq!(pool_member_count(&svm, &pool), 0);
    assert_eq!(pool_round(&svm, &pool), 0);

    // 2. commit two members
    for c in [[1u8; 32], [2u8; 32]] {
        let mut data = disc("commit").to_vec();
        data.extend_from_slice(&c);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(authority.pubkey(), true),
            ],
            data,
        };
        assert!(send(&mut svm, &[&authority], ix), "commit should succeed");
    }
    assert_eq!(pool_member_count(&svm, &pool), 2, "two members committed");

    // 3. execute an action for round 0 via a relayer (no member key signs)
    let relayer = Keypair::new();
    svm.airdrop(&relayer.pubkey(), 10_000_000_000).unwrap();
    let action = [7u8; 32];
    let nf1 = [0xAA; 32];
    let (nf1_pda, _) = nullifier_pda(&pool, &nf1);

    let execute_ix = |action: [u8; 32], nf: [u8; 32], round: u64, nf_pda: Pubkey| {
        let mut data = disc("execute").to_vec();
        data.extend_from_slice(&action);
        data.extend_from_slice(&nf);
        data.extend_from_slice(&round.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new(nf_pda, false),
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        }
    };

    assert!(
        send(&mut svm, &[&relayer], execute_ix(action, nf1, 0, nf1_pda)),
        "first execution should succeed"
    );
    assert!(svm.get_account(&nf1_pda).is_some(), "nullifier PDA now exists");

    // 4. double execution with the same nullifier must FAIL (PDA already exists)
    assert!(
        !send(&mut svm, &[&relayer], execute_ix(action, nf1, 0, nf1_pda)),
        "double execution (nullifier reuse) must be rejected"
    );

    // 5. execution for a stale round must FAIL (pool is at round 0)
    let nf2 = [0xBB; 32];
    let (nf2_pda, _) = nullifier_pda(&pool, &nf2);
    assert!(
        !send(&mut svm, &[&relayer], execute_ix(action, nf2, 9, nf2_pda)),
        "execution for the wrong round must be rejected"
    );

    // 6. advance the round
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data: disc("advance_round").to_vec(),
    };
    assert!(send(&mut svm, &[&authority], ix), "advance_round should succeed");
    assert_eq!(pool_round(&svm, &pool), 1, "round advanced to 1");
}
