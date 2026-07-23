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

/// What one seat in the anonymity set costs. Anti-Sybil is not a solved problem
/// here either — a fee prices set inflation, it does not prevent it. What it
/// buys is that inflating k to k+m costs m·fee instead of m·0.
const ENTRY_FEE: u64 = 5_000_000; // 0.005 SOL
/// The anonymity-set floor: below this many members, an execution is not private
/// enough to be worth settling, so the program refuses.
const K_MIN: u32 = 2;

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
    send_many(svm, signers, &[ix]).is_ok()
}

/// Send a multi-instruction transaction, returning the program logs on failure so
/// a test can assert *why* it failed rather than only that it did.
fn send_many(svm: &mut LiteSVM, signers: &[&Keypair], ixs: &[Instruction]) -> Result<(), String> {
    let payer = signers[0].pubkey();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer), signers, svm.latest_blockhash());
    match svm.send_transaction(tx) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{:?} {}", e.err, e.meta.logs.join(" | "))),
    }
}

/// The message a verifier signs to attest "I checked the membership proof behind
/// this execution". Binding every field is what stops an attestation from being
/// replayed onto another pool, round, action or nullifier.
fn attestation_message(
    pool: &Pubkey,
    root: &[u8; 32],
    action_hash: &[u8; 32],
    nullifier: &[u8; 32],
    round: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(152);
    m.extend_from_slice(b"riverrun-exec-v1");
    m.extend_from_slice(pool.as_ref());
    m.extend_from_slice(root);
    m.extend_from_slice(action_hash);
    m.extend_from_slice(nullifier);
    m.extend_from_slice(&round.to_le_bytes());
    m
}

/// Build a native Ed25519 sigverify instruction over `msg`, laid out the way
/// `new_ed25519_instruction` does: 16-byte header, pubkey at 16, signature at 48,
/// message at 112, all three source indices being "this instruction" (0xFFFF).
fn ed25519_ix(signer: &Keypair, msg: &[u8], tamper_signature: bool) -> Instruction {
    ed25519_ix_sourced_from(signer, msg, tamper_signature, u16::MAX)
}

/// The same, but with a chosen `source_index` for where the precompile should read
/// the public key, signature and message from. `u16::MAX` means "this
/// instruction's own data", which is the only layout the program accepts.
fn ed25519_ix_sourced_from(
    signer: &Keypair,
    msg: &[u8],
    tamper_signature: bool,
    source_index: u16,
) -> Instruction {
    let mut sig = signer.sign_message(msg).as_ref().to_vec();
    if tamper_signature {
        sig[0] ^= 0xFF;
    }
    let pk = signer.pubkey().to_bytes();

    let mut data = Vec::with_capacity(16 + 32 + 64 + msg.len());
    data.push(1); // one signature
    data.push(0); // padding
    for v in [48u16, source_index, 16u16, source_index, 112u16, msg.len() as u16, source_index] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data.extend_from_slice(&pk);
    data.extend_from_slice(&sig);
    data.extend_from_slice(msg);

    Instruction { program_id: solana_sdk::ed25519_program::ID, accounts: vec![], data }
}

/// `commit` now moves lamports, so the committer must be writable and the pool
/// must be too.
fn commit_ix(pool: Pubkey, committer: &Keypair, commitment: [u8; 32]) -> Instruction {
    let mut data = disc("commit").to_vec();
    data.extend_from_slice(&commitment);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(committer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn pool_member_count(svm: &LiteSVM, pool: &Pubkey) -> u32 {
    let data = svm.get_account(pool).unwrap().data;
    u32::from_le_bytes(data[148..152].try_into().unwrap())
}

fn pool_round(svm: &LiteSVM, pool: &Pubkey) -> u64 {
    let data = svm.get_account(pool).unwrap().data;
    u64::from_le_bytes(data[152..160].try_into().unwrap())
}

/// An initialized pool with a published root and enough members to clear the
/// anonymity floor — the ordinary state an execution happens in.
fn pool_ready() -> (LiteSVM, Keypair, Keypair, Pubkey, [u8; 32]) {
    let (mut svm, authority, verifier, pool, root) = pool_ready_with(K_MIN);
    svm.expire_blockhash();
    (svm, authority, verifier, pool, root)
}

/// The same, with a chosen number of members, so the floor itself can be tested.
fn pool_ready_with(members: u32) -> (LiteSVM, Keypair, Keypair, Pubkey, [u8; 32]) {
    let (mut svm, authority) = load();
    let verifier = Keypair::new();
    let (pool, _) = pool_pda(&authority.pubkey());
    let root = [0x5A; 32];

    let mut data = disc("initialize").to_vec();
    data.extend_from_slice(verifier.pubkey().as_ref());
    data.extend_from_slice(&ENTRY_FEE.to_le_bytes());
    data.extend_from_slice(&K_MIN.to_le_bytes());
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    assert!(send(&mut svm, &[&authority], ix), "initialize should succeed");

    let mut data = disc("publish_root").to_vec();
    data.extend_from_slice(&root);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data,
    };
    assert!(send(&mut svm, &[&authority], ix), "publish_root should succeed");

    for i in 0..members {
        svm.expire_blockhash();
        assert!(
            send(&mut svm, &[&authority], commit_ix(pool, &authority, [(i + 1) as u8; 32])),
            "commit should succeed"
        );
    }

    (svm, authority, verifier, pool, root)
}

fn execute_ix(
    pool: Pubkey,
    relayer: &Keypair,
    root: [u8; 32],
    action: [u8; 32],
    nf: [u8; 32],
    round: u64,
) -> Instruction {
    let mut data = disc("execute").to_vec();
    data.extend_from_slice(&action);
    data.extend_from_slice(&nf);
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&root);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(nullifier_pda(&pool, &nf).0, false),
            AccountMeta::new(relayer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(
                solana_sdk::sysvar::instructions::ID,
                false,
            ),
        ],
        data,
    }
}

fn relayer(svm: &mut LiteSVM) -> Keypair {
    let r = Keypair::new();
    svm.airdrop(&r.pubkey(), 10_000_000_000).unwrap();
    r
}

/// Audit-critical #2: before this, `execute` checked only the round and the
/// nullifier PDA — any signer could settle an action for a member they were not,
/// and a watcher could front-run a nullifier out of the mempool. `execute` now
/// requires an Ed25519 attestation from the pool's named verifier, bound to the
/// exact `(pool, root, action, nullifier, round)` being settled.
///
/// This is a *trust-minimising* control, not a trustless one: it moves the hole
/// from "anyone" to "a named key", and the on-chain program still does not verify
/// the membership proof itself. See the README's Security status.
mod attestation {
    use super::*;

    #[test]
    fn joining_the_set_costs_the_entry_fee() {
        // Permissionless commit means k is buyable: an attacker who can create
        // members for free owns the anonymity set. The fee makes each seat cost
        // something, and the lamports land in the pool rather than nowhere.
        let (mut svm, authority, _v, pool, _root) = pool_ready_with(0);
        let before = svm.get_account(&pool).unwrap().lamports;

        assert!(send(&mut svm, &[&authority], commit_ix(pool, &authority, [1u8; 32])));

        let after = svm.get_account(&pool).unwrap().lamports;
        assert_eq!(after - before, ENTRY_FEE, "the seat is paid for, into the pool");
    }

    #[test]
    fn an_execution_below_the_anonymity_floor_is_rejected() {
        // A pool with one member offers that member nothing: the action is theirs
        // by elimination. The program refuses to settle it.
        let (mut svm, authority, verifier, pool, root) = pool_ready_with(K_MIN - 1);

        let relayer = relayer(&mut svm);
        let (action, nf) = ([7u8; 32], [0xC1; 32]);
        let msg = attestation_message(&pool, &root, &action, &nf, 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&verifier, &msg, false),
                execute_ix(pool, &relayer, root, action, nf, 0),
            ],
        )
        .expect_err("a set of one is not an anonymity set");
        assert!(err.contains("AnonymitySetTooSmall"), "got: {err}");

        // one more member and the same execution settles
        svm.expire_blockhash();
        assert!(send(&mut svm, &[&authority], commit_ix(pool, &authority, [0x9u8; 32])));
        svm.expire_blockhash();
        send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&verifier, &msg, false),
                execute_ix(pool, &relayer, root, action, nf, 0),
            ],
        )
        .expect("at k_min the execution settles");
    }

    #[test]
    fn an_attested_execution_succeeds_and_still_cannot_be_replayed() {
        let (mut svm, _auth, verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);
        let (action, nf) = ([7u8; 32], [0xAA; 32]);

        let msg = attestation_message(&pool, &root, &action, &nf, 0);
        let ixs = [
            ed25519_ix(&verifier, &msg, false),
            execute_ix(pool, &relayer, root, action, nf, 0),
        ];
        send_many(&mut svm, &[&relayer], &ixs).expect("attested execution should succeed");
        assert!(svm.get_account(&nullifier_pda(&pool, &nf).0).is_some());

        // a fresh blockhash, so this is a genuinely new transaction rather than a
        // duplicate the runtime would drop before reaching the program
        svm.expire_blockhash();
        let err = send_many(&mut svm, &[&relayer], &ixs)
            .expect_err("the same nullifier must not settle twice");
        assert!(err.contains("already in use"), "got: {err}");
    }

    #[test]
    fn an_attestation_that_sources_its_message_from_elsewhere_is_rejected() {
        // The classic break in this pattern: the sigverify instruction declares
        // *where* the key and message come from. If the program reads them at fixed
        // offsets in the sigverify instruction's own data but lets the declared
        // source point at some other instruction, the precompile can be made to
        // check a different message than the one the program reads. So the program
        // accepts only the self-contained layout (source index 0xFFFF).
        let (mut svm, _auth, verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);
        let (action, nf) = ([7u8; 32], [0xB1; 32]);

        let msg = attestation_message(&pool, &root, &action, &nf, 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix_sourced_from(&verifier, &msg, false, 0),
                execute_ix(pool, &relayer, root, action, nf, 0),
            ],
        )
        .expect_err("only a self-contained sigverify instruction may attest");
        assert!(err.contains("AttestationMismatch"), "got: {err}");
    }

    #[test]
    fn an_execution_with_no_attestation_is_rejected() {
        let (mut svm, _auth, _verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);

        let err = send_many(
            &mut svm,
            &[&relayer],
            &[execute_ix(pool, &relayer, root, [7u8; 32], [0xAB; 32], 0)],
        )
        .expect_err("an unattested execution must be rejected");
        assert!(err.contains("MissingAttestation"), "got: {err}");
    }

    #[test]
    fn an_attestation_from_the_wrong_key_is_rejected() {
        let (mut svm, _auth, _verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);
        let impostor = Keypair::new();
        let (action, nf) = ([7u8; 32], [0xAC; 32]);

        let msg = attestation_message(&pool, &root, &action, &nf, 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&impostor, &msg, false),
                execute_ix(pool, &relayer, root, action, nf, 0),
            ],
        )
        .expect_err("only the pool's named verifier may attest");
        assert!(err.contains("UnknownVerifier"), "got: {err}");
    }

    #[test]
    fn an_attestation_for_a_different_nullifier_is_rejected() {
        // The front-running case: a watcher lifts a valid attestation and tries to
        // settle a nullifier of their own choosing with it.
        let (mut svm, _auth, verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);
        let action = [7u8; 32];

        let msg = attestation_message(&pool, &root, &action, &[0xAD; 32], 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&verifier, &msg, false),
                execute_ix(pool, &relayer, root, action, [0xAE; 32], 0),
            ],
        )
        .expect_err("the attestation must bind the nullifier it settles");
        assert!(err.contains("AttestationMismatch"), "got: {err}");
    }

    #[test]
    fn an_execution_against_an_unpublished_root_is_rejected() {
        let (mut svm, _auth, verifier, pool, _root) = pool_ready();
        let relayer = relayer(&mut svm);
        let (action, nf, stale) = ([7u8; 32], [0xAF; 32], [0x11; 32]);

        let msg = attestation_message(&pool, &stale, &action, &nf, 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&verifier, &msg, false),
                execute_ix(pool, &relayer, stale, action, nf, 0),
            ],
        )
        .expect_err("executions are bound to the root the pool published");
        assert!(err.contains("RootMismatch"), "got: {err}");
    }

    #[test]
    fn a_forged_signature_is_rejected_by_the_runtime() {
        // The program trusts the Ed25519 precompile to have checked the signature;
        // this asserts the precompile actually runs here, so the rest of these
        // tests are not green for the wrong reason.
        let (mut svm, _auth, verifier, pool, root) = pool_ready();
        let relayer = relayer(&mut svm);
        let (action, nf) = ([7u8; 32], [0xB0; 32]);

        let msg = attestation_message(&pool, &root, &action, &nf, 0);
        let err = send_many(
            &mut svm,
            &[&relayer],
            &[
                ed25519_ix(&verifier, &msg, true),
                execute_ix(pool, &relayer, root, action, nf, 0),
            ],
        )
        .expect_err("a tampered signature must not verify");
        // instruction 0 is the sigverify precompile: the runtime rejected it before
        // our program ran at all, which is what the program's check relies on
        assert!(err.contains("InstructionError(0,"), "got: {err}");
    }
}

#[test]
fn full_lifecycle() {
    let (mut svm, authority, verifier, pool, root) = pool_ready_with(0);
    assert_eq!(pool_member_count(&svm, &pool), 0);
    assert_eq!(pool_round(&svm, &pool), 0);

    // commit two members
    for c in [[1u8; 32], [2u8; 32]] {
        assert!(
            send(&mut svm, &[&authority], commit_ix(pool, &authority, c)),
            "commit should succeed"
        );
    }
    assert_eq!(pool_member_count(&svm, &pool), 2, "two members committed");

    // execute an action for round 0 via a relayer (no member key signs), carrying
    // the verifier's attestation
    let relayer = relayer(&mut svm);
    let (action, nf1) = ([7u8; 32], [0xAA; 32]);
    let attested = |nf: [u8; 32], round: u64| {
        [
            ed25519_ix(&verifier, &attestation_message(&pool, &root, &action, &nf, round), false),
            execute_ix(pool, &relayer, root, action, nf, round),
        ]
    };

    send_many(&mut svm, &[&relayer], &attested(nf1, 0)).expect("first execution should succeed");
    assert!(svm.get_account(&nullifier_pda(&pool, &nf1).0).is_some(), "nullifier PDA now exists");

    // double execution with the same nullifier must fail (PDA already exists)
    svm.expire_blockhash();
    assert!(
        send_many(&mut svm, &[&relayer], &attested(nf1, 0)).is_err(),
        "double execution (nullifier reuse) must be rejected"
    );

    // execution for a stale round must fail (pool is at round 0)
    assert!(
        send_many(&mut svm, &[&relayer], &attested([0xBB; 32], 9)).is_err(),
        "execution for the wrong round must be rejected"
    );

    // advance the round
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
