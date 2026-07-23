//! Live devnet demo: send real transactions to the deployed riverrun program and
//! print the confirmed signatures. Proves the program runs on a real cluster
//! (not just the in-process LiteSVM e2e).
//!
//! Run: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example devnet_demo`
//! Uses the default Solana CLI wallet (`~/.config/solana/id.json`) as payer +
//! pool authority, and the devnet RPC.

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_program,
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");

fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize()[..8]);
    out
}

fn main() {
    let rpc = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    );
    let home = std::env::var("HOME").unwrap();
    let payer = read_keypair_file(format!("{home}/.config/solana/id.json"))
        .expect("read ~/.config/solana/id.json");
    let authority = &payer;

    let (pool, _) = Pubkey::find_program_address(&[b"pool", authority.pubkey().as_ref()], &PROGRAM_ID);
    println!("program : {PROGRAM_ID}");
    println!("pool PDA: {pool}\n");

    let send_many = |name: &str, ixs: &[Instruction], signers: &[&Keypair]| -> bool {
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), signers, bh);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("  {name:<26} OK   {sig}");
                true
            }
            Err(e) => {
                let msg = e.to_string();
                let short = msg.lines().next().unwrap_or(&msg);
                println!("  {name:<26} FAIL {short}");
                false
            }
        }
    };

    let send = |name: &str, ix: Instruction, signers: &[&Keypair]| -> bool {
        send_many(name, &[ix], signers)
    };

    // The verifier attests that it checked the off-chain membership proof. In a
    // real deployment this is a separate operator (or a threshold of them); here
    // the demo operator plays that role, which is exactly the trust assumption the
    // README's Security status names.
    let verifier: &Keypair = authority;

    // 1. initialize (skip if the pool already exists from a prior run)
    if rpc.get_account(&pool).is_err() {
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: {
                let mut d = disc("initialize").to_vec();
                d.extend_from_slice(verifier.pubkey().as_ref());
                d.extend_from_slice(&5_000_000u64.to_le_bytes()); // entry fee: 0.005 SOL a seat
                d.extend_from_slice(&1u32.to_le_bytes()); // k_min for the demo
                d
            },
        };
        send("initialize", ix, &[authority]);
    } else {
        println!("  initialize                 SKIP (pool already exists)");
    }

    // 1b. publish the membership root executions are settled against. The
    // canonical tree is Rescue-Prime and lives off-chain, so the root is published
    // here rather than recomputed on-chain.
    let root = *b"riverrun-devnet-demo-root-000001";
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
    send("publish_root", ix, &[authority]);

    // 2. commit a member
    let commitment = Keypair::new().pubkey().to_bytes(); // unique per run
    let mut data = disc("commit").to_vec();
    data.extend_from_slice(&commitment);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    send("commit", ix, &[authority]);

    // read the pool's current round
    let pool_data = rpc.get_account_data(&pool).unwrap();
    let round = u64::from_le_bytes(pool_data[152..160].try_into().unwrap());
    let member_count = u32::from_le_bytes(pool_data[148..152].try_into().unwrap());
    println!("  (pool now: round={round}, members={member_count})");

    // 3. execute via a fresh relayer key (no member signs) — unique nullifier
    let relayer = &payer; // payer relays, for demo simplicity
    let nullifier = Keypair::new().pubkey().to_bytes();
    let action = *b"riverrun-devnet-demo-action-0001";
    let (nf_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifier], &PROGRAM_ID);

    // the verifier's attestation, bound to this exact pool, root, action,
    // nullifier and round
    let attestation = |nf: [u8; 32], round: u64| -> Instruction {
        let mut msg = Vec::with_capacity(152);
        msg.extend_from_slice(b"riverrun-exec-v1");
        msg.extend_from_slice(pool.as_ref());
        msg.extend_from_slice(&root);
        msg.extend_from_slice(&action);
        msg.extend_from_slice(&nf);
        msg.extend_from_slice(&round.to_le_bytes());

        let sig = verifier.sign_message(&msg);
        let mut data = Vec::with_capacity(16 + 32 + 64 + msg.len());
        data.push(1);
        data.push(0);
        for v in [48u16, u16::MAX, 16u16, u16::MAX, 112u16, msg.len() as u16, u16::MAX] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(&verifier.pubkey().to_bytes());
        data.extend_from_slice(sig.as_ref());
        data.extend_from_slice(&msg);
        Instruction { program_id: solana_sdk::ed25519_program::ID, accounts: vec![], data }
    };

    let exec_ix = |nf: [u8; 32], nf_pda: Pubkey, round: u64| {
        let mut data = disc("execute").to_vec();
        data.extend_from_slice(&action);
        data.extend_from_slice(&nf);
        data.extend_from_slice(&round.to_le_bytes());
        data.extend_from_slice(&root);
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new(nf_pda, false),
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            ],
            data,
        }
    };

    let attested = |nf: [u8; 32], nf_pda: Pubkey, round: u64| {
        vec![attestation(nf, round), exec_ix(nf, nf_pda, round)]
    };

    send_many("execute", &attested(nullifier, nf_pda, round), &[relayer]);
    // 4. double execution with the same nullifier must fail on the live cluster
    let ok = send_many(
        "execute (double-spend)",
        &attested(nullifier, nf_pda, round),
        &[relayer],
    );
    println!(
        "\ndouble-spend {}",
        if ok { "UNEXPECTEDLY SUCCEEDED (bug!)" } else { "correctly REJECTED on-chain" }
    );
}
