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

    let send = |name: &str, ix: Instruction, signers: &[&Keypair]| -> bool {
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            signers,
            bh,
        );
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

    // 1. initialize (skip if the pool already exists from a prior run)
    if rpc.get_account(&pool).is_err() {
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: disc("initialize").to_vec(),
        };
        send("initialize", ix, &[authority]);
    } else {
        println!("  initialize                 SKIP (pool already exists)");
    }

    // 2. commit a member
    let commitment = Keypair::new().pubkey().to_bytes(); // unique per run
    let mut data = disc("commit").to_vec();
    data.extend_from_slice(&commitment);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data,
    };
    send("commit", ix, &[authority]);

    // read the pool's current round
    let pool_data = rpc.get_account_data(&pool).unwrap();
    let round = u64::from_le_bytes(pool_data[76..84].try_into().unwrap());
    let member_count = u32::from_le_bytes(pool_data[72..76].try_into().unwrap());
    println!("  (pool now: round={round}, members={member_count})");

    // 3. execute via a fresh relayer key (no member signs) — unique nullifier
    let relayer = &payer; // payer relays, for demo simplicity
    let nullifier = Keypair::new().pubkey().to_bytes();
    let action = *b"riverrun-devnet-demo-action-0001";
    let (nf_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifier], &PROGRAM_ID);

    let exec_ix = |nf: [u8; 32], nf_pda: Pubkey, round: u64| {
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

    send("execute", exec_ix(nullifier, nf_pda, round), &[relayer]);
    // 4. double execution with the same nullifier must fail on the live cluster
    let ok = send("execute (double-spend)", exec_ix(nullifier, nf_pda, round), &[relayer]);
    println!(
        "\ndouble-spend {}",
        if ok { "UNEXPECTEDLY SUCCEEDED (bug!)" } else { "correctly REJECTED on-chain" }
    );
}
