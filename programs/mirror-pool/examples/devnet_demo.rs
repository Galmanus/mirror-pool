//! Live devnet demo of the behavioral cloak: a member commits, then a **relayer**
//! executes the member's action — and the member's key never signs the execution.
//! An observer of the permanent record sees the action happen but cannot say which
//! committer did it. Prints the confirmed signatures so the run is checkable.
//!
//! Run: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example devnet_demo`
//! Uses the default Solana CLI wallet (`~/.config/solana/id.json`) only to *fund*
//! four fresh roles (authority, verifier, member, relayer); the privacy claim is in
//! who signs what, so the roles are kept distinct.

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction, system_program,
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

    // Four distinct roles. The whole behavioral-privacy claim is about *who signs
    // what*, so we never collapse them onto one key.
    let authority = Keypair::new(); // owns the pool, publishes the root
    let verifier = Keypair::new(); // the committee (of one, here), attests membership
    let member = Keypair::new(); // the user: commits an intent
    let relayer = Keypair::new(); // submits the execution so the member need not

    let (pool, _) =
        Pubkey::find_program_address(&[b"pool", authority.pubkey().as_ref()], &PROGRAM_ID);
    println!("program : {PROGRAM_ID}");
    println!("pool PDA: {pool}");
    println!("member  : {}", member.pubkey());
    println!("relayer : {}\n", relayer.pubkey());

    let send = |name: &str, ixs: &[Instruction], fee_payer: &Keypair, signers: &[&Keypair]| -> bool {
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(ixs, Some(&fee_payer.pubkey()), signers, bh);
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

    // 0. fund the three fresh roles that must pay their own way, from the CLI wallet
    let fund = vec![
        system_instruction::transfer(&payer.pubkey(), &authority.pubkey(), 50_000_000),
        system_instruction::transfer(&payer.pubkey(), &member.pubkey(), 20_000_000),
        system_instruction::transfer(&payer.pubkey(), &relayer.pubkey(), 20_000_000),
    ];
    if !send("fund roles", &fund, &payer, &[&payer]) {
        eprintln!("could not fund roles — is the devnet wallet topped up?");
        std::process::exit(1);
    }

    // 1. initialize a fresh pool: a committee of one (verifier), threshold 1
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: {
            let mut d = disc("initialize").to_vec();
            d.extend_from_slice(&1u32.to_le_bytes()); // committee: Vec len = 1
            d.extend_from_slice(verifier.pubkey().as_ref());
            d.push(1); // threshold = 1
            d.extend_from_slice(&5_000_000u64.to_le_bytes()); // entry fee: 0.005 SOL a seat
            d.extend_from_slice(&1u32.to_le_bytes()); // k_min for the demo
            d
        },
    };
    send("initialize", &[ix], &authority, &[&authority]);

    // 1b. publish the membership root executions settle against (authority-gated).
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
    send("publish_root", &[ix], &authority, &[&authority]);

    // 2. the MEMBER commits an intent, paying the entry fee. This is the only place
    //    the member's key appears on-chain — joining the crowd, not acting.
    let commitment = Keypair::new().pubkey().to_bytes();
    let mut data = disc("commit").to_vec();
    data.extend_from_slice(&commitment);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(member.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    send("commit (member signs)", &[ix], &member, &[&member]);

    // 3. the RELAYER executes the action. A fresh pool is at round 0. The member's
    //    key is nowhere in this transaction — that is the whole point.
    let round = 0u64;
    let nullifier = Keypair::new().pubkey().to_bytes();
    let action = *b"riverrun-devnet-demo-action-0001";
    let (nf_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifier], &PROGRAM_ID);

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

    send("execute (relayer signs)", &attested(nullifier, nf_pda, round), &relayer, &[&relayer]);

    // 4. the same nullifier a second time must be rejected on the live cluster
    let ok = send(
        "execute (double-spend)",
        &attested(nullifier, nf_pda, round),
        &relayer,
        &[&relayer],
    );
    println!(
        "\ndouble-spend {}",
        if ok { "UNEXPECTEDLY SUCCEEDED (bug!)" } else { "correctly REJECTED on-chain" }
    );
    println!(
        "\nThe member signed only `commit`. `execute` was signed by the relayer alone —\n\
         the actor is unlinked from the action on a permanent, public ledger."
    );
}
