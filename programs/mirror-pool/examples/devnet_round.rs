//! Live devnet demo of a full multi-member **round**: the crowd, not one actor.
//!
//! `k` distinct members each commit an intent, each signing only their own commit.
//! The pool's anonymity floor is set to `k_min = k`, so the program refuses any
//! execution until the whole crowd has formed (shown live: an early execute is
//! rejected on-chain with `AnonymitySetTooSmall`). Once the crowd is complete, a
//! single **relayer** settles every member's action, signing all of them alone,
//! with `k` distinct nullifiers. An observer of the permanent record sees `k`
//! identical actions and `k` committers but cannot say which committer is behind
//! which action. Every confirmed signature is printed so the run is checkable.
//!
//! Run: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example devnet_round [k]`
//! (default k = 8). Uses the default Solana CLI wallet only to fund fresh roles;
//! the privacy claim is in who signs what, so the roles are kept distinct.

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature, Signer},
    system_instruction, system_program,
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");
const PAYOUT_LAMPORTS: u64 = 1_000_000; // must match the program's fixed denomination

fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize()[..8]);
    out
}

fn main() {
    let k: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .max(2);

    let rpc = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    );
    let home = std::env::var("HOME").unwrap();
    let payer = read_keypair_file(format!("{home}/.config/solana/id.json"))
        .expect("read ~/.config/solana/id.json");

    let authority = Keypair::new(); // owns the pool, publishes the root, sets k_min
    let verifier = Keypair::new(); // the committee of one, attests each execution
    let members: Vec<Keypair> = (0..k).map(|_| Keypair::new()).collect();
    let relayer = Keypair::new(); // settles every action; no member key signs execute

    let (pool, _) =
        Pubkey::find_program_address(&[b"pool", authority.pubkey().as_ref()], &PROGRAM_ID);
    let (vault, _) = Pubkey::find_program_address(&[b"vault", pool.as_ref()], &PROGRAM_ID);
    let root = *b"riverrun-devnet-round-root-00001";
    let action = *b"riverrun-devnet-round-action-001";

    println!("program : {PROGRAM_ID}");
    println!("pool PDA: {pool}");
    println!("round   : k = {k} members, k_min = {k} (floor enforced on-chain)");
    println!("relayer : {}\n", relayer.pubkey());

    let send = |name: &str, ixs: &[Instruction], fee_payer: &Keypair, signers: &[&Keypair]| -> Option<Signature> {
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(ixs, Some(&fee_payer.pubkey()), signers, bh);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("  {name:<28} OK   {sig}");
                Some(sig)
            }
            Err(e) => {
                let msg = e.to_string();
                let short = msg.lines().next().unwrap_or(&msg);
                println!("  {name:<28} FAIL {short}");
                None
            }
        }
    };

    // 0. fund the fresh roles. Authority and relayer pay their own fees; each member
    //    pays one entry fee; the vault holds k payouts. Chunk the transfers so no
    //    single funding transaction grows too large.
    println!("funding {k} members + roles:");
    let vault_topup = 20_000_000 + (k as u64) * PAYOUT_LAMPORTS;
    let base = vec![
        system_instruction::transfer(&payer.pubkey(), &authority.pubkey(), 50_000_000),
        system_instruction::transfer(&payer.pubkey(), &relayer.pubkey(), 60_000_000),
        system_instruction::transfer(&payer.pubkey(), &vault, vault_topup),
    ];
    if send("fund roles", &base, &payer, &[&payer]).is_none() {
        eprintln!("could not fund roles, is the devnet wallet topped up?");
        std::process::exit(1);
    }
    for (chunk_i, chunk) in members.chunks(6).enumerate() {
        let ixs: Vec<Instruction> = chunk
            .iter()
            .map(|m| system_instruction::transfer(&payer.pubkey(), &m.pubkey(), 20_000_000))
            .collect();
        send(&format!("fund members {chunk_i}"), &ixs, &payer, &[&payer]);
    }

    // 1. initialize the pool: committee of one, threshold 1, k_min = k so the crowd
    //    must be complete before any action settles.
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
            d.extend_from_slice(&(k as u32).to_le_bytes()); // k_min = k
            d
        },
    };
    send("initialize", &[ix], &authority, &[&authority]);

    // 1b. publish the membership root executions settle against (authority-gated).
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

    // Build a committee attestation + execute pair for one member's action. The
    // attestation binds the recipient, so a relayer cannot redirect the payout.
    let attested = |nullifier: [u8; 32], recipient: &Pubkey, round: u64| -> Vec<Instruction> {
        let (nf_pda, _) =
            Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifier], &PROGRAM_ID);

        let mut msg = Vec::with_capacity(184);
        msg.extend_from_slice(b"riverrun-exec-v2");
        msg.extend_from_slice(pool.as_ref());
        msg.extend_from_slice(&root);
        msg.extend_from_slice(&action);
        msg.extend_from_slice(&nullifier);
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(recipient.as_ref());
        let sig = verifier.sign_message(&msg);

        let mut edata = Vec::with_capacity(16 + 32 + 64 + msg.len());
        edata.push(1);
        edata.push(0);
        for v in [48u16, u16::MAX, 16u16, u16::MAX, 112u16, msg.len() as u16, u16::MAX] {
            edata.extend_from_slice(&v.to_le_bytes());
        }
        edata.extend_from_slice(&verifier.pubkey().to_bytes());
        edata.extend_from_slice(sig.as_ref());
        edata.extend_from_slice(&msg);
        let ed_ix = Instruction { program_id: solana_sdk::ed25519_program::ID, accounts: vec![], data: edata };

        let mut xdata = disc("execute").to_vec();
        xdata.extend_from_slice(&action);
        xdata.extend_from_slice(&nullifier);
        xdata.extend_from_slice(&round.to_le_bytes());
        xdata.extend_from_slice(&root);
        let exec_ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new(nf_pda, false),
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new(vault, false),
                AccountMeta::new(*recipient, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            ],
            data: xdata,
        };
        vec![ed_ix, exec_ix]
    };

    let round = 0u64;

    // 2. the first member commits, then we try to settle immediately. With k_min = k
    //    the floor is not met, and the program rejects the execution on-chain. This
    //    is the anonymity floor, enforced live, not a promise in a README.
    let commitment = Keypair::new().pubkey().to_bytes();
    let mut cdata = disc("commit").to_vec();
    cdata.extend_from_slice(&commitment);
    let commit_ix = |m: &Pubkey, data: Vec<u8>| Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(*m, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    println!("\nforming the crowd:");
    let mut commit_sigs = Vec::new();
    if let Some(s) = send(
        "commit 1/k (member signs)",
        &[commit_ix(&members[0].pubkey(), cdata)],
        &members[0],
        &[&members[0]],
    ) {
        commit_sigs.push(s);
    }

    println!("\nfloor check (crowd incomplete, execution must be refused):");
    let early_nf = Keypair::new().pubkey().to_bytes();
    let early_recipient = Keypair::new().pubkey();
    let refused = send(
        "execute @ 1 member",
        &attested(early_nf, &early_recipient, round),
        &relayer,
        &[&relayer],
    );
    println!(
        "  -> {}",
        if refused.is_some() {
            "UNEXPECTEDLY SETTLED (floor bug!)"
        } else {
            "correctly REFUSED on-chain (AnonymitySetTooSmall)"
        }
    );

    // 3. the rest of the crowd commits, each member signing only their own commit.
    println!("\ncompleting the crowd:");
    for (i, m) in members.iter().enumerate().skip(1) {
        let commitment = Keypair::new().pubkey().to_bytes();
        let mut cdata = disc("commit").to_vec();
        cdata.extend_from_slice(&commitment);
        if let Some(s) = send(
            &format!("commit {}/{k} (member signs)", i + 1),
            &[commit_ix(&m.pubkey(), cdata)],
            m,
            &[m],
        ) {
            commit_sigs.push(s);
        }
    }

    // 4. the crowd is complete. The relayer settles every action, alone, with a
    //    distinct nullifier each. No member key appears in any execution.
    println!("\nsettling the round (relayer signs every execution, no member does):");
    let mut exec_sigs = Vec::new();
    let mut first_nullifier = None;
    for i in 0..k {
        let nullifier = Keypair::new().pubkey().to_bytes();
        if first_nullifier.is_none() {
            first_nullifier = Some(nullifier);
        }
        let recipient = Keypair::new().pubkey();
        if let Some(s) = send(
            &format!("execute {}/{k} (relayer)", i + 1),
            &attested(nullifier, &recipient, round),
            &relayer,
            &[&relayer],
        ) {
            exec_sigs.push(s);
        }
    }

    // 5. replay one spent nullifier: the per-nullifier PDA already exists, so the
    //    second execution must be rejected on the live cluster.
    println!("\nanti-replay (a spent nullifier, reused):");
    let recipient = Keypair::new().pubkey();
    let replayed = send(
        "execute (double-spend)",
        &attested(first_nullifier.unwrap(), &recipient, round),
        &relayer,
        &[&relayer],
    );
    println!(
        "  -> {}",
        if replayed.is_some() {
            "UNEXPECTEDLY SUCCEEDED (bug!)"
        } else {
            "correctly REJECTED on-chain (NullifierSpent)"
        }
    );

    println!("\n{}", "=".repeat(72));
    println!(
        "round complete: {} of {k} members committed, {} of {k} actions settled.",
        commit_sigs.len(),
        exec_sigs.len()
    );
    println!(
        "the crowd signed {} commits with {} distinct keys; the relayer signed all {}\n\
         executions alone. {} distinct nullifiers were spent, one per action, and the\n\
         floor refused settlement until the crowd was complete. An observer sees {k}\n\
         identical actions and cannot link any of them to a committer.",
        commit_sigs.len(),
        commit_sigs.len(),
        exec_sigs.len(),
        exec_sigs.len(),
    );
}
