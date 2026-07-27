//! The batch answer, live: a whole round settled in ONE devnet transaction via an
//! Address Lookup Table. One relayer signature, one committee attestation over the
//! batch, k payouts from the vault, no member key. This is the k-actions-in-one-tx
//! consolidation the curve pools do, but post-quantum.
//!
//! Run: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example batch_alt_devnet [k]`

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    address_lookup_table::{instruction as alt_ix, AddressLookupTableAccount},
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction, system_program,
    transaction::{Transaction, VersionedTransaction},
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");
const PAYOUT: u64 = 1_000_000;

fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut o = [0u8; 8];
    o.copy_from_slice(&h.finalize()[..8]);
    o
}

fn main() {
    let k: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8).max(2);
    let rpc = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    );
    let home = std::env::var("HOME").unwrap();
    let payer = read_keypair_file(format!("{home}/.config/solana/id.json")).unwrap();

    let authority = Keypair::new();
    let verifier = Keypair::new();
    let relayer = Keypair::new();
    let (pool, _) = Pubkey::find_program_address(&[b"pool", authority.pubkey().as_ref()], &PROGRAM_ID);
    let (vault, _) = Pubkey::find_program_address(&[b"vault", pool.as_ref()], &PROGRAM_ID);
    let root = *b"riverrun-batch-alt-root-00000001";

    println!("program : {PROGRAM_ID}");
    println!("pool    : {pool}");
    println!("batch   : k = {k} actions in ONE transaction via ALT\n");

    let send = |name: &str, ixs: &[Instruction], fee: &Keypair, signers: &[&Keypair]| -> String {
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(ixs, Some(&fee.pubkey()), signers, bh);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(s) => { println!("  {name:<22} OK   {s}"); s.to_string() }
            Err(e) => { println!("  {name:<22} FAIL {}", e.to_string().lines().next().unwrap_or("")); String::new() }
        }
    };

    // setup
    println!("setup:");
    send("fund roles", &[
        system_instruction::transfer(&payer.pubkey(), &authority.pubkey(), 60_000_000),
        system_instruction::transfer(&payer.pubkey(), &relayer.pubkey(), 200_000_000),
        system_instruction::transfer(&payer.pubkey(), &vault, 50_000_000 + (k as u64) * PAYOUT),
    ], &payer, &[&payer]);
    let mut init = disc("initialize").to_vec();
    init.extend_from_slice(&1u32.to_le_bytes());
    init.extend_from_slice(verifier.pubkey().as_ref());
    init.push(1);
    init.extend_from_slice(&5_000_000u64.to_le_bytes());
    init.extend_from_slice(&(k as u32).to_le_bytes());
    send("initialize", &[Instruction { program_id: PROGRAM_ID, accounts: vec![
        AccountMeta::new(pool, false), AccountMeta::new(authority.pubkey(), true),
        AccountMeta::new_readonly(system_program::ID, false)], data: init }], &authority, &[&authority]);
    let mut pr = disc("publish_root").to_vec();
    pr.extend_from_slice(&root);
    send("publish_root", &[Instruction { program_id: PROGRAM_ID, accounts: vec![
        AccountMeta::new(pool, false), AccountMeta::new_readonly(authority.pubkey(), true)], data: pr }],
        &authority, &[&authority]);

    // commit k members to meet the floor (fresh key each)
    println!("\nforming the crowd ({k} members):");
    for i in 0..k {
        let m = Keypair::new();
        send(&format!("fund m{i}"),
            &[system_instruction::transfer(&payer.pubkey(), &m.pubkey(), 20_000_000)], &payer, &[&payer]);
        let mut c = disc("commit").to_vec();
        c.extend_from_slice(&Keypair::new().pubkey().to_bytes());
        send(&format!("commit m{i}"), &[Instruction { program_id: PROGRAM_ID, accounts: vec![
            AccountMeta::new(pool, false), AccountMeta::new(m.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false)], data: c }], &m, &[&m]);
    }

    // build the batch: k (action, nullifier, recipient)
    let actions: Vec<[u8; 32]> = (0..k).map(|i| [0xA0 + i as u8; 32]).collect();
    let nullifiers: Vec<[u8; 32]> = (0..k).map(|i| { let mut n=[0u8;32]; n[0]=0xB0+i as u8; n[31]=i as u8; n }).collect();
    let recipients: Vec<Keypair> = (0..k).map(|_| Keypair::new()).collect();

    // one committee attestation over the whole batch
    let mut hdig = Sha256::new();
    for i in 0..k { hdig.update(actions[i]); hdig.update(nullifiers[i]); hdig.update(recipients[i].pubkey().as_ref()); }
    let digest: [u8; 32] = hdig.finalize().into();
    let mut msg = vec![0u8; 184];
    msg[..16].copy_from_slice(b"riverrun-batch-1");
    msg[16..48].copy_from_slice(pool.as_ref());
    msg[48..80].copy_from_slice(&root);
    msg[80..112].copy_from_slice(&digest);
    // round = 0 at m[144..152] stays zero
    let sig = verifier.sign_message(&msg);
    let mut edata = Vec::new();
    edata.push(1); edata.push(0);
    for v in [48u16, u16::MAX, 16u16, u16::MAX, 112u16, msg.len() as u16, u16::MAX] { edata.extend_from_slice(&v.to_le_bytes()); }
    edata.extend_from_slice(&verifier.pubkey().to_bytes());
    edata.extend_from_slice(sig.as_ref());
    edata.extend_from_slice(&msg);
    let att_ix = Instruction { program_id: solana_sdk::ed25519_program::ID, accounts: vec![], data: edata };

    // the execute_batch instruction
    let mut xdata = disc("execute_batch").to_vec();
    xdata.extend_from_slice(&(k as u32).to_le_bytes());
    for a in &actions { xdata.extend_from_slice(a); }
    xdata.extend_from_slice(&(k as u32).to_le_bytes());
    for n in &nullifiers { xdata.extend_from_slice(n); }
    xdata.extend_from_slice(&0u64.to_le_bytes());
    xdata.extend_from_slice(&root);
    let mut accts = vec![
        AccountMeta::new_readonly(pool, false),
        AccountMeta::new(relayer.pubkey(), true),
        AccountMeta::new(vault, false),
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
    ];
    let mut lookup_addrs: Vec<Pubkey> = vec![vault];
    for i in 0..k {
        let (nf_pda, _) = Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifiers[i]], &PROGRAM_ID);
        accts.push(AccountMeta::new(nf_pda, false));
        accts.push(AccountMeta::new(recipients[i].pubkey(), false));
        lookup_addrs.push(nf_pda);
        lookup_addrs.push(recipients[i].pubkey());
    }
    let exec_ix = Instruction { program_id: PROGRAM_ID, accounts: accts, data: xdata };

    // create + extend an Address Lookup Table with the batch's accounts
    println!("\ncreating the address lookup table:");
    let slot = rpc.get_slot().unwrap();
    let (create_ix, alt) = alt_ix::create_lookup_table(relayer.pubkey(), relayer.pubkey(), slot);
    send("create ALT", &[create_ix], &relayer, &[&relayer]);
    // extend in chunks (each extend ix has an account limit)
    for chunk in lookup_addrs.chunks(20) {
        let ext = alt_ix::extend_lookup_table(alt, relayer.pubkey(), Some(relayer.pubkey()), chunk.to_vec());
        send("extend ALT", &[ext], &relayer, &[&relayer]);
    }
    // the ALT must warm up one slot before use
    let start = rpc.get_slot().unwrap();
    while rpc.get_slot().unwrap() < start + 2 { std::thread::sleep(std::time::Duration::from_millis(400)); }

    let alt_account = AddressLookupTableAccount { key: alt, addresses: lookup_addrs.clone() };

    println!("\nsettling the WHOLE round in ONE transaction (relayer signs, no member does):");
    let bh = rpc.get_latest_blockhash().unwrap();
    let vmsg = v0::Message::try_compile(&relayer.pubkey(), &[att_ix, exec_ix], &[alt_account], bh)
        .expect("compile v0 message with ALT");
    let vtx = VersionedTransaction::try_new(VersionedMessage::V0(vmsg), &[&relayer]).unwrap();
    match rpc.send_and_confirm_transaction(&vtx) {
        Ok(s) => {
            println!("\n  ONE TRANSACTION, {k} ACTIONS SETTLED:");
            println!("  {s}");
            let paid = recipients.iter().filter(|r| rpc.get_balance(&r.pubkey()).unwrap_or(0) >= PAYOUT).count();
            println!("\n  {paid}/{k} recipients paid the fixed denomination from the vault.");
            println!("  One relayer signed. No member key appears. The batch digest bound every");
            println!("  action, nullifier, and recipient, and every on-chain value is a hash.");
        }
        Err(e) => println!("  FAILED: {e}"),
    }
}
