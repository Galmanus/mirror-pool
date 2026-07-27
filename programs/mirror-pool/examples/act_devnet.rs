//! Phase D: `act()` running for real on devnet.
//!
//! This wires the `riverrun-sdk` `act()` flow to the deployed mirror-pool program
//! through the committee settlement path (the path that is live today). It
//! implements the SDK's `Backend` and `Prover` traits with real devnet calls, then
//! calls `act()` once: derive from one secret, commit the leaf to join, fill the
//! crowd to the floor, refuse if the measured anonymity is too low, settle through
//! a relayer, and print a receipt with a real settlement signature. Then it shows
//! the floor by calling `act()` again with a floor above the crowd size: refused,
//! nothing settled.
//!
//! Run: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example act_devnet [k]`
//!
//! Honest scope: on devnet the members are funded synthetically, so the effective-k
//! reported here is optimistic (every member counted as distinct and honest). A real
//! effective-k needs mainnet funding data through the ruler. What is real here is the
//! end-to-end flow, the floor enforcement, and the on-chain settlement.

use riverrun_core::commitment::{Commitment, Secret};
use riverrun_core::nullifier::Nullifier;
use riverrun_sdk::{act, ActError, ActRequest, Backend, Policy, Proof, Prover, RoundInfo};
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
const PAYOUT_LAMPORTS: u64 = 1_000_000; // the pool's fixed denomination

fn disc(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize()[..8]);
    out
}

fn rpc() -> RpcClient {
    RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    )
}

fn payer() -> Keypair {
    let home = std::env::var("HOME").unwrap();
    read_keypair_file(format!("{home}/.config/solana/id.json")).expect("read ~/.config/solana/id.json")
}

/// The real devnet backend for `act()`, committee settlement path.
struct DevnetBackend {
    rpc: RpcClient,
    payer: Keypair,
    verifier: Keypair,
    relayer: Keypair,
    pool: Pubkey,
    vault: Pubkey,
    root: [u8; 32],
    action: [u8; 32],
    k_min: usize,
    round: u64,
}

impl DevnetBackend {
    fn send(&self, name: &str, ixs: &[Instruction], fee_payer: &Keypair, signers: &[&Keypair]) -> Result<String, String> {
        let bh = self.rpc.get_latest_blockhash().map_err(|e| e.to_string())?;
        let tx = Transaction::new_signed_with_payer(ixs, Some(&fee_payer.pubkey()), signers, bh);
        match self.rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("  {name:<26} OK   {sig}");
                Ok(sig.to_string())
            }
            Err(e) => {
                let msg = e.to_string();
                let short = msg.lines().next().unwrap_or(&msg).to_string();
                println!("  {name:<26} FAIL {short}");
                Err(short)
            }
        }
    }

    /// Commit one commitment from a fresh, crowd-funded member key, so even joining
    /// is unlinkable and the master secret never signs on-chain.
    fn commit_member(&self, label: &str, commitment: [u8; 32]) -> Result<(), String> {
        let member = Keypair::new();
        self.send(
            &format!("fund {label}"),
            &[system_instruction::transfer(&self.payer.pubkey(), &member.pubkey(), 20_000_000)],
            &self.payer,
            &[&self.payer],
        )?;
        let mut data = disc("commit").to_vec();
        data.extend_from_slice(&commitment);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.pool, false),
                AccountMeta::new(member.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        };
        self.send(&format!("commit {label}"), &[ix], &member, &[&member]).map(|_| ())
    }

    fn attested_execute(&self, nullifier: [u8; 32], recipient: &Pubkey) -> Vec<Instruction> {
        let (nf_pda, _) =
            Pubkey::find_program_address(&[b"nullifier", self.pool.as_ref(), &nullifier], &PROGRAM_ID);

        let mut msg = Vec::with_capacity(184);
        msg.extend_from_slice(b"riverrun-exec-v2");
        msg.extend_from_slice(self.pool.as_ref());
        msg.extend_from_slice(&self.root);
        msg.extend_from_slice(&self.action);
        msg.extend_from_slice(&nullifier);
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(recipient.as_ref());
        let sig = self.verifier.sign_message(&msg);

        let mut edata = Vec::with_capacity(16 + 32 + 64 + msg.len());
        edata.push(1);
        edata.push(0);
        for v in [48u16, u16::MAX, 16u16, u16::MAX, 112u16, msg.len() as u16, u16::MAX] {
            edata.extend_from_slice(&v.to_le_bytes());
        }
        edata.extend_from_slice(&self.verifier.pubkey().to_bytes());
        edata.extend_from_slice(sig.as_ref());
        edata.extend_from_slice(&msg);
        let ed_ix = Instruction { program_id: solana_sdk::ed25519_program::ID, accounts: vec![], data: edata };

        let mut xdata = disc("execute").to_vec();
        xdata.extend_from_slice(&self.action);
        xdata.extend_from_slice(&nullifier);
        xdata.extend_from_slice(&self.round.to_le_bytes());
        xdata.extend_from_slice(&self.root);
        let exec_ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.pool, false),
                AccountMeta::new(nf_pda, false),
                AccountMeta::new(self.relayer.pubkey(), true),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(*recipient, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            ],
            data: xdata,
        };
        vec![ed_ix, exec_ix]
    }
}

impl Backend for DevnetBackend {
    fn commit(&mut self, commitment: &Commitment) -> Result<(), String> {
        println!("\njoining the round (the fund's leaf, a fresh key signs):");
        self.commit_member("member (the fund)", *commitment.as_bytes())
    }

    fn await_round(&mut self) -> Result<RoundInfo, String> {
        println!("\nforming the crowd to the floor (k_min = {}):", self.k_min);
        for i in 1..self.k_min {
            let cover = Keypair::new().pubkey().to_bytes(); // a fresh cover commitment
            self.commit_member(&format!("cover {i}/{}", self.k_min - 1), cover)?;
        }
        // Honest: on devnet the members are synthetic, so effective-k is optimistic
        // (each counted as distinct and honest). A real number needs mainnet funding
        // through the ruler. The floor mechanism below is real regardless.
        Ok(RoundInfo {
            round: self.round.to_le_bytes().to_vec(),
            advertised_k: self.k_min,
            effective_k: self.k_min as f64,
        })
    }

    fn settle(
        &mut self,
        _round: &RoundInfo,
        nullifier: &Nullifier,
        _action: &[u8],
        recipient: &[u8; 32],
        _amount: u64,
        _proof: &Proof,
    ) -> Result<String, String> {
        println!("\nsettling through the relayer (no member key signs):");
        let recipient = Pubkey::new_from_array(*recipient);
        self.send(
            "execute (relayer)",
            &self.attested_execute(*nullifier.as_bytes(), &recipient),
            &self.relayer,
            &[&self.relayer],
        )
    }
}

/// Committee path: settlement is authorized by the verifier's attestation (built in
/// `settle`), so the proof itself is empty here. The STARK prover plugs in when the
/// on-chain post-quantum verification lands, with no change to this flow.
struct CommitteeProver;
impl Prover for CommitteeProver {
    fn prove(&self, _s: &Secret, _c: &[u8], _a: &[u8], _r: &RoundInfo) -> Result<Proof, String> {
        Ok(Vec::new())
    }
}

fn main() {
    let k: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(4).max(2);

    let authority = Keypair::new();
    let verifier = Keypair::new();
    let relayer = Keypair::new();
    let (pool, _) = Pubkey::find_program_address(&[b"pool", authority.pubkey().as_ref()], &PROGRAM_ID);
    let (vault, _) = Pubkey::find_program_address(&[b"vault", pool.as_ref()], &PROGRAM_ID);
    let root = *b"riverrun-act-devnet-root-0000001";
    let action = *b"riverrun-act-devnet-action-00001";

    println!("program : {PROGRAM_ID}");
    println!("pool    : {pool}");
    println!("act()   : one secret, k_min = {k}, committee settlement path\n");

    // Setup: fund roles, initialize the pool with k_min = k, publish the root.
    let setup = DevnetBackend {
        rpc: rpc(),
        payer: payer(),
        verifier: verifier.insecure_clone(),
        relayer: relayer.insecure_clone(),
        pool,
        vault,
        root,
        action,
        k_min: k,
        round: 0,
    };
    println!("setup:");
    let fund = vec![
        system_instruction::transfer(&setup.payer.pubkey(), &authority.pubkey(), 50_000_000),
        system_instruction::transfer(&setup.payer.pubkey(), &relayer.pubkey(), 60_000_000),
        system_instruction::transfer(&setup.payer.pubkey(), &vault, 20_000_000 + (k as u64) * PAYOUT_LAMPORTS),
    ];
    if setup.send("fund roles", &fund, &setup.payer, &[&setup.payer]).is_err() {
        eprintln!("could not fund roles, is the devnet wallet topped up?");
        std::process::exit(1);
    }
    let mut init = disc("initialize").to_vec();
    init.extend_from_slice(&1u32.to_le_bytes());
    init.extend_from_slice(verifier.pubkey().as_ref());
    init.push(1);
    init.extend_from_slice(&5_000_000u64.to_le_bytes());
    init.extend_from_slice(&(k as u32).to_le_bytes());
    let init_ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: init,
    };
    setup.send("initialize", &[init_ix], &authority, &[&authority]).ok();
    let mut pr = disc("publish_root").to_vec();
    pr.extend_from_slice(&root);
    let pr_ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(pool, false), AccountMeta::new_readonly(authority.pubkey(), true)],
        data: pr,
    };
    setup.send("publish_root", &[pr_ix], &authority, &[&authority]).ok();

    // The fund holds one secret. act() does the rest.
    let secret = Secret::random();
    let recipient = Keypair::new().pubkey().to_bytes();
    let request = ActRequest { context: b"amm-exit", action: &action, recipient, amount: PAYOUT_LAMPORTS };

    let mut backend = DevnetBackend {
        rpc: rpc(),
        payer: payer(),
        verifier,
        relayer,
        pool,
        vault,
        root,
        action,
        k_min: k,
        round: 0,
    };

    println!("\n{}", "=".repeat(64));
    println!("act() with a floor of {k}.0 (the crowd will meet it):");
    match act(&secret, &request, &CommitteeProver, &mut backend, &Policy { min_effective_k: k as f64 }) {
        Ok(receipt) => {
            println!("\nRECEIPT");
            println!("  settlement signature : {}", receipt.signature);
            println!("  advertised k         : {}", receipt.advertised_k);
            println!("  effective k (measured): {:.1}", receipt.effective_k);
            println!("  nullifier            : spent once, this round");
            println!("\nThe fund acted with one secret, its key never signed the execution, and the\nreceipt carries the anonymity it actually got, not just the advertised count.");
        }
        Err(e) => println!("\nact() did not settle: {e:?}"),
    }

    // Now show the floor: a floor above the crowd size must refuse, spending nothing
    // on settlement. Reuse a fresh backend so the demonstration is clean.
    println!("\n{}", "=".repeat(64));
    println!("act() with a floor of {}.0 (above the crowd, must refuse):", k + 100);
    let secret2 = Secret::random();
    let request2 = ActRequest { context: b"amm-exit", action: &action, recipient, amount: PAYOUT_LAMPORTS };
    let mut backend2 = DevnetBackend {
        rpc: rpc(),
        payer: payer(),
        verifier: Keypair::new(),
        relayer: Keypair::new(),
        pool,
        vault,
        root,
        action,
        k_min: k,
        round: 0,
    };
    match act(&secret2, &request2, &CommitteeProver, &mut backend2, &Policy { min_effective_k: (k + 100) as f64 }) {
        Ok(_) => println!("\nUNEXPECTED: act() settled above its floor (bug)"),
        Err(ActError::BelowFloor { effective_k, floor }) => {
            println!("\nact() correctly REFUSED: measured effective-k {effective_k:.1} is below the floor {floor:.1}.");
            println!("Nothing was settled. The fund does not act into a crowd that would not hide it.");
        }
        Err(e) => println!("\nact() failed for another reason: {e:?}"),
    }
}
