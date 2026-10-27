//! The staged buffer protocol, measured and attacked inside LiteSVM's Solana
//! runtime, at the production crowd parameters (12 FRI queries, blowup 128,
//! 128 rows), the same ones `riverrun_m31::staged`'s native equivalence tests
//! use. Every transaction here runs under the REAL limits: an explicit
//! `set_compute_unit_limit(1_400_000)`, the 256 KB heap frame, and a serialized
//! size checked against the 1232-byte packet limit. Nothing is measured with a
//! raised CU cap.
//!
//! Needs the SBF artifact: `cargo build-sbf`, then
//! `cargo test --release --test staged -- --ignored --nocapture --test-threads 1`.

use std::sync::OnceLock;

use litesvm::LiteSVM;
use riverrun_m31::{
    compress, prove_binding_crowd, prove_binding_crowd_for, prove_membership_crowd,
    prove_membership_crowd_for, zk::Seed, PathStep, BLINDER_LEN, CONTEXT_LEN, CROWD_DEPTH,
    DIGEST_LEN, SECRET_LEN,
};
use riverrun_m31_verifier::{client, staged::*};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    rent::Rent,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::{Transaction, TransactionError},
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("r1Vrrunm31VeriFier1111111111111111111111111");
const CU_CAP: u32 = 1_400_000;
const PACKET: usize = 1232;
/// Bytes of proof per WRITE transaction: the largest that keeps a
/// one-signer WRITE under the packet limit (asserted on every send).
const CHUNK: usize = client::WRITE_CHUNK;
/// Query positions per QUERIES transaction: a CLIENT choice (the program
/// takes any list of unverified positions). Default 2, measured at ~1.21M CU
/// for the binding proof; `QUERY_BATCH=1` trades 6 more transactions for
/// roughly half the per-transaction cost. Set from measurement, never above
/// what leaves real margin under CU_CAP.
fn query_batch() -> usize {
    std::env::var("QUERY_BATCH").ok().and_then(|v| v.parse().ok()).unwrap_or(2)
}

// ---------------------------------------------------------------- fixtures

struct Proofs {
    binding: Vec<u8>,
    membership: Vec<u8>,
    /// The same statement, both proofs bound to `recipient` (item 3).
    bound_binding: Vec<u8>,
    bound_membership: Vec<u8>,
    recipient: Pubkey,
    /// action | round | C | nullifier | root, as canonical u32 limbs.
    publics: [u32; 40],
    round: u64,
}

fn proofs() -> &'static Proofs {
    static P: OnceLock<Proofs> = OnceLock::new();
    P.get_or_init(|| {
        // Small, so the pool end-to-end test can advance a real pool to it;
        // the multi-limb round encoding is pinned by `round_encoding_round_trips`.
        let round: u64 = 3;
        let round_l = round_limbs(round);
        let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
        let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 100 + i as u64);
        let round8: [u64; CONTEXT_LEN] = core::array::from_fn(|i| round_l[i] as u64);
        let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 7000 + i as u64);
        let (bp, c, leaf, nullifier) =
            prove_binding_crowd(secret, action, round8, blinder, NUM_QUERIES, LOG_BLOWUP, 7, Seed::reproducible(42));
        let path: [PathStep; CROWD_DEPTH] = core::array::from_fn(|i| PathStep {
            sibling: core::array::from_fn(|j| (i as u64 + 1) * 4000 + j as u64),
            node_on_right: i % 3 == 1,
        });
        let (mp, c2, root) = prove_membership_crowd(leaf, blinder, &path, NUM_QUERIES, LOG_BLOWUP, Seed::reproducible(43));
        assert_eq!(c, c2);
        let _ = compress;
        let mut publics = [0u32; 40];
        for (f, v) in [action, round8, c, nullifier, root].iter().enumerate() {
            for k in 0..8 {
                publics[f * 8 + k] = v[k] as u32;
            }
        }
        let _ = DIGEST_LEN;
        let recipient = Pubkey::new_from_array([0xA1; 32]);
        let r = recipient.to_bytes();
        let (bbp, c3, leaf3, n3) = prove_binding_crowd_for(
            &r, secret, action, round8, blinder, NUM_QUERIES, LOG_BLOWUP, 7, Seed::reproducible(44),
        );
        let (bmp, _, root3) =
            prove_membership_crowd_for(&r, leaf3, blinder, &path, NUM_QUERIES, LOG_BLOWUP, Seed::reproducible(45));
        assert_eq!((c3, n3, root3), (c, nullifier, root));
        Proofs {
            binding: bp.to_bytes(),
            membership: mp.to_bytes(),
            bound_binding: bbp.to_bytes(),
            bound_membership: bmp.to_bytes(),
            recipient,
            publics,
            round,
        }
    })
}

fn limb_bytes(l: &[u32]) -> Vec<u8> {
    l.iter().flat_map(|v| v.to_le_bytes()).collect()
}

// ---------------------------------------------------------------- harness

struct Env {
    svm: LiteSVM,
    authority: Keypair,
    /// (label, CU) of every verification-stage transaction sent.
    log: Vec<(String, u64)>,
    txs: usize,
    /// Diagnostic mode: the CU limit was raised via the runtime budget, so the
    /// per-tx cap assertion is off. Never used by a pass/fail test.
    diag: bool,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/riverrun_m31_verifier.so");
        svm.add_program_from_file(PROGRAM_ID, so).expect("load .so (run cargo build-sbf first)");
        let authority = Keypair::new();
        svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
        Self { svm, authority, log: Vec::new(), txs: 0, diag: false }
    }

    /// DIAGNOSTIC ONLY: the cu-trace build with a 50M CU runtime budget.
    fn diagnostic() -> Self {
        let mut budget = solana_compute_budget::compute_budget::ComputeBudget::default();
        budget.compute_unit_limit = 50_000_000;
        budget.heap_size = 256 * 1024;
        let mut svm = LiteSVM::new().with_compute_budget(budget);
        let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy-cutrace/riverrun_m31_verifier.so");
        svm.add_program_from_file(PROGRAM_ID, so).expect("load cu-trace .so");
        let authority = Keypair::new();
        svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
        Self { svm, authority, log: Vec::new(), txs: 0, diag: true }
    }

    /// Send under the real limits. `stage`: prepend the CU limit and the 256 KB
    /// heap frame. Returns the CU consumed, or the program's error code.
    fn send(&mut self, ixs: Vec<Instruction>, extra: &[&Keypair], stage: bool) -> Result<u64, (TransactionError, Vec<String>)> {
        let mut all = Vec::new();
        if stage && !self.diag {
            all.push(ComputeBudgetInstruction::set_compute_unit_limit(CU_CAP));
            all.push(ComputeBudgetInstruction::request_heap_frame(256 * 1024));
        }
        all.extend(ixs);
        self.svm.expire_blockhash();
        let msg = Message::new(&all, Some(&self.authority.pubkey()));
        let mut signers: Vec<&Keypair> = vec![&self.authority];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, msg, self.svm.latest_blockhash());
        let size = bincode::serialize(&tx).unwrap().len();
        assert!(size <= PACKET, "transaction is {size} B, over the {PACKET} B packet limit");
        self.txs += 1;
        match self.svm.send_transaction(tx) {
            Ok(meta) => {
                if self.diag {
                    print_probes(&meta.logs);
                } else {
                    assert!(meta.compute_units_consumed <= CU_CAP as u64);
                }
                Ok(meta.compute_units_consumed)
            }
            Err(e) => Err((e.err, e.meta.logs)),
        }
    }

    fn ix(&self, buffer: &Pubkey, tag: u8, data: &[u8]) -> Instruction {
        client::stage(&PROGRAM_ID, buffer, &self.authority.pubkey(), tag, data)
    }

    /// Create + INIT in one transaction. Returns the buffer keypair (its
    /// holder alone can INIT it) and its size.
    fn create(&mut self, kind: u8, slots: &[&[u8]], publics: &[u32; 40], recipient: &Pubkey) -> (Keypair, usize) {
        let buffer = Keypair::new();
        let lens: Vec<usize> = slots.iter().map(|s| s.len()).collect();
        let size = client::buffer_size(&lens);
        let lamports = self.svm.minimum_balance_for_rent_exemption(size);
        let create = system_instruction::create_account(&self.authority.pubkey(), &buffer.pubkey(), lamports, size as u64, &PROGRAM_ID);
        let init = client::init(&PROGRAM_ID, &buffer.pubkey(), &self.authority.pubkey(), kind, 7, recipient, publics, &lens);
        self.send(vec![create, init], &[&buffer], false).expect("create + init");
        (buffer, size)
    }

    fn upload(&mut self, buffer: &Pubkey, slot: u8, bytes: &[u8]) -> usize {
        let ixs = client::writes(&PROGRAM_ID, buffer, &self.authority.pubkey(), slot, bytes);
        let n = ixs.len();
        for ix in ixs {
            self.send(vec![ix], &[], false).expect("write");
        }
        n
    }

    fn stage(&mut self, buffer: &Pubkey, label: &str, tag: u8, data: &[u8]) -> Result<u64, u32> {
        let ix = self.ix(buffer, tag, data);
        match self.send(vec![ix], &[], true) {
            Ok(cu) => {
                self.log.push((label.to_string(), cu));
                Ok(cu)
            }
            Err((TransactionError::InstructionError(_, InstructionError::Custom(c)), _)) => Err(c),
            Err((e, logs)) => panic!("{label}: unexpected failure {e:?}\n{}", logs.join("\n")),
        }
    }

    /// Run every verification stage of `slot` in protocol order.
    fn verify_slot(&mut self, buffer: &Pubkey, slot: u8, name: &str) {
        self.stage(buffer, &format!("{name} TRANSCRIPT"), IX_TRANSCRIPT, &[slot]).expect("transcript");
        self.stage(buffer, &format!("{name} QUOTIENT"), IX_QUOTIENT, &[slot]).expect("quotient");
        self.stage(buffer, &format!("{name} OOD"), IX_OOD, &[slot]).expect("ood");
        let positions: Vec<u8> = (0..NUM_QUERIES as u8).collect();
        for batch in positions.chunks(query_batch()) {
            let mut d = vec![slot];
            d.extend_from_slice(batch);
            self.stage(buffer, &format!("{name} QUERIES {batch:?}"), IX_QUERIES, &d).expect("queries");
        }
    }

    fn data(&self, buffer: &Pubkey) -> Vec<u8> {
        self.svm.get_account(buffer).map(|a| a.data).unwrap_or_default()
    }
}

fn print_table(title: &str, env: &Env, size: usize, writes: usize) {
    let rent = Rent::default().minimum_balance(size);
    println!("\n== {title} ==");
    println!("buffer: {size} B, rent-exempt minimum {rent} lamports ({:.4} SOL), {writes} WRITE txs of <= {CHUNK} B", rent as f64 / 1e9);
    let mut max = 0;
    for (label, cu) in &env.log {
        println!("  {label:<40} {cu:>9} CU");
        max = max.max(*cu);
    }
    println!("  verification txs: {}, max {} CU ({:.1}% of the 1.4M cap); total txs incl. create/write/seal/finalize: {}",
        env.log.len(), max, 100.0 * max as f64 / CU_CAP as f64, env.txs);
}

/// Turn the program's `[cu-trace]` probes into per-phase deltas.
fn print_probes(logs: &[String]) {
    let mut last: Option<u64> = None;
    let mut label = String::from("start");
    for l in logs {
        if let Some(rest) = l.strip_prefix("Program log: ") {
            if !rest.starts_with("Program consumption") {
                label = rest.to_string();
            }
        }
        if let Some(rest) = l.split("Program consumption: ").nth(1) {
            let remaining: u64 = rest.split_whitespace().next().unwrap().parse().unwrap();
            if let Some(prev) = last {
                println!("      {:>9} CU  up to: {label}", prev - remaining);
            }
            last = Some(remaining);
        }
    }
}

/// DIAGNOSTIC ONLY, not a pass condition and NOT the real cap: every stage of
/// both proofs, one query per transaction, on the cu-trace build with the CU
/// limit raised to 50M, printing per-phase CU. This is how stage costs are
/// attributed; the real-cap tests above are what claim anything.
#[test]
#[ignore = "diagnostic: cargo build-sbf --features cu-trace --sbf-out-dir target/deploy-cutrace first"]
fn diagnose_stage_costs_with_raised_cap() {
    let p = proofs();
    let mut env = Env::diagnostic();
    let (bufk, _) = env.create(KIND_CROWD, &[&p.binding, &p.membership], &p.publics, &Pubkey::new_unique());
    let buf = bufk.pubkey();
    env.upload(&buf, 0, &p.binding);
    env.upload(&buf, 1, &p.membership);
    for (label, tag, data) in [
        ("SEAL", IX_SEAL, vec![]),
        ("binding TRANSCRIPT", IX_TRANSCRIPT, vec![0]),
        ("binding QUOTIENT", IX_QUOTIENT, vec![0]),
        ("binding OOD", IX_OOD, vec![0]),
        ("binding QUERIES [0]", IX_QUERIES, vec![0, 0]),
        ("binding QUERIES [1, 2]", IX_QUERIES, vec![0, 1, 2]),
        ("membership TRANSCRIPT", IX_TRANSCRIPT, vec![1]),
        ("membership QUOTIENT", IX_QUOTIENT, vec![1]),
        ("membership OOD", IX_OOD, vec![1]),
        ("membership QUERIES [0]", IX_QUERIES, vec![1, 0]),
        ("membership QUERIES [1, 2]", IX_QUERIES, vec![1, 1, 2]),
    ] {
        println!("  {label}:");
        let cu = env.stage(&buf, label, tag, &data).unwrap_or_else(|c| panic!("{label}: error {c}"));
        println!("    total {cu} CU");
    }
}

// ---------------------------------------------------------------- happy paths

/// The headline: the composed crowd statement (binding + membership over one
/// C) verified on-chain across transactions at production parameters, and the
/// finalized buffer carrying exactly the bytes `programs/mirror-pool` compares.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn crowd_composition_verifies_staged_at_production_parameters() {
    let p = proofs();
    let mut env = Env::new();
    let recipient = Pubkey::new_unique();
    let (bufk, size) = env.create(KIND_CROWD, &[&p.binding, &p.membership], &p.publics, &recipient);
    let buf = bufk.pubkey();
    let writes = env.upload(&buf, 0, &p.binding) + env.upload(&buf, 1, &p.membership);
    env.stage(&buf, "SEAL (hash + index both slots)", IX_SEAL, &[]).expect("seal");
    env.verify_slot(&buf, 0, "binding");
    env.verify_slot(&buf, 1, "membership");
    let d = env.data(&buf);
    assert_eq!(d[B_FINALIZED], 0, "not finalized before FINALIZE");
    env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]).expect("finalize");
    print_table("crowd composition (binding slot 0 + membership slot 1, one C)", &env, size, writes);

    let d = env.data(&buf);
    // Verified, but an UNBOUND composition never authorizes a payout.
    assert_eq!(d[B_FINALIZED], FINAL_VERIFIED_ONLY);
    assert_eq!(&d[B_ACTION..B_ACTION + 32], &limb_bytes(&p.publics[0..8])[..]);
    assert_eq!(&d[B_NULLIFIER..B_NULLIFIER + 32], &limb_bytes(&p.publics[24..32])[..]);
    assert_eq!(&d[B_ROOT..B_ROOT + 32], &limb_bytes(&p.publics[32..40])[..]);
    assert_eq!(&d[B_ROUND..B_ROUND + 16], &(p.round as u128).to_le_bytes()[..]);
    assert_eq!(&d[B_RECIPIENT..B_RECIPIENT + 32], recipient.as_ref());
    assert_eq!(&d[B_C..B_C + 32], &limb_bytes(&p.publics[16..24])[..]);
    assert_eq!(&d[B_VK..B_VK + 32], &vk_tag(KIND_CROWD)[..]);
    // A finalized buffer takes no further stages.
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), Err(StagedError::AlreadyFinalized as u32));
    assert_eq!(env.stage(&buf, "x", IX_TRANSCRIPT, &[0]), Err(StagedError::AlreadyFinalized as u32));
}

#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn binding_alone_verifies_staged() {
    let p = proofs();
    let mut env = Env::new();
    let (bufk, size) = env.create(KIND_BINDING, &[&p.binding], &p.publics, &Pubkey::new_unique());
    let buf = bufk.pubkey();
    let writes = env.upload(&buf, 0, &p.binding);
    // Driven by the client module's plan, exactly as a devnet script would.
    let auth = env.authority.pubkey();
    for (label, ix) in client::verification_plan(&PROGRAM_ID, &buf, &auth, KIND_BINDING, query_batch()) {
        let r = env.send(vec![ix], &[], true).unwrap_or_else(|(e, logs)| panic!("{label}: {e:?}\n{}", logs.join("\n")));
        env.log.push((format!("binding {label}"), r));
    }
    print_table("crowd binding alone", &env, size, writes);
    assert_eq!(env.data(&buf)[B_FINALIZED], FINAL_VERIFIED_ONLY);
}

#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn membership_alone_verifies_staged() {
    let p = proofs();
    let mut env = Env::new();
    let (bufk, size) = env.create(KIND_MEMBERSHIP, &[&p.membership], &p.publics, &Pubkey::new_unique());
    let buf = bufk.pubkey();
    let writes = env.upload(&buf, 0, &p.membership);
    env.stage(&buf, "SEAL", IX_SEAL, &[]).expect("seal");
    env.verify_slot(&buf, 0, "membership");
    env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]).expect("finalize");
    print_table("crowd membership alone", &env, size, writes);
    assert_eq!(env.data(&buf)[B_FINALIZED], FINAL_VERIFIED_ONLY);
}

// ---------------------------------------------------------------- attacks

fn err(e: StagedError) -> Result<u64, u32> {
    Err(e as u32)
}

/// Protocol order, replay, skip, write-after-seal, re-init, wrong signer: one
/// honest binding buffer driven through every misuse, then completed.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn the_state_machine_refuses_misuse() {
    let p = proofs();
    let mut env = Env::new();
    let (bufk, _) = env.create(KIND_BINDING, &[&p.binding], &p.publics, &Pubkey::new_unique());
    let buf = bufk.pubkey();
    env.upload(&buf, 0, &p.binding);

    // Before SEAL: no stage runs.
    assert_eq!(env.stage(&buf, "x", IX_TRANSCRIPT, &[0]), err(StagedError::NotSealed));
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), err(StagedError::NotSealed));
    env.stage(&buf, "SEAL", IX_SEAL, &[]).unwrap();

    // After SEAL: no writes, no second seal, no re-init.
    let ix = env.ix(&buf, IX_WRITE, &[0, 0, 0, 0, 0, 0xAA]);
    let r = env.send(vec![ix], &[], false);
    assert!(matches!(r, Err((TransactionError::InstructionError(_, InstructionError::Custom(c)), _)) if c == StagedError::Sealed as u32));
    assert_eq!(env.stage(&buf, "x", IX_SEAL, &[]), err(StagedError::Sealed));

    // Out of order: QUOTIENT / OOD / QUERIES / FINALIZE before TRANSCRIPT.
    assert_eq!(env.stage(&buf, "x", IX_QUOTIENT, &[0]), err(StagedError::TranscriptMissing));
    assert_eq!(env.stage(&buf, "x", IX_OOD, &[0]), err(StagedError::TranscriptMissing));
    assert_eq!(env.stage(&buf, "x", IX_QUERIES, &[0, 0]), err(StagedError::TranscriptMissing));
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), err(StagedError::Incomplete));
    // A slot the kind does not have.
    assert_eq!(env.stage(&buf, "x", IX_TRANSCRIPT, &[1]), err(StagedError::BadSlot));

    env.stage(&buf, "TRANSCRIPT", IX_TRANSCRIPT, &[0]).unwrap();
    // The transcript is derived once; it cannot be re-derived or replaced.
    assert_eq!(env.stage(&buf, "x", IX_TRANSCRIPT, &[0]), err(StagedError::TranscriptAlreadyDone));

    // Queries: out of range, duplicate inside one batch, replay of a done one.
    assert_eq!(env.stage(&buf, "x", IX_QUERIES, &[0, NUM_QUERIES as u8]), err(StagedError::OutOfBounds));
    assert_eq!(env.stage(&buf, "x", IX_QUERIES, &[0, 3, 3]), err(StagedError::QueryAlreadyVerified));
    env.stage(&buf, "Q 0,1", IX_QUERIES, &[0, 0, 1]).unwrap();
    assert_eq!(env.stage(&buf, "x", IX_QUERIES, &[0, 1]), err(StagedError::QueryAlreadyVerified));
    assert_eq!(env.stage(&buf, "x", IX_QUERIES, &[0, 2, 0]), err(StagedError::QueryAlreadyVerified));

    // Everything but query 11 and the OOD check: FINALIZE must refuse.
    for q in (2..11u8).step_by(query_batch()) {
        let batch: Vec<u8> = (q..(q + query_batch() as u8).min(11)).collect();
        let mut d = vec![0u8];
        d.extend_from_slice(&batch);
        env.stage(&buf, "Q", IX_QUERIES, &d).unwrap();
    }
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), err(StagedError::Incomplete));
    env.stage(&buf, "Q 11", IX_QUERIES, &[0, 11]).unwrap();
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), err(StagedError::Incomplete), "OOD still missing");
    assert_eq!(env.stage(&buf, "x", IX_OOD, &[0]), err(StagedError::QuotientMissing));
    env.stage(&buf, "QUOTIENT", IX_QUOTIENT, &[0]).unwrap();
    assert_eq!(env.stage(&buf, "x", IX_QUOTIENT, &[0]), err(StagedError::QuotientAlreadyDone));
    assert_eq!(env.stage(&buf, "x", IX_FINALIZE, &[]), err(StagedError::Incomplete), "OOD still missing");
    env.stage(&buf, "OOD", IX_OOD, &[0]).unwrap();
    assert_eq!(env.stage(&buf, "x", IX_OOD, &[0]), err(StagedError::OodAlreadyDone));

    // A different signer cannot drive someone else's buffer.
    let mallory = Keypair::new();
    env.svm.airdrop(&mallory.pubkey(), 1_000_000_000).unwrap();
    let mut ix = env.ix(&buf, IX_FINALIZE, &[]);
    ix.accounts[1] = AccountMeta::new_readonly(mallory.pubkey(), true);
    env.svm.expire_blockhash();
    let tx = Transaction::new(&[&mallory], Message::new(&[ix], Some(&mallory.pubkey())), env.svm.latest_blockhash());
    let r = env.svm.send_transaction(tx);
    assert!(matches!(r, Err(ref e) if e.err == TransactionError::InstructionError(0, InstructionError::Custom(StagedError::WrongAuthority as u32))));

    env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]).unwrap();
    assert_eq!(env.data(&buf)[B_FINALIZED], FINAL_VERIFIED_ONLY);

    // Re-INIT of a live buffer is refused (it would reset the state machine).
    let mut data = vec![KIND_BINDING];
    data.extend_from_slice(&[0u8; 8 + 32]);
    data.extend_from_slice(&limb_bytes(&p.publics));
    data.extend_from_slice(&(p.binding.len() as u32).to_le_bytes());
    let mut init = env.ix(&buf, IX_INIT, &data);
    init.accounts[0].is_signer = true;
    let r = env.send(vec![init], &[&bufk], false);
    assert!(
        matches!(r, Err((TransactionError::InstructionError(0, InstructionError::Custom(c)), _)) if c == StagedError::AlreadyInitialized as u32),
        "re-INIT: {r:?}"
    );
    assert_eq!(env.data(&buf)[B_FINALIZED], FINAL_VERIFIED_ONLY, "a refused re-INIT leaves the finalized state intact");
}

/// One tampered proof per case, each uploaded into its own buffer: the staged
/// path must refuse at SOME stage and the buffer must never finalize.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn tampered_proofs_never_finalize() {
    let p = proofs();
    let idx = riverrun_m31::staged::index_proof(&p.binding).unwrap();
    let n = idx.num_query_proofs();
    let cases: Vec<(&str, usize)> = vec![
        ("trace commitment byte", 8 + 5),
        ("first opened trace value", (8 + 32) * 2 + 1 + 8 + 32 + 8 + 2),
        ("query 5 input opening", idx.bounds[5] + 8 + 8 + 8 + 1),
        ("query 11 last Merkle sibling byte", idx.bounds[n] - 1),
        ("FRI final poly", idx.bounds[n] + 2),
    ];
    for (label, off) in cases {
        let mut bytes = p.binding.clone();
        bytes[off] ^= 0x01;
        let outcome = drive_to_finalize(&bytes, &p.publics);
        println!("  {label:<36} refused at: {outcome}");
        assert_ne!(outcome, "FINALIZED", "{label}");
    }
    // A tampered PUBLIC input (the claimed nullifier), honest proof bytes.
    let mut publics = p.publics;
    publics[24] ^= 1;
    let outcome = drive_to_finalize(&p.binding, &publics);
    println!("  {:<36} refused at: {outcome}", "claimed nullifier limb");
    assert_ne!(outcome, "FINALIZED");
    // Control: the honest proof through the same driver does finalize.
    assert_eq!(drive_to_finalize(&p.binding, &p.publics), "FINALIZED");
}

/// Upload, seal, and run every stage until one refuses; report which.
fn drive_to_finalize(bytes: &[u8], publics: &[u32; 40]) -> String {
    let mut env = Env::new();
    let (bufk, _) = env.create(KIND_BINDING, &[bytes], publics, &Pubkey::new_unique());
    let buf = bufk.pubkey();
    env.upload(&buf, 0, bytes);
    if let Err(c) = env.stage(&buf, "SEAL", IX_SEAL, &[]) {
        return format!("SEAL (error {c})");
    }
    if let Err(c) = env.stage(&buf, "TRANSCRIPT", IX_TRANSCRIPT, &[0]) {
        return format!("TRANSCRIPT (error {c})");
    }
    let mut refused = Vec::new();
    if let Err(c) = env.stage(&buf, "QUOTIENT", IX_QUOTIENT, &[0]) {
        refused.push(format!("QUOTIENT (error {c})"));
    }
    if let Err(c) = env.stage(&buf, "OOD", IX_OOD, &[0]) {
        refused.push(format!("OOD (error {c})"));
    }
    // One query per transaction so the refusing query is identified.
    for q in 0..NUM_QUERIES as u8 {
        if let Err(c) = env.stage(&buf, "Q", IX_QUERIES, &[0, q]) {
            refused.push(format!("QUERY {q} (error {c})"));
        }
    }
    match env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]) {
        Ok(_) => {
            assert!(refused.is_empty());
            "FINALIZED".to_string()
        }
        Err(c) => {
            assert_eq!(c, StagedError::Incomplete as u32);
            assert_eq!(env.data(&buf)[B_FINALIZED], 0);
            refused.join(", ")
        }
    }
}

/// INIT refuses non-canonical public limbs (the replayable-nullifier hole) and
/// a round that does not encode a u64 for the pool.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn init_refuses_non_canonical_publics_and_non_u64_rounds() {
    let p = proofs();
    let mut env = Env::new();
    for (label, publics, want) in [
        ("nullifier limb = p", { let mut x = p.publics; x[24] = (1 << 31) - 1; x }, StagedError::NonCanonicalPublic),
        ("round limb 4 set", { let mut x = p.publics; x[12] = 1; x }, StagedError::RoundNotU64),
        ("round limb 0 >= 2^16", { let mut x = p.publics; x[8] = 0x1_0000; x }, StagedError::RoundNotU64),
    ] {
        let buffer = Keypair::new();
        let size = B_PROOFS + p.binding.len();
        let lamports = env.svm.minimum_balance_for_rent_exemption(size);
        let create = system_instruction::create_account(&env.authority.pubkey(), &buffer.pubkey(), lamports, size as u64, &PROGRAM_ID);
        let mut data = vec![KIND_BINDING];
        data.extend_from_slice(&7u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&limb_bytes(&publics));
        data.extend_from_slice(&(p.binding.len() as u32).to_le_bytes());
        let mut init = env.ix(&buffer.pubkey(), IX_INIT, &data);
        init.accounts[0].is_signer = true;
        let r = env.send(vec![create, init], &[&buffer], false);
        assert!(
            matches!(r, Err((TransactionError::InstructionError(1, InstructionError::Custom(c)), _)) if c == want as u32),
            "{label}: {r:?}"
        );
    }
}

#[test]
fn round_encoding_round_trips() {
    for r in [0u64, 1, (1 << 31) - 2, 1 << 31, 0x0000_0001_2345_6789, u64::MAX >> 1, u64::MAX] {
        assert_eq!(round_u64(&round_limbs(r)), Some(r), "{r}");
    }
    assert_eq!(round_u64(&[0x1_0000, 0, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(round_u64(&[0, 0, 0, 0, 1, 0, 0, 0]), None);
    assert_eq!(round_u64(&[0, 0, 0, 0, 0, 0, 0, 1]), None);
}

// ---------------------------------------------------------------- item 3

/// The composed statement with both proofs bound to the recipient, in a
/// `KIND_CROWD | KIND_BOUND` buffer declaring that recipient: finalizes, and
/// its `B_RECIPIENT` is now a verified public input.
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn recipient_bound_crowd_verifies_staged_at_production_parameters() {
    let p = proofs();
    let mut env = Env::new();
    let kind = KIND_CROWD | KIND_BOUND;
    let (bufk, size) = env.create(kind, &[&p.bound_binding, &p.bound_membership], &p.publics, &p.recipient);
    let buf = bufk.pubkey();
    let writes = env.upload(&buf, 0, &p.bound_binding) + env.upload(&buf, 1, &p.bound_membership);
    env.stage(&buf, "SEAL (hash + index both slots)", IX_SEAL, &[]).expect("seal");
    env.verify_slot(&buf, 0, "bound binding");
    env.verify_slot(&buf, 1, "bound membership");
    env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]).expect("finalize");
    print_table("recipient-bound crowd composition", &env, size, writes);
    let d = env.data(&buf);
    assert_eq!(d[B_FINALIZED], FINAL_SETTLEABLE);
    assert_eq!(&d[B_RECIPIENT..B_RECIPIENT + 32], p.recipient.as_ref());
    assert_eq!(&d[B_VK..B_VK + 32], &vk_tag(kind)[..]);
}

/// The race item 3 closes. A watcher copies the uploaded (public) proof bytes
/// into a buffer of their own that declares THEIR recipient. Bound kind: the
/// transcript no longer matches and the buffer never finalizes. Plain kind:
/// the bound proof is not a valid unbound proof either. Control: the same
/// copy declaring the honest recipient does finalize (the binding is to the
/// recipient, not to the uploader).
#[test]
#[ignore = "needs target/deploy/riverrun_m31_verifier.so: cargo build-sbf first"]
fn a_copied_bound_proof_cannot_be_redirected() {
    let p = proofs();
    let mallory = Pubkey::new_from_array([0x3A; 32]);
    for (label, kind, recipient, want_final) in [
        ("bound kind, attacker recipient", KIND_CROWD | KIND_BOUND, mallory, false),
        ("plain kind, attacker recipient", KIND_CROWD, mallory, false),
        ("bound kind, honest recipient (control)", KIND_CROWD | KIND_BOUND, p.recipient, true),
    ] {
        let mut env = Env::new();
        let (bufk, _) = env.create(kind, &[&p.bound_binding, &p.bound_membership], &p.publics, &recipient);
        let buf = bufk.pubkey();
        env.upload(&buf, 0, &p.bound_binding);
        env.upload(&buf, 1, &p.bound_membership);
        env.stage(&buf, "SEAL", IX_SEAL, &[]).expect("seal");
        let mut refused = Vec::new();
        for slot in 0..2u8 {
            match env.stage(&buf, "T", IX_TRANSCRIPT, &[slot]) {
                Err(c) => refused.push(format!("slot {slot} TRANSCRIPT (error {c})")),
                Ok(_) => {
                    if let Err(c) = env.stage(&buf, "Qt", IX_QUOTIENT, &[slot]) {
                        refused.push(format!("slot {slot} QUOTIENT (error {c})"));
                    }
                    if let Err(c) = env.stage(&buf, "O", IX_OOD, &[slot]) {
                        refused.push(format!("slot {slot} OOD (error {c})"));
                    }
                    for q in (0..NUM_QUERIES as u8).collect::<Vec<_>>().chunks(query_batch()) {
                        let mut d = vec![slot];
                        d.extend_from_slice(q);
                        if let Err(c) = env.stage(&buf, "Q", IX_QUERIES, &d) {
                            refused.push(format!("slot {slot} QUERIES {q:?} (error {c})"));
                        }
                    }
                }
            }
        }
        let fin = env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]);
        println!("  {label:<42} -> {}", if fin.is_ok() { "FINALIZED".to_string() } else { refused.join(", ") });
        assert_eq!(fin.is_ok(), want_final, "{label}");
        assert_eq!(env.data(&buf)[B_FINALIZED], if want_final { FINAL_SETTLEABLE } else { 0 }, "{label}");
    }
}

// ---------------------------------------------------------------- the pool

const POOL_ID: Pubkey = solana_sdk::pubkey!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");
/// `programs/mirror-pool`'s `PAYOUT_LAMPORTS`.
const POOL_PAYOUT: u64 = 1_000_000;

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = solana_sdk::hash::hashv(&[format!("global:{name}").as_bytes()]);
    h.to_bytes()[..8].try_into().unwrap()
}

/// The end of the line: the recipient-bound crowd buffer, verified by this
/// program across transactions under the real cap, is consumed by the REAL
/// `programs/mirror-pool` (its own SBF build, unmodified) through
/// `execute_verified`, which pays the recipient. Then the same nullifier
/// cannot settle twice, and a buffer that was not finalized does not settle.
///
/// Needs both artifacts: this crate's `cargo build-sbf`, and
/// `programs/mirror-pool/target/deploy/riverrun_program.so` (or the path in
/// `MIRROR_POOL_SO`).
#[test]
#[ignore = "needs both .so artifacts (this program and programs/mirror-pool)"]
fn a_finalized_buffer_settles_in_the_real_pool() {
    let p = proofs();
    let mut env = Env::new();
    let pool_so = std::env::var("MIRROR_POOL_SO").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../mirror-pool/target/deploy/riverrun_program.so").to_string()
    });
    env.svm.add_program_from_file(POOL_ID, &pool_so).expect("load mirror-pool .so");

    let auth = env.authority.pubkey();
    let pool = Pubkey::find_program_address(&[b"pool", auth.as_ref()], &POOL_ID).0;
    let vault = Pubkey::find_program_address(&[b"vault", pool.as_ref()], &POOL_ID).0;
    let pool_ix = |name: &str, args: &[u8], extra: Vec<AccountMeta>| {
        let mut data = anchor_disc(name).to_vec();
        data.extend_from_slice(args);
        let mut accounts = vec![AccountMeta::new(pool, false), AccountMeta::new(auth, true)];
        accounts.extend(extra);
        Instruction { program_id: POOL_ID, accounts, data }
    };
    let sys = AccountMeta::new_readonly(solana_sdk::system_program::ID, false);

    // The pool, set up the way its own tests do, pointed at THIS verifier.
    let root = limb_bytes(&p.publics[32..40]);
    let mut init = 1u32.to_le_bytes().to_vec();
    init.extend_from_slice(Keypair::new().pubkey().as_ref()); // a committee is required by initialize; unused here
    init.push(1);
    init.extend_from_slice(&0u64.to_le_bytes()); // entry fee
    init.extend_from_slice(&2u32.to_le_bytes()); // k_min
    env.send(vec![pool_ix("initialize", &init, vec![sys.clone()])], &[], false).expect("initialize");
    env.send(vec![pool_ix("publish_root", &root, vec![])], &[], false).expect("publish_root");
    for i in 0..2u8 {
        env.send(vec![pool_ix("commit", &[i + 1; 32], vec![sys.clone()])], &[], false).expect("commit");
    }
    env.send(vec![pool_ix("set_stark_verifier", PROGRAM_ID.as_ref(), vec![])], &[], false).expect("set_stark_verifier");
    for _ in 0..p.round {
        env.send(vec![pool_ix("advance_round", &[], vec![])], &[], false).expect("advance_round");
    }
    env.svm.airdrop(&vault, 1_000_000_000).unwrap();

    // The verified buffer.
    let kind = KIND_CROWD | KIND_BOUND;
    let (bufk, _) = env.create(kind, &[&p.bound_binding, &p.bound_membership], &p.publics, &p.recipient);
    let buf = bufk.pubkey();
    env.upload(&buf, 0, &p.bound_binding);
    env.upload(&buf, 1, &p.bound_membership);
    env.stage(&buf, "SEAL", IX_SEAL, &[]).expect("seal");
    env.verify_slot(&buf, 0, "bound binding");
    env.verify_slot(&buf, 1, "bound membership");

    // One more buffer for the same statement, stopped before FINALIZE.
    let (unfk, _) = env.create(kind, &[&p.bound_binding, &p.bound_membership], &p.publics, &p.recipient);
    let unfinalized = unfk.pubkey();
    env.upload(&unfinalized, 0, &p.bound_binding);
    env.upload(&unfinalized, 1, &p.bound_membership);
    env.stage(&unfinalized, "SEAL", IX_SEAL, &[]).expect("seal");

    let action = limb_bytes(&p.publics[0..8]);
    let nullifier = limb_bytes(&p.publics[24..32]);
    let relayer = Keypair::new();
    env.svm.airdrop(&relayer.pubkey(), 10_000_000_000).unwrap();
    let execute = |buffer: &Pubkey| {
        let nf_pda = Pubkey::find_program_address(&[b"nullifier", pool.as_ref(), &nullifier], &POOL_ID).0;
        let mut data = anchor_disc("execute_verified").to_vec();
        data.extend_from_slice(&action);
        data.extend_from_slice(&nullifier);
        data.extend_from_slice(&p.round.to_le_bytes());
        data.extend_from_slice(&root);
        Instruction {
            program_id: POOL_ID,
            accounts: vec![
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new(nf_pda, false),
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new(vault, false),
                AccountMeta::new(p.recipient, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(*buffer, false),
            ],
            data,
        }
    };
    let send_as_relayer = |env: &mut Env, ix: Instruction| {
        env.svm.expire_blockhash();
        let tx = Transaction::new(&[&relayer], Message::new(&[ix], Some(&relayer.pubkey())), env.svm.latest_blockhash());
        env.svm.send_transaction(tx).map(|m| m.compute_units_consumed).map_err(|e| format!("{:?} | {}", e.err, e.meta.logs.join(" | ")))
    };

    let err = send_as_relayer(&mut env, execute(&unfinalized)).expect_err("an unfinalized buffer must not settle");
    assert!(err.contains("ProofNotFinalized"), "{err}");

    // A fully verified but UNBOUND composition of the same statement: the
    // verifier marks it verified-only, and the pool refuses it.
    let (ubk, _) = env.create(KIND_CROWD, &[&p.binding, &p.membership], &p.publics, &p.recipient);
    let unbound = ubk.pubkey();
    env.upload(&unbound, 0, &p.binding);
    env.upload(&unbound, 1, &p.membership);
    env.stage(&unbound, "SEAL", IX_SEAL, &[]).expect("seal");
    env.verify_slot(&unbound, 0, "unbound binding");
    env.verify_slot(&unbound, 1, "unbound membership");
    env.stage(&unbound, "FINALIZE", IX_FINALIZE, &[]).expect("finalize");
    assert_eq!(env.data(&unbound)[B_FINALIZED], FINAL_VERIFIED_ONLY);
    let err = send_as_relayer(&mut env, execute(&unbound)).expect_err("an unbound composition must not settle");
    assert!(err.contains("ProofNotFinalized"), "{err}");

    // Not finalized yet: the real buffer does not settle either.
    let err = send_as_relayer(&mut env, execute(&buf)).expect_err("not finalized yet");
    assert!(err.contains("ProofNotFinalized"), "{err}");
    env.stage(&buf, "FINALIZE", IX_FINALIZE, &[]).expect("finalize");

    let before = env.svm.get_account(&p.recipient).map(|a| a.lamports).unwrap_or(0);
    let cu = send_as_relayer(&mut env, execute(&buf)).expect("a verified buffer must settle in the pool");
    let after = env.svm.get_account(&p.recipient).unwrap().lamports;
    assert_eq!(after - before, POOL_PAYOUT);
    println!("execute_verified settled from the on-chain-verified buffer: {cu} CU, recipient +{} lamports", after - before);

    // The same proof, the same nullifier: the pool's anti-replay refuses.
    let err = send_as_relayer(&mut env, execute(&buf)).expect_err("a spent nullifier must not settle twice");
    println!("replay refused: {}", err.split(" | ").next().unwrap());
}
