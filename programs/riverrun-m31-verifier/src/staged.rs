//! Staged on-chain verification of the crowd proofs, through a buffer account.
//!
//! A production crowd proof is ~110 KB (binding) / ~84 KB (membership) and
//! verifying either costs several million CU, so neither the proof nor its
//! verification fits one transaction. This module is the buffer protocol of
//! `docs/M31_CIRCLE_STARK.md` §2 made real: the proof is uploaded into an
//! account owned by this program in packet-sized chunks, sealed, and then
//! verified by a sequence of transactions, each under the 1.4M CU cap and the
//! 256 KB heap, that run the stages of `riverrun_m31::staged`:
//!
//! ```text
//! INIT ─▶ WRITE* ─▶ SEAL ─▶ per proof slot: TRANSCRIPT ─▶ QUOTIENT ─▶ OOD
//!                                           TRANSCRIPT ─▶ QUERIES(batch)*
//!                   ─▶ FINALIZE (every slot: transcript, quotient, OOD, all queries)
//! ```
//!
//! What makes this exactly the monolithic verifier (`verify_crowd`) and not an
//! approximation of it:
//!
//! - **Same code.** Each stage calls the same functions the monolithic verifier
//!   is composed of (see `riverrun_m31::staged` and the vendored
//!   `[staged-patch]` changes); `riverrun_m31`'s native tests pin agreement on
//!   honest proofs and on hundreds of tampered ones.
//! - **Challenges are never client-supplied.** The TRANSCRIPT stage derives
//!   every Fiat-Shamir value (alpha, zeta, PCS batch challenge, bivariate beta,
//!   FRI betas, PoW checks, all query indices) from the sealed bytes and writes
//!   them into this program-owned account; later stages only read them.
//! - **Immutable input.** After SEAL no instruction writes the proof region,
//!   the claimed public inputs were fixed at INIT, and the layout is fixed, so
//!   every stage reads the same bytes the transcript was derived from. SEAL also
//!   records keccak256 of each slot's bytes, so a client can check what it is
//!   paying CU to verify.
//! - **Exactly-once coverage.** A per-slot bitmap records verified query
//!   positions; a batch naming an already-verified position (or a duplicate, or
//!   an out-of-range one) is refused, and FINALIZE requires every bit. Stages
//!   out of order (OOD or QUERIES before TRANSCRIPT, FINALIZE early) are
//!   refused.
//! - **Composition.** A `KIND_CROWD` buffer carries both proofs (slot 0 binding,
//!   slot 1 membership) and ONE stored `C`, against which both are verified:
//!   exactly `verify_crowd`'s "both verify and publish the same C".
//!
//! Every instruction requires the buffer's authority (fixed at INIT) to sign.
//! Verification stages are deterministic, so this is griefing protection, not a
//! trust assumption.
//!
//! **The recipient, bound or not.** `B_RECIPIENT` holds the recipient the
//! authority declared at INIT. For a plain kind (`KIND_BINDING`,
//! `KIND_MEMBERSHIP`, `KIND_CROWD`) the proofs do not commit to it, so anyone
//! who sees the uploaded bytes (public transaction data) can upload the same
//! proof into a buffer of their own, declare their own recipient, and race the
//! settlement. With `KIND_BOUND` set (`KIND_CROWD | KIND_BOUND` is the one a
//! pool should accept), every stage verifies the proofs against a transcript
//! seeded with `RECIPIENT_DOMAIN ‖ B_RECIPIENT` (`riverrun_m31::zk::
//! make_zk_config_bound`): a proof made for another recipient fails the
//! TRANSCRIPT or QUERIES stage and never finalizes, so `B_RECIPIENT` of a
//! finalized bound buffer is a verified public input.
//!
//! **Only that kind authorizes a payout.** `programs/mirror-pool` checks owner,
//! `B_FINALIZED == 1` and field equality, not the kind. FINALIZE therefore
//! writes [`FINAL_SETTLEABLE`] (1) only for `KIND_CROWD | KIND_BOUND` and
//! [`FINAL_VERIFIED_ONLY`] (2) for every other kind: a single relation leaves
//! the other relation's pool fields at zero, and an unbound composition is the
//! front-runnable case above.

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, keccak, msg, program_error::ProgramError,
    pubkey::Pubkey, rent::Rent, sysvar::Sysvar,
};

use riverrun_m31::staged::{
    decode_ext, decode_header, decode_query, encode_ext, index_proof, publics_from_limbs, stage_ood,
    stage_queries, stage_quotient, stage_transcript, Params, ProofIndex, Relation, Transcript,
};

// --- Program constants: the verifier parameters are NOT client input. -------

/// FRI queries of the production crowd proofs (`prove_crowd_real`).
pub const NUM_QUERIES: usize = 12;
/// log2 of the FRI blowup of the production crowd proofs.
pub const LOG_BLOWUP: usize = 7;
/// The verifier's parameters for this buffer: the program constants, plus
/// the buffer's own recipient when its kind is `KIND_BOUND`.
fn params(d: &[u8]) -> Params {
    let recipient = (d[B_KIND] & KIND_BOUND != 0)
        .then(|| d[B_RECIPIENT..B_RECIPIENT + 32].try_into().unwrap());
    Params { num_queries: NUM_QUERIES, log_blowup: LOG_BLOWUP, recipient }
}

// --- The pool-facing prefix (docs/M31_CIRCLE_STARK.md §2; mirrors
// programs/mirror-pool's B_* constants byte for byte). ------------------------
pub const B_VK: usize = 0; //          [0, 32)   keccak of (relation kind, parameters)
pub const B_NONCE: usize = 32; //      [32, 40)  session nonce, chosen at INIT
pub const B_FINALIZED: usize = 40; //  1 = settleable, 2 = verified only (see FINAL_*)
pub const B_ROOT: usize = 41; //       [41, 73)   8 x u32 LE canonical M31 limbs
pub const B_NULLIFIER: usize = 73; //  [73, 105)  8 x u32 LE
pub const B_ROUND: usize = 105; //     [105, 121) round as u128 LE (see `round_u64`)
pub const B_ACTION: usize = 121; //    [121, 153) 8 x u32 LE
pub const B_RECIPIENT: usize = 153; // [153, 185) declared at INIT; NOT proof-bound

// --- Bookkeeping (this program only). ----------------------------------------
pub const B_VERSION: usize = 185; // 0 = uninitialized, 1 = this layout
pub const B_KIND: usize = 186;
pub const B_SEALED: usize = 187;
pub const B_AUTHORITY: usize = 188; // [188, 220)
/// Claimed public inputs as canonical u32 LE limbs, fixed at INIT:
/// action(8) | round(8) | C(8) | nullifier(8) | root(8).
pub const B_PUBLICS: usize = 220; //   [220, 380)
pub const B_C: usize = B_PUBLICS + 2 * 32; // the commitment, verified against in both slots
pub const B_SLOTS: usize = 384;
pub const SLOT_LEN: usize = 1024;
pub const MAX_SLOTS: usize = 2;
/// Proof bytes start here; slot 0 first, then slot 1.
pub const B_PROOFS: usize = B_SLOTS + MAX_SLOTS * SLOT_LEN; // 2432

// Per-slot layout, relative to the slot's base.
const S_LEN: usize = 0; //        u32 proof length
const S_FLAGS: usize = 4; //      u8: TRANSCRIPT_DONE | OOD_DONE
const S_BITMAP: usize = 8; //     u64 verified query positions
const S_HASH: usize = 16; //      [16, 48) keccak256 of the proof bytes, set at SEAL
const S_QAT: usize = 48; //       u32 ProofIndex::queries_at
const S_END: usize = 52; //       u32 ProofIndex::end
const S_BOUNDS: usize = 56; //    (NUM_QUERIES + 1) x u32
const S_QUOTIENT: usize = S_BOUNDS + 4 * (NUM_QUERIES + 1); // [16] quotient(zeta), set by QUOTIENT
const S_TLEN: usize = S_QUOTIENT + 16; // u16 transcript length
const S_TRANSCRIPT: usize = S_TLEN + 2;
const S_TRANSCRIPT_MAX: usize = SLOT_LEN - S_TRANSCRIPT;

/// `B_FINALIZED` of a recipient-bound composition: every slot verified, and the
/// buffer authorizes a settlement. The ONLY value `programs/mirror-pool` honors.
pub const FINAL_SETTLEABLE: u8 = 1;
/// `B_FINALIZED` of any other kind: every slot verified, but the buffer must not
/// authorize a payout. A single relation leaves pool-facing fields at zero (a
/// membership-only buffer would otherwise settle with nullifier = action = 0
/// in round 0, since the pool checks fields, not the kind), and an unbound
/// composition can be copied by a watcher under another recipient.
pub const FINAL_VERIFIED_ONLY: u8 = 2;

const FLAG_TRANSCRIPT: u8 = 1;
const FLAG_OOD: u8 = 2;
const FLAG_QUOTIENT: u8 = 4;
const ALL_QUERIES: u64 = (1u64 << NUM_QUERIES) - 1;

pub const KIND_BINDING: u8 = 1;
pub const KIND_MEMBERSHIP: u8 = 2;
/// Binding (slot 0) + membership (slot 1) composed over one `C`.
pub const KIND_CROWD: u8 = 3;
/// Flag on any kind: the proofs are recipient-bound to `B_RECIPIENT`.
pub const KIND_BOUND: u8 = 0x80;

pub const IX_INIT: u8 = 10;
pub const IX_WRITE: u8 = 11;
pub const IX_SEAL: u8 = 12;
pub const IX_TRANSCRIPT: u8 = 13;
pub const IX_OOD: u8 = 14;
pub const IX_QUERIES: u8 = 15;
pub const IX_FINALIZE: u8 = 16;
pub const IX_CLOSE: u8 = 17;
pub const IX_QUOTIENT: u8 = 18;

/// Distinct errors so a test (or an operator reading logs) sees which gate
/// refused, not just "custom error".
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedError {
    NotInitialized = 100,
    AlreadyInitialized = 101,
    WrongAuthority = 102,
    Sealed = 103,
    NotSealed = 104,
    OutOfBounds = 105,
    BadKind = 106,
    NonCanonicalPublic = 107,
    RoundNotU64 = 108,
    NotRentExempt = 109,
    Unindexable = 110,
    WrongQueryCount = 111,
    TranscriptAlreadyDone = 112,
    TranscriptMissing = 113,
    TranscriptRejected = 114,
    OodAlreadyDone = 115,
    OodRejected = 116,
    QueryAlreadyVerified = 117,
    QueryRejected = 118,
    Incomplete = 119,
    AlreadyFinalized = 120,
    BadSlot = 121,
    Malformed = 122,
    QuotientAlreadyDone = 123,
    QuotientMissing = 124,
}

impl From<StagedError> for ProgramError {
    fn from(e: StagedError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

fn kind_slots(kind: u8) -> Option<&'static [Relation]> {
    match kind & !KIND_BOUND {
        KIND_BINDING => Some(&[Relation::Binding]),
        KIND_MEMBERSHIP => Some(&[Relation::Membership]),
        KIND_CROWD => Some(&[Relation::Binding, Relation::Membership]),
        _ => None,
    }
}

/// The verifier-key tag at `B_VK`: which relation(s), at which parameters.
pub fn vk_tag(kind: u8) -> [u8; 32] {
    keccak::hashv(&[
        b"riverrun-m31-verifier/crowd-staged/v1",
        &[kind],
        &(NUM_QUERIES as u32).to_le_bytes(),
        &(LOG_BLOWUP as u32).to_le_bytes(),
    ])
    .to_bytes()
}

/// The pool reads `round` as a u64 (low half of a u128 LE). The proof's round
/// is eight M31 limbs; the encoding is four 16-bit limbs,
/// `round = l0 + l1 * 2^16 + l2 * 2^32 + l3 * 2^48` with every `l_i < 2^16` and
/// `l4..l7 = 0`. 16-bit limbs make it total over u64 (31-bit limbs would leave
/// any round whose low 31 bits are all ones unrepresentable: that limb would
/// equal p, which is not canonical). INIT refuses any other round for a
/// relation that carries one, so a finalized buffer always has a faithful
/// `B_ROUND`.
pub fn round_u64(limbs: &[u32]) -> Option<u64> {
    if limbs.len() != 8 || limbs[4..].iter().any(|&l| l != 0) || limbs[..4].iter().any(|&l| l > 0xFFFF) {
        return None;
    }
    Some((0..4).fold(0u64, |acc, i| acc | (limbs[i] as u64) << (16 * i)))
}

/// The inverse of [`round_u64`].
pub fn round_limbs(round: u64) -> [u32; 8] {
    core::array::from_fn(|i| if i < 4 { ((round >> (16 * i)) & 0xFFFF) as u32 } else { 0 })
}

fn rd_u32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn wr_u32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn slot_base(i: usize) -> usize {
    B_SLOTS + i * SLOT_LEN
}

/// Absolute byte range of slot `i`'s proof.
fn slot_range(d: &[u8], i: usize) -> core::ops::Range<usize> {
    let mut start = B_PROOFS;
    for j in 0..i {
        start += rd_u32(d, slot_base(j) + S_LEN) as usize;
    }
    start..start + rd_u32(d, slot_base(i) + S_LEN) as usize
}

fn publics_limbs(d: &[u8], rel: Relation) -> [u32; 32] {
    let mut out = [0u32; 32];
    let take = |field: usize, out: &mut [u32]| {
        for (k, o) in out.iter_mut().enumerate() {
            *o = rd_u32(d, B_PUBLICS + field * 32 + 4 * k);
        }
    };
    match rel {
        // action | round | C | nullifier
        Relation::Binding => {
            for f in 0..4 {
                take(f, &mut out[f * 8..f * 8 + 8]);
            }
        }
        // C | root
        Relation::Membership => {
            take(2, &mut out[0..8]);
            take(4, &mut out[8..16]);
        }
    }
    out
}

fn stored_index(d: &[u8], i: usize) -> ProofIndex {
    let b = slot_base(i);
    ProofIndex {
        queries_at: rd_u32(d, b + S_QAT) as usize,
        bounds: (0..=NUM_QUERIES).map(|k| rd_u32(d, b + S_BOUNDS + 4 * k) as usize).collect(),
        end: rd_u32(d, b + S_END) as usize,
    }
}

fn stored_transcript(d: &[u8], i: usize) -> Option<Transcript> {
    let b = slot_base(i);
    let len = u16::from_le_bytes([d[b + S_TLEN], d[b + S_TLEN + 1]]) as usize;
    Transcript::decode(&d[b + S_TRANSCRIPT..b + S_TRANSCRIPT + len])
}

/// The two accounts every staged instruction takes: the buffer (writable,
/// owned by this program) and its authority (signer).
fn buffer_and_authority<'a, 'b>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'b>],
) -> Result<(&'a AccountInfo<'b>, &'a AccountInfo<'b>), ProgramError> {
    let [buffer, authority, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if buffer.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !buffer.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok((buffer, authority))
}

fn check_initialized_by(d: &[u8], authority: &AccountInfo) -> ProgramResult {
    if d.len() < B_PROOFS || d[B_VERSION] != 1 {
        return Err(StagedError::NotInitialized.into());
    }
    if &d[B_AUTHORITY..B_AUTHORITY + 32] != authority.key.as_ref() {
        return Err(StagedError::WrongAuthority.into());
    }
    Ok(())
}

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], tag: u8, data: &[u8]) -> ProgramResult {
    match tag {
        IX_INIT => init(program_id, accounts, data),
        IX_WRITE => write(program_id, accounts, data),
        IX_SEAL => seal(program_id, accounts),
        IX_TRANSCRIPT => transcript(program_id, accounts, data),
        IX_OOD => ood(program_id, accounts, data),
        IX_QUERIES => queries(program_id, accounts, data),
        IX_FINALIZE => finalize(program_id, accounts),
        IX_CLOSE => close(program_id, accounts),
        IX_QUOTIENT => quotient(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// `kind u8 | nonce u64 | recipient [32] | publics 40 x u32 | lens u32 x slots`.
/// The buffer itself must sign: whoever created the account (and so holds its
/// key) decides who its authority is, so a freshly created buffer cannot be
/// claimed by a third party between creation and INIT.
fn init(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    if !buffer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (&kind, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    let slots = kind_slots(kind).ok_or(StagedError::BadKind)?;
    let need = 8 + 32 + 40 * 4 + 4 * slots.len();
    if rest.len() != need {
        return Err(ProgramError::InvalidInstructionData);
    }
    let nonce = &rest[..8];
    let recipient = &rest[8..40];
    let publics = &rest[40..200];
    let limbs: [u32; 40] = core::array::from_fn(|k| rd_u32(publics, 4 * k));
    if publics_from_limbs(&limbs).is_none() {
        return Err(StagedError::NonCanonicalPublic.into());
    }
    if slots.contains(&Relation::Binding) && round_u64(&limbs[8..16]).is_none() {
        return Err(StagedError::RoundNotU64.into());
    }
    let lens: [usize; MAX_SLOTS] = core::array::from_fn(|i| {
        if i < slots.len() { rd_u32(&rest[200..], 4 * i) as usize } else { 0 }
    });

    let mut d = buffer.try_borrow_mut_data()?;
    let total = B_PROOFS + lens.iter().sum::<usize>();
    if d.len() < total {
        return Err(StagedError::OutOfBounds.into());
    }
    if d.len() < B_PROOFS || d[..B_PROOFS].iter().any(|&b| b != 0) {
        return Err(StagedError::AlreadyInitialized.into());
    }
    if !Rent::get()?.is_exempt(buffer.lamports(), d.len()) {
        return Err(StagedError::NotRentExempt.into());
    }
    d[B_VK..B_VK + 32].copy_from_slice(&vk_tag(kind));
    d[B_NONCE..B_NONCE + 8].copy_from_slice(nonce);
    d[B_RECIPIENT..B_RECIPIENT + 32].copy_from_slice(recipient);
    d[B_VERSION] = 1;
    d[B_KIND] = kind;
    d[B_AUTHORITY..B_AUTHORITY + 32].copy_from_slice(authority.key.as_ref());
    d[B_PUBLICS..B_PUBLICS + 160].copy_from_slice(publics);
    for (i, len) in lens.iter().enumerate().take(slots.len()) {
        wr_u32(&mut d, slot_base(i) + S_LEN, *len as u32);
    }
    Ok(())
}

/// `slot u8 | offset u32 | bytes`: copy into slot `slot` at `offset`. Any
/// order, any number of times, until SEAL.
fn write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    if data.len() < 5 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let slot = data[0] as usize;
    let offset = rd_u32(data, 1) as usize;
    let bytes = &data[5..];
    let mut d = buffer.try_borrow_mut_data()?;
    check_initialized_by(&d, authority)?;
    if d[B_SEALED] != 0 {
        return Err(StagedError::Sealed.into());
    }
    let n_slots = kind_slots(d[B_KIND]).ok_or(StagedError::BadKind)?.len();
    if slot >= n_slots {
        return Err(StagedError::BadSlot.into());
    }
    let r = slot_range(&d, slot);
    let end = offset.checked_add(bytes.len()).ok_or(StagedError::OutOfBounds)?;
    if end > r.len() {
        return Err(StagedError::OutOfBounds.into());
    }
    d[r.start + offset..r.start + end].copy_from_slice(bytes);
    Ok(())
}

/// Lock the proof bytes, hash them, and index every slot. A slot that does not
/// index to exactly `NUM_QUERIES` query proofs is refused here (the buffer
/// stays unsealed; nothing is ever finalized from it).
fn seal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    check_initialized_by(&d, authority)?;
    if d[B_SEALED] != 0 {
        return Err(StagedError::Sealed.into());
    }
    let n_slots = kind_slots(d[B_KIND]).ok_or(StagedError::BadKind)?.len();
    for i in 0..n_slots {
        let r = slot_range(&d, i);
        let idx = index_proof(&d[r.clone()]).ok_or(StagedError::Unindexable)?;
        if idx.num_query_proofs() != NUM_QUERIES {
            return Err(StagedError::WrongQueryCount.into());
        }
        let hash = keccak::hashv(&[&d[r]]).to_bytes();
        let b = slot_base(i);
        d[b + S_HASH..b + S_HASH + 32].copy_from_slice(&hash);
        wr_u32(&mut d, b + S_QAT, idx.queries_at as u32);
        wr_u32(&mut d, b + S_END, idx.end as u32);
        for (k, bound) in idx.bounds.iter().enumerate() {
            wr_u32(&mut d, b + S_BOUNDS + 4 * k, *bound as u32);
        }
        msg!("slot {} sealed: {} B, keccak {}", i, r_len(&d, i), keccak::Hash::new_from_array(hash));
    }
    d[B_SEALED] = 1;
    Ok(())
}

fn r_len(d: &[u8], i: usize) -> usize {
    rd_u32(d, slot_base(i) + S_LEN) as usize
}

/// Common prologue of the three verification stages: initialized, sealed,
/// authority, a valid slot. Returns (relation, slot index).
fn stage_prologue(d: &[u8], authority: &AccountInfo, data: &[u8]) -> Result<(Relation, usize), ProgramError> {
    check_initialized_by(d, authority)?;
    if d[B_SEALED] != 1 {
        return Err(StagedError::NotSealed.into());
    }
    if d[B_FINALIZED] != 0 {
        return Err(StagedError::AlreadyFinalized.into());
    }
    let slots = kind_slots(d[B_KIND]).ok_or(StagedError::BadKind)?;
    let slot = *data.first().ok_or(ProgramError::InvalidInstructionData)? as usize;
    let rel = *slots.get(slot).ok_or(StagedError::BadSlot)?;
    Ok((rel, slot))
}

/// `slot u8`: derive and persist the whole Fiat-Shamir transcript.
fn transcript(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    let (rel, slot) = stage_prologue(&d, authority, data)?;
    let b = slot_base(slot);
    if d[b + S_FLAGS] & FLAG_TRANSCRIPT != 0 {
        return Err(StagedError::TranscriptAlreadyDone.into());
    }
    let encoded = {
        let bytes = &d[slot_range(&d, slot)];
        let idx = stored_index(&d, slot);
        let limbs = publics_limbs(&d, rel);
        let publics = publics_from_limbs(&limbs[..rel.num_public_values()]).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] before decode_header
        let header = decode_header(bytes, &idx).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] after decode_header
        let t = stage_transcript(rel, params(&d), &header, &publics, idx.num_query_proofs())
            .ok_or(StagedError::TranscriptRejected)?;
        t.encode()
    };
    if encoded.len() > S_TRANSCRIPT_MAX {
        return Err(StagedError::Malformed.into());
    }
    d[b + S_TLEN..b + S_TLEN + 2].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
    d[b + S_TRANSCRIPT..b + S_TRANSCRIPT + encoded.len()].copy_from_slice(&encoded);
    d[b + S_FLAGS] |= FLAG_TRANSCRIPT;
    Ok(())
}

/// `slot u8`: recompose `quotient(zeta)` and persist it for OOD.
fn quotient(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    let (rel, slot) = stage_prologue(&d, authority, data)?;
    let b = slot_base(slot);
    if d[b + S_FLAGS] & FLAG_TRANSCRIPT == 0 {
        return Err(StagedError::TranscriptMissing.into());
    }
    if d[b + S_FLAGS] & FLAG_QUOTIENT != 0 {
        return Err(StagedError::QuotientAlreadyDone.into());
    }
    let q = {
        let bytes = &d[slot_range(&d, slot)];
        let idx = stored_index(&d, slot);
        let limbs = publics_limbs(&d, rel);
        let publics = publics_from_limbs(&limbs[..rel.num_public_values()]).ok_or(StagedError::Malformed)?;
        let t = stored_transcript(&d, slot).ok_or(StagedError::Malformed)?;
        let header = decode_header(bytes, &idx).ok_or(StagedError::Malformed)?;
        stage_quotient(rel, params(&d), &header, &publics, &t).ok_or(StagedError::Malformed)?
    };
    d[b + S_QUOTIENT..b + S_QUOTIENT + 16].copy_from_slice(&encode_ext(q));
    d[b + S_FLAGS] |= FLAG_QUOTIENT;
    Ok(())
}

/// `slot u8`: the out-of-domain constraint check against the persisted
/// `(alpha, zeta)` and `quotient(zeta)`.
fn ood(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    let (rel, slot) = stage_prologue(&d, authority, data)?;
    let b = slot_base(slot);
    if d[b + S_FLAGS] & FLAG_TRANSCRIPT == 0 {
        return Err(StagedError::TranscriptMissing.into());
    }
    if d[b + S_FLAGS] & FLAG_QUOTIENT == 0 {
        return Err(StagedError::QuotientMissing.into());
    }
    if d[b + S_FLAGS] & FLAG_OOD != 0 {
        return Err(StagedError::OodAlreadyDone.into());
    }
    let ok = {
        let bytes = &d[slot_range(&d, slot)];
        let idx = stored_index(&d, slot);
        let limbs = publics_limbs(&d, rel);
        let publics = publics_from_limbs(&limbs[..rel.num_public_values()]).ok_or(StagedError::Malformed)?;
        let t = stored_transcript(&d, slot).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] before decode_header
        let header = decode_header(bytes, &idx).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] after decode_header
        let q: [u8; 16] = d[b + S_QUOTIENT..b + S_QUOTIENT + 16].try_into().unwrap();
        let q = decode_ext(&q).ok_or(StagedError::Malformed)?;
        stage_ood(rel, params(&d), &header, &publics, &t, q)
    };
    if !ok {
        return Err(StagedError::OodRejected.into());
    }
    d[b + S_FLAGS] |= FLAG_OOD;
    Ok(())
}

/// `slot u8 | positions u8...`: verify these query positions. Each must be in
/// range, distinct, and not yet verified; on success their bits are set.
fn queries(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    let (rel, slot) = stage_prologue(&d, authority, data)?;
    let b = slot_base(slot);
    if d[b + S_FLAGS] & FLAG_TRANSCRIPT == 0 {
        return Err(StagedError::TranscriptMissing.into());
    }
    let positions = &data[1..];
    if positions.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let bitmap = u64::from_le_bytes(d[b + S_BITMAP..b + S_BITMAP + 8].try_into().unwrap());
    let mut add = 0u64;
    for &p in positions {
        let p = p as usize;
        if p >= NUM_QUERIES {
            return Err(StagedError::OutOfBounds.into());
        }
        let bit = 1u64 << p;
        if (bitmap | add) & bit != 0 {
            return Err(StagedError::QueryAlreadyVerified.into());
        }
        add |= bit;
    }
    let ok = {
        let bytes = &d[slot_range(&d, slot)];
        let idx = stored_index(&d, slot);
        let limbs = publics_limbs(&d, rel);
        let publics = publics_from_limbs(&limbs[..rel.num_public_values()]).ok_or(StagedError::Malformed)?;
        let t = stored_transcript(&d, slot).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] before decode_header
        let header = decode_header(bytes, &idx).ok_or(StagedError::Malformed)?;
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] after decode_header
        let mut batch = Vec::with_capacity(positions.len());
        for &p in positions {
            let qp = decode_query(bytes, &idx, p as usize).ok_or(StagedError::Malformed)?;
            batch.push((p as usize, qp));
        }
        #[cfg(feature = "cu-trace")]
        solana_program::log::sol_log_compute_units(); // [cu-trace] after decode_query
        stage_queries(rel, params(&d), &header, &publics, &t, &batch)
    };
    if !ok {
        return Err(StagedError::QueryRejected.into());
    }
    d[b + S_BITMAP..b + S_BITMAP + 8].copy_from_slice(&(bitmap | add).to_le_bytes());
    Ok(())
}

/// Only when every slot has its transcript, its quotient, its OOD check and
/// all `NUM_QUERIES` query bits: write the verified public inputs into the
/// pool-facing prefix and set FINALIZED, to [`FINAL_SETTLEABLE`] for a
/// recipient-bound composition and to [`FINAL_VERIFIED_ONLY`] otherwise.
fn finalize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let mut d = buffer.try_borrow_mut_data()?;
    check_initialized_by(&d, authority)?;
    if d[B_SEALED] != 1 {
        return Err(StagedError::NotSealed.into());
    }
    if d[B_FINALIZED] != 0 {
        return Err(StagedError::AlreadyFinalized.into());
    }
    let slots = kind_slots(d[B_KIND]).ok_or(StagedError::BadKind)?;
    for i in 0..slots.len() {
        let b = slot_base(i);
        let bitmap = u64::from_le_bytes(d[b + S_BITMAP..b + S_BITMAP + 8].try_into().unwrap());
        if d[b + S_FLAGS] != FLAG_TRANSCRIPT | FLAG_QUOTIENT | FLAG_OOD || bitmap != ALL_QUERIES {
            return Err(StagedError::Incomplete.into());
        }
    }
    let field = |f: usize| B_PUBLICS + 32 * f; // action, round, C, nullifier, root
    fn copy(d: &mut [u8], to: usize, from: usize) {
        let v: [u8; 32] = d[from..from + 32].try_into().unwrap();
        d[to..to + 32].copy_from_slice(&v);
    }
    if slots.contains(&Relation::Binding) {
        copy(&mut d, B_ACTION, field(0));
        copy(&mut d, B_NULLIFIER, field(3));
        let round_limbs: [u32; 8] = core::array::from_fn(|k| rd_u32(&d, field(1) + 4 * k));
        let round = round_u64(&round_limbs).ok_or(StagedError::RoundNotU64)?;
        d[B_ROUND..B_ROUND + 16].copy_from_slice(&(round as u128).to_le_bytes());
    }
    if slots.contains(&Relation::Membership) {
        copy(&mut d, B_ROOT, field(4));
    }
    let settleable = d[B_KIND] == KIND_CROWD | KIND_BOUND;
    d[B_FINALIZED] = if settleable { FINAL_SETTLEABLE } else { FINAL_VERIFIED_ONLY };
    Ok(())
}

/// Return the buffer's lamports to `destination` (third account) and clear it.
/// Allowed at any point; closing a finalized buffer the pool has not consumed
/// yet is the authority's call to make.
fn close(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (buffer, authority) = buffer_and_authority(program_id, accounts)?;
    let destination = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    {
        let d = buffer.try_borrow_data()?;
        check_initialized_by(&d, authority)?;
    }
    let lamports = buffer.lamports();
    **destination.try_borrow_mut_lamports()? += lamports;
    **buffer.try_borrow_mut_lamports()? = 0;
    buffer.try_borrow_mut_data()?.fill(0);
    Ok(())
}
