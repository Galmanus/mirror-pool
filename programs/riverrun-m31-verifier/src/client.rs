//! Host-side instruction builders for the staged buffer protocol ([`crate::staged`]):
//! the exact encodings `tests/staged.rs` drives through LiteSVM, for a client
//! (or a devnet script) to submit the same sequence to a real cluster.
//!
//! Every verification-stage transaction (SEAL onward) must also carry
//! `ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)` and
//! `ComputeBudgetInstruction::request_heap_frame(262_144)`: the stages use up
//! to ~1.21M CU (measured) and the program's allocator assumes the 256 KB heap.
//! WRITE and INIT need neither. INIT must be signed by the buffer keypair as
//! well as the authority; send it in the same transaction as the system
//! program's `create_account` (owner = this program, space =
//! [`buffer_size`], lamports = the rent-exempt minimum for that space).

use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

use crate::staged::{
    B_PROOFS, IX_CLOSE, IX_FINALIZE, IX_INIT, IX_OOD, IX_QUERIES, IX_QUOTIENT, IX_SEAL,
    IX_TRANSCRIPT, IX_WRITE, KIND_BOUND, KIND_CROWD, NUM_QUERIES,
};

/// Proof bytes per WRITE that keep a one-signer WRITE transaction (authority
/// as fee payer, no compute-budget instructions) under the 1232-byte packet
/// limit; `tests/staged.rs` asserts the serialized size of every one it sends.
pub const WRITE_CHUNK: usize = 1015;

/// Account size for a buffer holding these proof slots.
pub fn buffer_size(slot_lens: &[usize]) -> usize {
    B_PROOFS + slot_lens.iter().sum::<usize>()
}

fn ix(program_id: &Pubkey, buffer: &Pubkey, authority: &Pubkey, tag: u8, data: &[u8]) -> Instruction {
    let mut d = Vec::with_capacity(1 + data.len());
    d.push(tag);
    d.extend_from_slice(data);
    Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new(*buffer, false), AccountMeta::new_readonly(*authority, true)],
        data: d,
    }
}

/// INIT. `publics` is action(8) | round(8) | C(8) | nullifier(8) | root(8) as
/// canonical u32 limbs (unused fields zero for a single-relation kind); `round`
/// limbs must follow `staged::round_limbs`.
#[allow(clippy::too_many_arguments)]
pub fn init(
    program_id: &Pubkey,
    buffer: &Pubkey,
    authority: &Pubkey,
    kind: u8,
    nonce: u64,
    recipient: &Pubkey,
    publics: &[u32; 40],
    slot_lens: &[usize],
) -> Instruction {
    let mut data = vec![kind];
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(recipient.as_ref());
    for v in publics {
        data.extend_from_slice(&v.to_le_bytes());
    }
    for len in slot_lens {
        data.extend_from_slice(&(*len as u32).to_le_bytes());
    }
    let mut i = ix(program_id, buffer, authority, IX_INIT, &data);
    i.accounts[0].is_signer = true;
    i
}

/// Every WRITE for one slot's proof bytes, [`WRITE_CHUNK`] at a time.
pub fn writes(program_id: &Pubkey, buffer: &Pubkey, authority: &Pubkey, slot: u8, bytes: &[u8]) -> Vec<Instruction> {
    bytes
        .chunks(WRITE_CHUNK)
        .enumerate()
        .map(|(k, chunk)| {
            let mut d = vec![slot];
            d.extend_from_slice(&((k * WRITE_CHUNK) as u32).to_le_bytes());
            d.extend_from_slice(chunk);
            ix(program_id, buffer, authority, IX_WRITE, &d)
        })
        .collect()
}

/// One verification-stage instruction (`tag` one of the `IX_*` stage tags).
pub fn stage(program_id: &Pubkey, buffer: &Pubkey, authority: &Pubkey, tag: u8, data: &[u8]) -> Instruction {
    ix(program_id, buffer, authority, tag, data)
}

/// The whole verification sequence after the WRITEs, one instruction per
/// transaction, labelled: SEAL, then per slot TRANSCRIPT, QUOTIENT, OOD and the
/// QUERIES batches of `query_batch` positions, then FINALIZE. Each needs the
/// compute-budget instructions named in the module doc.
pub fn verification_plan(
    program_id: &Pubkey,
    buffer: &Pubkey,
    authority: &Pubkey,
    kind: u8,
    query_batch: usize,
) -> Vec<(String, Instruction)> {
    let slots: u8 = if kind & !KIND_BOUND == KIND_CROWD { 2 } else { 1 };
    let mut plan = vec![("SEAL".to_string(), stage(program_id, buffer, authority, IX_SEAL, &[]))];
    for slot in 0..slots {
        for (name, tag) in [("TRANSCRIPT", IX_TRANSCRIPT), ("QUOTIENT", IX_QUOTIENT), ("OOD", IX_OOD)] {
            plan.push((format!("slot {slot} {name}"), stage(program_id, buffer, authority, tag, &[slot])));
        }
        let positions: Vec<u8> = (0..NUM_QUERIES as u8).collect();
        for batch in positions.chunks(query_batch.max(1)) {
            let mut d = vec![slot];
            d.extend_from_slice(batch);
            plan.push((format!("slot {slot} QUERIES {batch:?}"), stage(program_id, buffer, authority, IX_QUERIES, &d)));
        }
    }
    plan.push(("FINALIZE".to_string(), stage(program_id, buffer, authority, IX_FINALIZE, &[])));
    plan
}

/// CLOSE: return the buffer's rent to `destination`.
pub fn close(program_id: &Pubkey, buffer: &Pubkey, authority: &Pubkey, destination: &Pubkey) -> Instruction {
    let mut i = ix(program_id, buffer, authority, IX_CLOSE, &[]);
    i.accounts.push(AccountMeta::new(*destination, false));
    i
}
