//! On-chain verification of riverrun's own M31 relation, the measurement, not
//! a claim, mirroring `programs/stark-verifier`'s honesty for the Winterfell
//! f128 path (`verify_bound`, priced there at 157,758 CU on Solana SBF).
//!
//! This program takes a real `riverrun_m31::binding::BindingProof` (a genuine
//! Circle-STARK proof that a leaf and a nullifier share one secret, §1a+§1c
//! of `docs/M31_CIRCLE_STARK.md`) plus its public values, and runs riverrun's
//! own verifier, riverrun-authored constraint code built on licensed Plonky3
//! crates, inside the Solana runtime. The e2e test measures the real cost.
//!
//! **Scope, named honestly.** This verifies §1a+§1c (binding), not §1b
//! (membership under a root, `riverrun_m31::membership`) and not the composed
//! full relation (`riverrun_m31::relation`): binding is the smaller, simpler
//! proof, the right first thing to measure on-chain, not the whole relation
//! at once. It also does not gate anything: this program only answers
//! "does this proof verify," it is not wired into `riverrun-nullifier-registry`
//! or any settlement path. That wiring is real, separate, unstarted work.
//!
//! **A real BindingProof serializes to ~78 KB** at production security (40
//! FRI queries; measured, `crates/riverrun-m31/src/binding.rs`'s own
//! `a_proof_survives_a_byte_round_trip` test prints the exact figure). That
//! is past both a transaction's ~1232-byte packet limit AND, it turns out,
//! the ~65535-byte (u16) cap on a whole serialized message, confirmed
//! directly: LiteSVM's `send_transaction` rejects it with `"length larger
//! than u16"` even with no packet-size enforcement, at any query count that
//! keeps real security. A real deployment needs the buffer-account staging
//! `docs/M31_CIRCLE_STARK.md` already specifies (write the proof into an
//! account across several transactions, verify by reading it back); that
//! staging is not built here. `prove_binding_tuned`/`verify_binding_tuned`
//! (an explicit FRI-query-count parameter, always separate from the
//! production `prove_binding`/`verify_binding`) exist so this program's own
//! tests can measure a reduced-security point that fits inline, without ever
//! silently weakening the production path.
//!
//! **Status, as of this writing: loads and executes on-chain, does not yet
//! complete.** The compiled `.so` loads cleanly (confirmed by diffing
//! `readelf -S` section layout against `programs/stark-verifier`'s working
//! one: both end up at the same clean shape, `.text` / `.rodata` /
//! `.data.rel.ro` / `.dynamic` / `.dynsym` / `.dynstr` / `.rel.dyn`, after
//! two SBF-toolchain fixes: `p3-mersenne-31`'s unused Poseidon1/MDS code
//! removed via a vendored patch, and `tracing`'s `#[instrument]` callsite
//! statics compiled out via the `max_level_off` feature). It executes,
//! deserializes a real proof (bisected with temporary `msg!` logging: proof
//! bytes arrive and parse fine). It then runs out of Solana's hard 256 KB
//! heap ceiling (`MAX_HEAP_FRAME_BYTES`, not something a program can request
//! past) **inside `verify()` itself**, at a compute-unit cost
//! (~1.5-2M CU consumed before OOM) that stayed essentially flat between 4
//! and 12 FRI queries, meaning the memory wall sits in `verify()`'s fixed
//! setup (challenger/PCS construction), not the per-query loop, so reducing
//! queries further will not fix this alone. Closing it needs either a
//! from-scratch, memory-budgeted verifier (not `p3_uni_stark::verify`'s
//! generic machinery as-is) or confirming this is a hard ceiling for this
//! construction on SBF: real, unstarted work, not attempted further here.
//! See `programs/riverrun-m31-verifier/tests/cu.rs`'s `#[ignore]`d
//! `measure_on_chain_binding_verification_cost` for the reproduction.
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

use riverrun_m31::{verify_binding_tuned, BindingProof, CONTEXT_LEN, WIDTH};

// A real Circle-STARK verification allocates well past SBF's default 32 KB
// heap (same reason programs/stark-verifier needs this for Winterfell): a
// bump allocator over the largest heap Solana will grant (256 KB via
// request_heap_frame in the transaction, MAX_HEAP_FRAME_BYTES, a hard
// Solana-wide ceiling, not something this program can ask past).
//
// A pure bump allocator (dealloc is a no-op) genuinely ran out of the full
// 256 KB partway through a real verify() call: FRI folding and the query
// phase allocate many short-lived Vec<>s, and a pure bump never reclaims
// them. This is a LIFO/stack allocator instead: dealloc rolls the bump
// pointer back only when the freed block is exactly the most recently
// allocated one (the common case for scoped temporaries in iterative/
// recursive numerical code). Out-of-order frees just don't reclaim, same as
// the pure bump did for everything; this is strictly not worse, and
// measurably better for the allocation pattern verify() actually has.
#[cfg(target_os = "solana")]
mod bump {
    use std::alloc::{GlobalAlloc, Layout};
    const HEAP_START: usize = solana_program::entrypoint::HEAP_START_ADDRESS as usize;
    const HEAP_LEN: usize = 256 * 1024;
    pub struct Bump;
    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pos_ptr = HEAP_START as *mut usize;
            let mut pos = *pos_ptr;
            if pos == 0 {
                pos = HEAP_START + 8;
            }
            let align = layout.align();
            let start = (pos + align - 1) & !(align - 1);
            let end = start + layout.size();
            if end > HEAP_START + HEAP_LEN {
                return core::ptr::null_mut();
            }
            *pos_ptr = end;
            start as *mut u8
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let pos_ptr = HEAP_START as *mut usize;
            let pos = *pos_ptr;
            let end = ptr as usize + layout.size();
            if end == pos {
                *pos_ptr = ptr as usize;
            }
        }
    }
}
#[cfg(target_os = "solana")]
#[global_allocator]
static A: bump::Bump = bump::Bump;

entrypoint!(process_instruction);

const U64S: usize = 8;
const QUERIES_BYTES: usize = 2; // u16 LE
const CTX_BYTES: usize = CONTEXT_LEN * U64S; // 64
const WIDTH_BYTES: usize = WIDTH * U64S; // 128
const HEAD: usize = QUERIES_BYTES + CTX_BYTES + CTX_BYTES + WIDTH_BYTES + WIDTH_BYTES; // queries | action | round | leaf | nullifier

/// Instruction data layout (little-endian):
///   num_queries(2, u16) | action(64) | round(64) | leaf(128) | nullifier(128) | proof(rest, bincode)
///
/// `num_queries` must match whatever FRI query count the proof was produced
/// with (`prove_binding_tuned`). Exposed here, not hardcoded, so the caller's
/// choice of security/size tradeoff is explicit in the instruction itself,
/// not silently assumed by the program.
pub fn process_instruction(_id: &Pubkey, _accts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < HEAD {
        return Err(ProgramError::InvalidInstructionData);
    }
    let num_queries = u16::from_le_bytes([data[0], data[1]]) as usize;
    let action = ctx_at(&data[QUERIES_BYTES..QUERIES_BYTES + CTX_BYTES]);
    let round = ctx_at(&data[QUERIES_BYTES + CTX_BYTES..QUERIES_BYTES + 2 * CTX_BYTES]);
    let leaf = wide_at(&data[QUERIES_BYTES + 2 * CTX_BYTES..QUERIES_BYTES + 2 * CTX_BYTES + WIDTH_BYTES]);
    let nullifier = wide_at(&data[QUERIES_BYTES + 2 * CTX_BYTES + WIDTH_BYTES..HEAD]);
    let proof_bytes = &data[HEAD..];

    let Some(proof) = BindingProof::from_bytes(proof_bytes) else {
        msg!("riverrun M31 binding proof: malformed bytes");
        return Err(ProgramError::InvalidInstructionData);
    };

    if verify_binding_tuned(&proof, action, round, leaf, nullifier, num_queries) {
        msg!("riverrun M31 binding proof verified on-chain");
        Ok(())
    } else {
        msg!("riverrun M31 binding proof rejected");
        Err(ProgramError::Custom(1))
    }
}

fn ctx_at(b: &[u8]) -> [u64; CONTEXT_LEN] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * U64S..(i + 1) * U64S].try_into().unwrap()))
}

fn wide_at(b: &[u8]) -> [u64; WIDTH] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * U64S..(i + 1) * U64S].try_into().unwrap()))
}
