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
//! **Status (2026-07-29): VERIFIES ON-CHAIN.** The 256 KB heap wall described
//! below is closed. Native heap profiling with a tracking allocator (plus a
//! replay simulation of this program's exact LIFO-bump reclaim semantics)
//! attributed ~92% of `verify()`'s peak live heap not to FRI, PCS state or
//! the challenger but to `p3_uni_stark`'s **symbolic AIR re-evaluation** —
//! `get_log_num_quotient_chunks` building a transient `SymbolicExpr` tree
//! (452,760 B peak live at 4 queries) purely to derive one compile-time
//! constant. The fix is the third vendored patch,
//! `vendor/p3-uni-stark-0.6.2-heap-patch` (see its PATCH.md):
//! `verify_with_known_quotient_chunks` takes that constant as a parameter,
//! and `riverrun_m31` pins it (`binding::LOG_NUM_QUOTIENT_CHUNKS`, guarded by
//! a native test that recomputes it symbolically and fails on drift).
//! Re-measured peak live heap after the fix: 37,664 B at 4 queries,
//! 109,376 B at the production 40 queries — LIFO-bump watermark 171,736 B,
//! under the ceiling with ~90 KB of margin.
//!
//! Measured on-chain cost (LiteSVM, 4-query proof, this crate's `cu.rs`):
//! **2,384,277 CU, ACCEPTED** — the first time riverrun's own M31 relation
//! verifies inside the Solana runtime. Two further cost reductions got it
//! there: keccak256 routed to Solana's syscall on-chain
//! (`riverrun_m31::keccak::SolKeccak256`; software keccak cost 6.17M CU
//! total) and `opt-level = 3` for the SBF build (`"z"` cost 4.31M; CU is an
//! instruction count, not bytes). Still over a real transaction's 1.4M cap:
//! per-phase attribution (the patch's `cu-trace` feature) puts ~70% in
//! `pcs.verify` at ~348k CU *per FRI query* (DEEP column reduction + MMCS +
//! fold), so the remaining gap is per-query cost, not fixed overhead —
//! open, real work (arity/blowup tuning, column-count reduction, or staged
//! verification), named in `tests/cu.rs`.
//!
//! History of the wall, kept because the diagnosis was real work: the
//! compiled `.so` loads cleanly (confirmed by diffing
//! `readelf -S` section layout against `programs/stark-verifier`'s working
//! one: both end up at the same clean shape, `.text` / `.rodata` /
//! `.data.rel.ro` / `.dynamic` / `.dynsym` / `.dynstr` / `.rel.dyn`, after
//! two SBF-toolchain fixes: `p3-mersenne-31`'s unused Poseidon1/MDS code
//! removed via a vendored patch, and `tracing`'s `#[instrument]` callsite
//! statics compiled out via the `max_level_off` feature). It executes,
//! deserializes a real proof (bisected with checkpointed `msg!` logging:
//! proof bytes arrive and parse fine, using well under 10% of the heap:
//! 16,196 of 262,144 bytes for a 4-query `BindingProof` right up to the
//! `verify()` call). It then runs out of Solana's hard 256 KB heap ceiling
//! (`MAX_HEAP_FRAME_BYTES`, not something a program can request past)
//! **inside `verify()` itself**, meaning `verify()` alone needs over 240 KB
//! on top of a proof that only cost 16 KB to hold. The CU cost before OOM
//! stayed essentially flat between 4 and 12 FRI queries (~1.5-2M), meaning
//! the wall is not the per-query loop. **A further, real comparison ruled
//! out AIR complexity as the cause too:** the smallest possible AIR in this
//! crate (`permutation.rs`'s single-block, non-vectorized preimage proof,
//! `discriminator 1`) ALSO exceeds the ceiling (and costs even more CU
//! before failing, ~3.05M), so this is not specific to `BindingAir`'s two-
//! block width. The wall looks inherent to this CirclePcs / Keccak-MMCS /
//! FRI verifier construction as configured here, independent of both proof
//! size and AIR shape. Closing it needs either a from-scratch, memory-
//! budgeted verifier (not `p3_uni_stark::verify`'s generic machinery as-is)
//! or confirming this really is a hard ceiling for this construction on SBF:
//! real, unstarted, and genuinely uncertain work, not attempted further
//! here. See `programs/riverrun-m31-verifier/tests/cu.rs`'s two `#[ignore]`d
//! tests, `measure_on_chain_binding_verification_cost` and
//! `measure_on_chain_preimage_verification_cost`, for the reproduction.
//!
//! **Source-level follow-up (2026-07-28).** Read `p3_uni_stark::verifier::verify`,
//! `CirclePcs::verify`, and the start of `p3_fri::verifier::verify_fri` directly
//! (not guessing from outside): no single oversized `Vec::with_capacity` or
//! buffer stands out in `verify()`'s own body; most of what it holds is
//! proof-sized data already accounted for in the ~16KB deserialization cost.
//! One real signal from the CU data: cost stayed nearly flat across a 10x
//! query-count range (4 to 40 queries, 1.5M to 2.06M CU, +37%), which is not
//! what a per-query-dominated cost would look like; it points at FRI/PCS's
//! one-time setup (challenger sampling, alpha/domain bookkeeping, before the
//! per-query closure ever runs) as the actual driver, not the query loop
//! itself. Pinpointing the exact allocation from here needs either
//! instrumenting or forking `p3-fri`/`p3-circle` internals directly, a
//! materially larger step than the two toolchain patches this crate already
//! carries (those changed a build flag and a stable-API rewrite; this would
//! mean editing real verification logic in an upstream crypto library).
//! Deliberately not done without separate sign-off given that risk profile.
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

use riverrun_m31::{BindingProof, PreimageProof, CONTEXT_LEN, WIDTH};

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
                // Tried logging the failing request's exact size here
                // (format! + sol_log) to tell a single giant allocation
                // apart from many small ones; reverted; std::format! itself
                // allocates, so a failing alloc's own logging can recurse
                // into more failing allocs, which surfaced as Solana's BPF-
                // to-BPF call-depth limit instead of useful data. Left
                // unresolved rather than chasing a diagnostic that fights
                // itself.
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

/// Bytes of heap consumed so far (the bump pointer's distance from the base),
/// for diagnostic `msg!` logging while bisecting where a heap ceiling is hit.
/// `0` off-chain (there is no HEAP_START_ADDRESS memory to read).
fn heap_used() -> usize {
    #[cfg(target_os = "solana")]
    {
        let heap_start = solana_program::entrypoint::HEAP_START_ADDRESS as usize;
        let pos_ptr = heap_start as *const usize;
        let pos = unsafe { *pos_ptr };
        if pos == 0 {
            0
        } else {
            pos - heap_start
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        0
    }
}

entrypoint!(process_instruction);

const U64S: usize = 8;
const QUERIES_BYTES: usize = 2; // u16 LE
const CTX_BYTES: usize = CONTEXT_LEN * U64S; // 64
const WIDTH_BYTES: usize = WIDTH * U64S; // 128
const HEAD: usize = QUERIES_BYTES + CTX_BYTES + CTX_BYTES + WIDTH_BYTES + WIDTH_BYTES; // queries | action | round | leaf | nullifier

/// Instruction data layout: a 1-byte discriminator, then per-instruction data.
///
/// - `0`: verify a `BindingProof` (§1a+§1c). `num_queries(2, u16) | action(64)
///   | round(64) | leaf(128) | nullifier(128) | proof(rest, bincode)`.
///   `num_queries` must match whatever FRI query count the proof was produced
///   with (`prove_binding_tuned`), exposed rather than assumed by the program.
/// - `1`: verify a `PreimageProof` (the simpler, single-block, non-vectorized
///   AIR from `permutation.rs`), added purely to diagnose
///   riverrun-m31-verifier's on-chain memory ceiling: comparing this
///   smaller/simpler AIR's peak `verify()` memory against `BindingProof`'s
///   two-block vectorized one isolates whether AIR complexity is what drives
///   it. `output(128) | proof(rest, bincode)`.
pub fn process_instruction(_id: &Pubkey, _accts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let Some((&discriminator, rest)) = data.split_first() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match discriminator {
        0 => process_binding(rest),
        1 => process_preimage(rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_binding(data: &[u8]) -> ProgramResult {
    if data.len() < HEAD {
        return Err(ProgramError::InvalidInstructionData);
    }
    let num_queries = u16::from_le_bytes([data[0], data[1]]) as usize;
    let action = ctx_at(&data[QUERIES_BYTES..QUERIES_BYTES + CTX_BYTES]);
    let round = ctx_at(&data[QUERIES_BYTES + CTX_BYTES..QUERIES_BYTES + 2 * CTX_BYTES]);
    let leaf = wide_at(&data[QUERIES_BYTES + 2 * CTX_BYTES..QUERIES_BYTES + 2 * CTX_BYTES + WIDTH_BYTES]);
    let nullifier = wide_at(&data[QUERIES_BYTES + 2 * CTX_BYTES + WIDTH_BYTES..HEAD]);
    let proof_bytes = &data[HEAD..];
    msg!("heap: {} B before deserialize", heap_used());

    let Some(proof) = BindingProof::from_bytes(proof_bytes) else {
        msg!("riverrun M31 binding proof: malformed bytes");
        return Err(ProgramError::InvalidInstructionData);
    };
    msg!("heap: {} B after deserialize", heap_used());

    if riverrun_m31::verify_binding_tuned_checkpointed(&proof, action, round, leaf, nullifier, num_queries, || {
        msg!("heap: {} B after config, before verify()", heap_used());
    }) {
        msg!("riverrun M31 binding proof verified on-chain");
        Ok(())
    } else {
        msg!("riverrun M31 binding proof rejected");
        Err(ProgramError::Custom(1))
    }
}

fn process_preimage(data: &[u8]) -> ProgramResult {
    if data.len() < WIDTH_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    let output = wide_at(&data[..WIDTH_BYTES]);
    let proof_bytes = &data[WIDTH_BYTES..];
    msg!("heap: {} B before deserialize", heap_used());

    let Some(proof) = PreimageProof::from_bytes(proof_bytes) else {
        msg!("riverrun M31 preimage proof: malformed bytes");
        return Err(ProgramError::InvalidInstructionData);
    };
    msg!("heap: {} B after deserialize", heap_used());

    if riverrun_m31::verify_preimage(&proof, output) {
        msg!("heap: {} B after verify()", heap_used());
        msg!("riverrun M31 preimage proof verified on-chain");
        Ok(())
    } else {
        msg!("riverrun M31 preimage proof rejected");
        Err(ProgramError::Custom(1))
    }
}

fn ctx_at(b: &[u8]) -> [u64; CONTEXT_LEN] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * U64S..(i + 1) * U64S].try_into().unwrap()))
}

fn wide_at(b: &[u8]) -> [u64; WIDTH] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * U64S..(i + 1) * U64S].try_into().unwrap()))
}
