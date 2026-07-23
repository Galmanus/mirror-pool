//! On-chain STARK verification for riverrun — the measurement, not a claim.
//!
//! This program embeds nothing and trusts nothing: it takes an opaque riverrun
//! bound-membership proof plus its public inputs and runs the **real** Winterfell
//! verifier — FRI folds, Merkle openings, Fiat-Shamir, constraint checks — inside
//! the Solana runtime. The e2e test measures what that costs in compute units.
//!
//! The point is honesty about a claim this repo made and then corrected: on-chain
//! STARK verification on Solana is not infeasible, it has been done (eprint
//! 2025/1741, murkl, mosaic). This shows riverrun's own verifier running on SBF,
//! and prices it, so the cost is a number rather than an assertion.
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

use riverrun_stark::{verify_bound, BaseElement, Hash};

// Winterfell allocates well past the SBF default 32 KB heap, so we install a
// bump allocator over the largest heap Solana will grant (256 KB via
// request_heap_frame in the transaction). This is the "custom bump allocator
// synchronized with the requested heap frame" that eprint 2025/1741 also needed.
#[cfg(target_os = "solana")]
mod bump {
    use std::alloc::{GlobalAlloc, Layout};
    // real Solana heap base; length is what request_heap_frame grants (256 KB max)
    const HEAP_START: usize = solana_program::entrypoint::HEAP_START_ADDRESS as usize;
    const HEAP_LEN: usize = 256 * 1024;
    pub struct Bump;
    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // position of the next-free pointer, kept in the first 8 bytes of heap
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
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }
}
#[cfg(target_os = "solana")]
#[global_allocator]
static A: bump::Bump = bump::Bump;

entrypoint!(process_instruction);

/// Instruction data layout (little-endian, all field elements as 16-byte f128):
///   root(32) | nullifier(32) | round(16) | action(32) | proof(rest)
pub fn process_instruction(_id: &Pubkey, _accts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    const HEAD: usize = 32 + 32 + 16 + 32;
    if data.len() < HEAD {
        return Err(ProgramError::InvalidInstructionData);
    }
    let root = hash_at(&data[0..32]);
    let nullifier = hash_at(&data[32..64]);
    let round = elem_at(&data[64..80]);
    let action = [elem_at(&data[80..96]), elem_at(&data[96..112])];
    let proof = &data[HEAD..];

    if verify_bound(root, nullifier, round, action, proof) {
        msg!("riverrun STARK verified on-chain");
        Ok(())
    } else {
        msg!("riverrun STARK rejected");
        Err(ProgramError::Custom(1))
    }
}

fn elem_at(b: &[u8]) -> BaseElement {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    BaseElement::new(u128::from_le_bytes(a))
}

fn hash_at(b: &[u8]) -> Hash {
    Hash::new(elem_at(&b[0..16]), elem_at(&b[16..32]))
}
