//! Probe for the on-chain verification attempt: does the Winterfell verifier
//! compile for Solana SBF at all? Everything downstream depends on this answer.
#![allow(unexpected_cfgs)]

extern crate alloc;

use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, pubkey::Pubkey};

entrypoint!(process_instruction);

pub fn process_instruction(_p: &Pubkey, _a: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Touch the verifier's types so the linker cannot discard the dependency.
    let n = winter_verifier::Proof::from_bytes(data).map(|p| p.context.trace_info().length());
    msg!("proof parse -> {:?}", n.is_ok());
    Ok(())
}
