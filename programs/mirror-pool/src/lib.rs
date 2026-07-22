//! # mirror-pool on-chain program
//!
//! The settlement and anti-replay layer of *Tornado for behavior* on Solana.
//!
//! It maintains the pool's commitment accumulator and member count, coordinates
//! synchronized rounds, and — the crux — enforces **one execution per member per
//! round** through a nullifier registry. The Solana idiom for a nullifier set is
//! a PDA per nullifier: `execute` *creates* the nullifier's PDA, so a second
//! execution with the same nullifier fails because the account already exists.
//! Every value the program stores is a hash, so the on-chain state is itself
//! post-quantum.
//!
//! Scope (honest): the zero-knowledge **membership proof** — that the revealed
//! nullifier belongs to a genuine committed member — is verified *off-chain* by
//! the relayer in this MVP (on-chain STARK verification is on the roadmap). The
//! program is the shared object that makes commitments, rounds, and nullifier
//! anti-replay canonical and tamper-evident on-chain. The commitment accumulator
//! is an *ordered* hash accumulator (a tamper-evident commitment to insertion
//! order and count); the canonical membership Merkle tree lives off-chain in
//! `mirror-core`, rebuildable from the `Committed` events.

use anchor_lang::prelude::*;
use solana_sha256_hasher::hashv;

declare_id!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");

#[program]
pub mod mirror_pool_program {
    use super::*;

    /// Create a pool owned by `authority`.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.merkle_root = [0u8; 32];
        pool.member_count = 0;
        pool.round = 0;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    /// Commit an action ("deposit"): fold `commitment = H(secret‖action)` into the
    /// ordered accumulator and bump the member count. The commitment is emitted so
    /// off-chain clients can rebuild the canonical membership tree.
    pub fn commit(ctx: Context<Commit>, commitment: [u8; 32]) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let index = pool.member_count;
        pool.merkle_root = hashv(&[&pool.merkle_root, &commitment]).to_bytes();
        pool.member_count = pool
            .member_count
            .checked_add(1)
            .ok_or(PoolError::PoolFull)?;
        emit!(Committed {
            pool: pool.key(),
            commitment,
            index,
        });
        Ok(())
    }

    /// Execute an action ("withdrawal"/saque) for the current round. Fails if the
    /// round is stale or the nullifier was already spent (the nullifier PDA
    /// already exists). The membership proof is checked off-chain by the relayer
    /// before this call in the MVP.
    pub fn execute(
        ctx: Context<Execute>,
        action_hash: [u8; 32],
        nullifier: [u8; 32],
        round: u64,
    ) -> Result<()> {
        let pool = &ctx.accounts.pool;
        require!(round == pool.round, PoolError::RoundMismatch);

        let record = &mut ctx.accounts.nullifier_record;
        record.round = round;
        record.bump = ctx.bumps.nullifier_record;

        emit!(Executed {
            pool: pool.key(),
            action_hash,
            nullifier,
            round,
        });
        Ok(())
    }

    /// Advance the pool to the next synchronized round. Authority-gated.
    pub fn advance_round(ctx: Context<AdvanceRound>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.round = pool.round.checked_add(1).ok_or(PoolError::RoundOverflow)?;
        Ok(())
    }
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    /// Ordered hash accumulator over committed commitments (not the canonical
    /// Merkle root; that is rebuilt off-chain from `Committed` events).
    pub merkle_root: [u8; 32],
    pub member_count: u32,
    pub round: u64,
    pub bump: u8,
}

impl Pool {
    pub const SPACE: usize = 8 + 32 + 32 + 4 + 8 + 1;
}

/// Marker account whose mere existence means "this nullifier is spent."
#[account]
pub struct NullifierRecord {
    pub round: u64,
    pub bump: u8,
}

impl NullifierRecord {
    pub const SPACE: usize = 8 + 8 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = Pool::SPACE,
        seeds = [b"pool", authority.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Commit<'info> {
    #[account(mut, seeds = [b"pool", pool.authority.as_ref()], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    /// Anyone may commit into the pool; the committer pays for the (no new
    /// account) transaction. The pool grows permissionlessly.
    pub committer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(action_hash: [u8; 32], nullifier: [u8; 32], round: u64)]
pub struct Execute<'info> {
    #[account(seeds = [b"pool", pool.authority.as_ref()], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    /// The nullifier's PDA. `init` here is the anti-replay: a repeat nullifier
    /// makes this account already exist, and the instruction fails.
    #[account(
        init,
        payer = relayer,
        space = NullifierRecord::SPACE,
        seeds = [b"nullifier", pool.key().as_ref(), nullifier.as_ref()],
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,
    /// A gasless relayer submits on the member's behalf, so no member key signs
    /// the execution — the actor is unlinked from the action.
    #[account(mut)]
    pub relayer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdvanceRound<'info> {
    #[account(
        mut,
        seeds = [b"pool", authority.key().as_ref()],
        bump = pool.bump,
        has_one = authority
    )]
    pub pool: Account<'info, Pool>,
    pub authority: Signer<'info>,
}

#[event]
pub struct Committed {
    pub pool: Pubkey,
    pub commitment: [u8; 32],
    pub index: u32,
}

#[event]
pub struct Executed {
    pub pool: Pubkey,
    pub action_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub round: u64,
}

#[error_code]
pub enum PoolError {
    #[msg("execution round does not match the pool's current round")]
    RoundMismatch,
    #[msg("the commitment set is full")]
    PoolFull,
    #[msg("round counter overflow")]
    RoundOverflow,
}
