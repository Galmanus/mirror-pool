//! # riverrun on-chain program
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
//! `riverrun-core`, rebuildable from the `Committed` events.
//!
//! ## What `execute` now requires (audit-critical #2)
//!
//! A riverrun STARK is 12–16 KB, so it does not fit in Solana's 1232-byte
//! transaction limit at all — verifying it on-chain would mean chunk-uploading it
//! into a ~16 KB account (rent ~0.115 SOL, against ~0.001 SOL for a whole action
//! today) before any compute is spent. So this program takes the trusted-relayer
//! side of that trade, and makes the trust **explicit and bounded** instead of
//! implicit:
//!
//! - the pool names a **verifier** key;
//! - `execute` requires an Ed25519 signature from that key, checked through the
//!   native sigverify precompile and instruction introspection, over exactly the
//!   `(pool, root, action, nullifier, round)` being settled;
//! - the root in that attestation must equal the root the authority published for
//!   this round.
//!
//! What that buys: an arbitrary signer can no longer settle an action, and a
//! watcher can no longer front-run a nullifier out of the mempool, because
//! neither can produce the verifier's signature over their own tuple. What it
//! does **not** buy: soundness. A dishonest verifier can attest to a membership
//! proof that does not exist. This is a named trust assumption, not a proof — and
//! the root is *published* rather than computed here because the canonical tree
//! is Rescue-Prime, whose inverse S-box is not something to run on-chain.

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use solana_sdk_ids::ed25519_program;
use solana_sha256_hasher::hashv;

/// Domain separator for the verifier's attestation, so a signature made for
/// riverrun cannot be replayed as a signature for anything else the key signs.
const ATTESTATION_DOMAIN: &[u8; 16] = b"riverrun-exec-v1";
/// domain(16) + pool(32) + root(32) + action(32) + nullifier(32) + round(8)
const ATTESTATION_LEN: usize = 152;

/// Layout of the native Ed25519 instruction's data (one signature): a 16-byte
/// header, then the public key, the signature, and the message.
const ED25519_HEADER_LEN: usize = 16;
const ED25519_PUBKEY_OFFSET: usize = ED25519_HEADER_LEN;
const ED25519_SIGNATURE_OFFSET: usize = ED25519_PUBKEY_OFFSET + 32;
const ED25519_MESSAGE_OFFSET: usize = ED25519_SIGNATURE_OFFSET + 64;

declare_id!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");

#[program]
pub mod riverrun_program {
    use super::*;

    /// Create a pool owned by `authority`, naming the `verifier` key whose
    /// attestation every execution must carry.
    pub fn initialize(
        ctx: Context<Initialize>,
        verifier: Pubkey,
        entry_fee: u64,
        k_min: u32,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.verifier = verifier;
        pool.entry_fee = entry_fee;
        pool.k_min = k_min;
        pool.accumulator = [0u8; 32];
        pool.membership_root = [0u8; 32];
        pool.member_count = 0;
        pool.round = 0;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    /// Rotate the verifier key. Authority-gated — a compromised verifier can
    /// attest to executions that were never proven, so this is the recovery path.
    pub fn set_verifier(ctx: Context<AdvanceRound>, verifier: Pubkey) -> Result<()> {
        ctx.accounts.pool.verifier = verifier;
        Ok(())
    }

    /// Reprice a seat in the anonymity set. Authority-gated.
    pub fn set_entry_fee(ctx: Context<AdvanceRound>, entry_fee: u64) -> Result<()> {
        ctx.accounts.pool.entry_fee = entry_fee;
        Ok(())
    }

    /// Publish the canonical off-chain membership root that executions must be
    /// proven against. Authority-gated, and typically called alongside a round
    /// advance to freeze the anonymity set for that round.
    pub fn publish_root(ctx: Context<AdvanceRound>, root: [u8; 32]) -> Result<()> {
        require!(root != [0u8; 32], PoolError::RootNotPublished);
        ctx.accounts.pool.membership_root = root;
        emit!(RootPublished {
            pool: ctx.accounts.pool.key(),
            root,
            round: ctx.accounts.pool.round,
        });
        Ok(())
    }

    /// Commit an action ("deposit"): fold `commitment = H(secret‖action)` into the
    /// ordered accumulator and bump the member count. The commitment is emitted so
    /// off-chain clients can rebuild the canonical membership tree.
    pub fn commit(ctx: Context<Commit>, commitment: [u8; 32]) -> Result<()> {
        // Anti-Sybil, such as it is: a seat costs something. Permissionless
        // commit means k is buyable, and a fee does not stop an attacker with
        // money — it only makes inflating k to k+m cost m·fee instead of m·0.
        // The honest claim is "priced", not "prevented".
        let fee = ctx.accounts.pool.entry_fee;
        if fee > 0 {
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.committer.to_account_info(),
                        to: ctx.accounts.pool.to_account_info(),
                    },
                ),
                fee,
            )?;
        }

        let pool = &mut ctx.accounts.pool;
        let index = pool.member_count;
        pool.accumulator = hashv(&[&pool.accumulator, &commitment]).to_bytes();
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
    /// round is stale, the root is not the published one, the nullifier was
    /// already spent (its PDA already exists), or the transaction does not carry
    /// the named verifier's attestation for this exact tuple.
    pub fn execute(
        ctx: Context<Execute>,
        action_hash: [u8; 32],
        nullifier: [u8; 32],
        round: u64,
        root: [u8; 32],
    ) -> Result<()> {
        let pool = &ctx.accounts.pool;
        require!(round == pool.round, PoolError::RoundMismatch);
        // A set of one is not an anonymity set: the action belongs to that member
        // by elimination. Refuse to settle below the floor.
        require!(pool.member_count >= pool.k_min, PoolError::AnonymitySetTooSmall);
        require!(pool.membership_root != [0u8; 32], PoolError::RootNotPublished);
        require!(root == pool.membership_root, PoolError::RootMismatch);

        verify_attestation(
            &ctx.accounts.instructions,
            &pool.verifier,
            &attestation_message(&pool.key(), &root, &action_hash, &nullifier, round),
        )?;

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

/// The message the verifier signs. Every field is bound, so an attestation
/// cannot be lifted onto a different pool, round, action or nullifier — which is
/// what takes nullifier front-running off the table.
fn attestation_message(
    pool: &Pubkey,
    root: &[u8; 32],
    action_hash: &[u8; 32],
    nullifier: &[u8; 32],
    round: u64,
) -> [u8; ATTESTATION_LEN] {
    let mut m = [0u8; ATTESTATION_LEN];
    m[..16].copy_from_slice(ATTESTATION_DOMAIN);
    m[16..48].copy_from_slice(pool.as_ref());
    m[48..80].copy_from_slice(root);
    m[80..112].copy_from_slice(action_hash);
    m[112..144].copy_from_slice(nullifier);
    m[144..152].copy_from_slice(&round.to_le_bytes());
    m
}

/// Require that the transaction carries, immediately before this instruction, a
/// native Ed25519 sigverify instruction for `verifier` over `expected`.
///
/// The signature itself is checked by the precompile, not here: if the runtime
/// executes the transaction at all, the signature is valid. What is checked here
/// is that the precompile was asked about *this* key and *this* message, and that
/// the key and message live inside the sigverify instruction's own data
/// (index `0xFFFF`) rather than being read from elsewhere in the transaction.
fn verify_attestation(
    instructions: &UncheckedAccount,
    verifier: &Pubkey,
    expected: &[u8; ATTESTATION_LEN],
) -> Result<()> {
    let index = load_current_index_checked(instructions)?;
    require!(index > 0, PoolError::MissingAttestation);
    let ix = load_instruction_at_checked((index - 1) as usize, instructions)
        .map_err(|_| error!(PoolError::MissingAttestation))?;

    require_keys_eq!(ix.program_id, ed25519_program::ID, PoolError::MissingAttestation);
    let data = &ix.data;
    require!(
        data.len() == ED25519_MESSAGE_OFFSET + ATTESTATION_LEN,
        PoolError::AttestationMismatch
    );
    // exactly one signature, and every part sourced from this instruction's data
    require!(data[0] == 1 && data[1] == 0, PoolError::AttestationMismatch);
    let field = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
    require!(
        field(2) as usize == ED25519_SIGNATURE_OFFSET
            && field(6) as usize == ED25519_PUBKEY_OFFSET
            && field(10) as usize == ED25519_MESSAGE_OFFSET
            && field(12) as usize == ATTESTATION_LEN
            && field(4) == u16::MAX
            && field(8) == u16::MAX
            && field(14) == u16::MAX,
        PoolError::AttestationMismatch
    );

    let signer = &data[ED25519_PUBKEY_OFFSET..ED25519_PUBKEY_OFFSET + 32];
    require!(signer == verifier.as_ref(), PoolError::UnknownVerifier);
    let message = &data[ED25519_MESSAGE_OFFSET..];
    require!(message == expected.as_ref(), PoolError::AttestationMismatch);

    Ok(())
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    /// What one seat in the anonymity set costs, in lamports. Priced, not
    /// prevented — see `commit`.
    pub entry_fee: u64,
    /// Executions are refused while the set has fewer than this many members.
    pub k_min: u32,
    /// The key whose Ed25519 attestation every execution must carry. It attests
    /// that it checked the off-chain membership proof; it is trusted to do so.
    pub verifier: Pubkey,
    /// Ordered hash accumulator over committed commitments (not the canonical
    /// Merkle root; that is rebuilt off-chain from `Committed` events).
    pub accumulator: [u8; 32],
    /// The canonical off-chain (Rescue-Prime) membership root executions are
    /// settled against, published by the authority.
    pub membership_root: [u8; 32],
    pub member_count: u32,
    pub round: u64,
    pub bump: u8,
}

impl Pool {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 32 + 4 + 8 + 1 + 8 + 4;
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
    /// Anyone may commit into the pool — it grows permissionlessly — but a seat
    /// costs `entry_fee`, which this account pays.
    #[account(mut)]
    pub committer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(action_hash: [u8; 32], nullifier: [u8; 32], round: u64, root: [u8; 32])]
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
    /// CHECK: address-checked below; read only through the instructions-sysvar
    /// helpers to find the verifier's Ed25519 attestation in this transaction.
    #[account(address = solana_sdk_ids::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
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

#[event]
pub struct RootPublished {
    pub pool: Pubkey,
    pub root: [u8; 32],
    pub round: u64,
}

#[error_code]
pub enum PoolError {
    #[msg("execution round does not match the pool's current round")]
    RoundMismatch,
    #[msg("no verifier attestation precedes this instruction")]
    MissingAttestation,
    #[msg("the attestation was signed by a key that is not this pool's verifier")]
    UnknownVerifier,
    #[msg("the attestation does not cover this exact pool, root, action, nullifier and round")]
    AttestationMismatch,
    #[msg("the pool has not published a membership root yet")]
    RootNotPublished,
    #[msg("the execution's root is not the root published for this round")]
    RootMismatch,
    #[msg("the anonymity set is below the pool's floor: an execution here would not be private")]
    AnonymitySetTooSmall,
    #[msg("the commitment set is full")]
    PoolFull,
    #[msg("round counter overflow")]
    RoundOverflow,
}
