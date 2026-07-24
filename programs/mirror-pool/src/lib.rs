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
//! - the pool names a **committee** of verifier keys and a **threshold** M;
//! - `execute` requires Ed25519 signatures from at least M **distinct** committee
//!   members, checked through the native sigverify precompile and instruction
//!   introspection, over exactly the `(pool, root, action, nullifier, round)`
//!   being settled;
//! - the root in those attestations must equal the root the authority published
//!   for this round.
//!
//! What that buys: an arbitrary signer can no longer settle an action, and a
//! watcher can no longer front-run a nullifier out of the mempool, because
//! neither can produce a committee signature over their own tuple. What it does
//! **not** buy: soundness. But a false attestation now requires **M colluding
//! verifiers**, not one --- the Wake's Four, generalized to M-of-N (see
//! `verify_quorum`). This is a named, quorum-bounded trust assumption, not a
//! proof --- and the root is *published* rather than computed here because the
//! canonical tree is Rescue-Prime, whose inverse S-box is not for on-chain.

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use solana_sdk_ids::ed25519_program;
use solana_sha256_hasher::hashv;

/// Domain separator for the verifier's attestation, so a signature made for
/// riverrun cannot be replayed as a signature for anything else the key signs.
/// Bumped to v2 when the message grew a recipient field, so a v1 attestation can
/// never be replayed against the payout-carrying execution.
const ATTESTATION_DOMAIN: &[u8; 16] = b"riverrun-exec-v2";
/// domain(16) + pool(32) + root(32) + action(32) + nullifier(32) + round(8) +
/// recipient(32). Binding the recipient is what stops a relayer from redirecting
/// the payout: the committee attests to *where* the value goes, not just that it goes.
const ATTESTATION_LEN: usize = 184;

/// The fixed denomination each execution pays out from the shared vault. Fixed so
/// that the amount leaving the pool reveals nothing about which member acted —
/// every payout looks identical. Small on purpose: the demo moves real value, not
/// a fortune, while the circuit is still unaudited.
const PAYOUT_LAMPORTS: u64 = 1_000_000; // 0.001 SOL

/// Layout of the native Ed25519 instruction's data (one signature): a 16-byte
/// header, then the public key, the signature, and the message.
const ED25519_HEADER_LEN: usize = 16;
const ED25519_PUBKEY_OFFSET: usize = ED25519_HEADER_LEN;
const ED25519_SIGNATURE_OFFSET: usize = ED25519_PUBKEY_OFFSET + 32;
const ED25519_MESSAGE_OFFSET: usize = ED25519_SIGNATURE_OFFSET + 64;

/// Cap on the size of the verifier committee. Named for the Wake's Four Old Men
/// (Mamalujo), who judge as a quorum and never as one; generalized to M-of-N.
const MAX_VERIFIERS: usize = 8;

declare_id!("BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az");

#[program]
pub mod riverrun_program {
    use super::*;

    /// Create a pool owned by `authority`, naming the `verifier` key whose
    /// attestation every execution must carry.
    pub fn initialize(
        ctx: Context<Initialize>,
        verifiers: Vec<Pubkey>,
        threshold: u8,
        entry_fee: u64,
        k_min: u32,
    ) -> Result<()> {
        validate_committee(&verifiers, threshold)?;
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.verifiers = verifiers;
        pool.threshold = threshold;
        pool.entry_fee = entry_fee;
        pool.k_min = k_min;
        pool.accumulator = [0u8; 32];
        pool.membership_root = [0u8; 32];
        pool.member_count = 0;
        pool.round = 0;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    /// Replace the verifier committee and threshold. Authority-gated — a
    /// compromised verifier can attest to executions that were never proven, so
    /// rotating the committee is the recovery path. Requiring a quorum means one
    /// compromised member is no longer enough.
    pub fn set_committee(
        ctx: Context<AdvanceRound>,
        verifiers: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        validate_committee(&verifiers, threshold)?;
        ctx.accounts.pool.verifiers = verifiers;
        ctx.accounts.pool.threshold = threshold;
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

        verify_quorum(
            &ctx.accounts.instructions,
            &pool.verifiers,
            pool.threshold,
            &attestation_message(
                &pool.key(),
                &root,
                &action_hash,
                &nullifier,
                round,
                &ctx.accounts.recipient.key(),
            ),
        )?;

        let record = &mut ctx.accounts.nullifier_record;
        record.round = round;
        record.bump = ctx.bumps.nullifier_record;

        // The action, made real: pay the fixed denomination from the shared vault
        // to the committed recipient. The vault PDA signs (no member does), and the
        // amount is identical for every execution, so the value leaving the pool
        // does not reveal which member acted. The recipient is bound into the
        // attestation above, so a relayer cannot redirect it.
        let pool_key = ctx.accounts.pool.key();
        let vault_seeds: &[&[u8]] = &[b"vault", pool_key.as_ref(), &[ctx.bumps.vault]];
        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.recipient.key(),
            PAYOUT_LAMPORTS,
        );
        anchor_lang::solana_program::program::invoke_signed(
            &transfer_ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            &[vault_seeds],
        )?;

        emit!(Executed {
            pool: pool_key,
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
    recipient: &Pubkey,
) -> [u8; ATTESTATION_LEN] {
    let mut m = [0u8; ATTESTATION_LEN];
    m[..16].copy_from_slice(ATTESTATION_DOMAIN);
    m[16..48].copy_from_slice(pool.as_ref());
    m[48..80].copy_from_slice(root);
    m[80..112].copy_from_slice(action_hash);
    m[112..144].copy_from_slice(nullifier);
    m[144..152].copy_from_slice(&round.to_le_bytes());
    m[152..184].copy_from_slice(recipient.as_ref());
    m
}

/// Validate a committee declaration: at least one verifier, no more than the cap,
/// a threshold in `1..=N`, and no duplicate keys.
fn validate_committee(verifiers: &[Pubkey], threshold: u8) -> Result<()> {
    let n = verifiers.len();
    require!((1..=MAX_VERIFIERS).contains(&n), PoolError::InvalidCommittee);
    require!(threshold >= 1 && (threshold as usize) <= n, PoolError::InvalidCommittee);
    for i in 0..n {
        for j in (i + 1)..n {
            require_keys_neq!(verifiers[i], verifiers[j], PoolError::InvalidCommittee);
        }
    }
    Ok(())
}

/// If `ix` is a self-contained native Ed25519 sigverify instruction over exactly
/// `expected`, return the signer's public key bytes; otherwise `None`.
///
/// The signature itself is checked by the precompile, not here: if the runtime
/// executes the transaction, the signature is valid. What is checked is that the
/// precompile was asked about *this* message, and that the key and message live
/// inside the sigverify instruction's own data (source index `0xFFFF`) rather than
/// being read from elsewhere in the transaction.
fn attestation_signer(
    ix: &anchor_lang::solana_program::instruction::Instruction,
    expected: &[u8; ATTESTATION_LEN],
) -> Option<[u8; 32]> {
    if ix.program_id != ed25519_program::ID {
        return None;
    }
    let data = &ix.data;
    if data.len() != ED25519_MESSAGE_OFFSET + ATTESTATION_LEN {
        return None;
    }
    if data[0] != 1 || data[1] != 0 {
        return None;
    }
    let field = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
    let self_contained = field(2) as usize == ED25519_SIGNATURE_OFFSET
        && field(6) as usize == ED25519_PUBKEY_OFFSET
        && field(10) as usize == ED25519_MESSAGE_OFFSET
        && field(12) as usize == ATTESTATION_LEN
        && field(4) == u16::MAX
        && field(8) == u16::MAX
        && field(14) == u16::MAX;
    if !self_contained {
        return None;
    }
    if &data[ED25519_MESSAGE_OFFSET..] != expected.as_ref() {
        return None;
    }
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&data[ED25519_PUBKEY_OFFSET..ED25519_PUBKEY_OFFSET + 32]);
    Some(signer)
}

/// Require that the transaction carries attestations over `expected` from at least
/// `threshold` **distinct** members of the verifier committee.
///
/// This is the Wake's Four (Mamalujo) --- the annalists who judge and record as a
/// quorum, none authoritative alone. "Impassable tissue of improbable liyers"
/// (FW III.4): no single layer/liar is trusted; the truth is what enough of them
/// attest. A false attestation now needs `threshold` colluding verifiers, not one.
/// The sigverify instructions must precede this instruction; each one the runtime
/// accepted carries a valid signature, and this scans them for committee members
/// signing exactly the settled tuple, counting each member once.
fn verify_quorum(
    instructions: &UncheckedAccount,
    verifiers: &[Pubkey],
    threshold: u8,
    expected: &[u8; ATTESTATION_LEN],
) -> Result<()> {
    let index = load_current_index_checked(instructions)?;
    let mut counted = [false; MAX_VERIFIERS];
    let mut have = 0u8;

    for i in 0..index {
        let Ok(ix) = load_instruction_at_checked(i as usize, instructions) else {
            continue;
        };
        let Some(signer) = attestation_signer(&ix, expected) else {
            continue;
        };
        // a committee member we have not already counted this transaction
        if let Some(slot) = verifiers.iter().position(|v| v.as_ref() == signer) {
            if !counted[slot] {
                counted[slot] = true;
                have += 1;
            }
        }
    }

    require!(have >= threshold, PoolError::NotEnoughAttestations);
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
    /// The verifier committee — the Wake's Four, generalized. Each attests that it
    /// checked the off-chain membership proof; a quorum of `threshold` of them is
    /// trusted, no single one.
    pub verifiers: Vec<Pubkey>,
    /// How many distinct committee members must sign an execution (M of N).
    pub threshold: u8,
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
    pub const SPACE: usize = 8 + 32 + (4 + MAX_VERIFIERS * 32) + 1 + 32 + 32 + 4 + 8 + 1 + 8 + 4;
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
    /// The shared vault the payout leaves from. System-owned PDA, seeded by the
    /// pool, so the program can sign the transfer with `invoke_signed` and no
    /// member's key is involved. Funded by members' deposits (equal, so the
    /// outflow is unlinkable).
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump)]
    pub vault: SystemAccount<'info>,
    /// Where the action sends the value. Its key is bound into the attestation, so
    /// the committee vouches for this exact recipient and a relayer cannot swap it.
    /// CHECK: identity is enforced cryptographically via the attestation, not by type.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
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
    #[msg("fewer than the required threshold of committee verifiers attested")]
    NotEnoughAttestations,
    #[msg("the verifier committee is empty, too large, has a bad threshold, or has duplicates")]
    InvalidCommittee,
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
