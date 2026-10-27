//! Staged verification of the crowd proofs: the same verifier, cut at its
//! Fiat-Shamir seams so it can run across several Solana transactions.
//!
//! A production crowd proof (12 FRI queries, blowup 128, 128 rows) is ~100 KB
//! and its verification does not fit one transaction's 1.4M CU. Nothing about
//! verification is inherently sequential across those limits, though: every
//! challenge the verifier will ever use is derived from the transcript BEFORE
//! the first query is opened (`p3_circle`'s FRI never touches the challenger
//! inside its query loop). So the verifier splits, exactly, into
//!
//! 1. **transcript** ([`stage_transcript`]): shape checks, observe the instance,
//!    `alpha`, `zeta`, the PCS batch challenge, the bivariate beta, every FRI
//!    beta, the commit- and query-phase proof-of-work checks, and every query
//!    index. Output: a [`Transcript`], which a program persists in its own
//!    account (never accepted from a client).
//! 2. **quotient** ([`stage_quotient`]): `quotient(zeta)` recomposed from the
//!    opened chunks; a program persists the one extension element.
//! 3. **out-of-domain** ([`stage_ood`]): `constraints(zeta) / Z_H(zeta) ==
//!    quotient(zeta)` against the persisted quotient and `(alpha, zeta)`.
//!    (On SBF the recomposition and the constraint evaluation do not fit one
//!    transaction together for the binding AIR, so they are two stages.)
//! 4. **queries** ([`stage_queries`]): for each query, the input MMCS openings,
//!    the DEEP reduction, the first-layer fold, the FRI fold chain and the
//!    final-polynomial check. Pure functions of the transcript, the header and
//!    that one query proof, so any batch of queries can run in any transaction.
//!
//! The monolithic verifier (`p3_uni_stark::verify_with_known_quotient_chunks`
//! over `HidingCirclePcs`) is, after the vendored `[staged-patch]` changes,
//! literally the composition of the same functions: `verifier_shape`,
//! `verifier_transcript`, `opening_claims`, the PCS's `verify_staged_setup`,
//! one `verify_staged_query` per query, and `verify_ood`. A proof is accepted
//! by the staged path iff the transcript stage succeeds, the OOD stage
//! succeeds, and every query index `0..num_queries` passes its query stage,
//! which is exactly the monolithic acceptance condition. The tests in this
//! module pin that on honest proofs, on targeted tampering, and on a sweep of
//! single-byte flips across a whole proof.
//!
//! ## The wire format and what "the same proof" means
//!
//! A staged verifier cannot afford to deserialize the whole proof in every
//! transaction (measured on-chain cost of that is in
//! `programs/riverrun-m31-verifier`), so the bytes are cut, not re-encoded:
//! the buffer holds exactly `CrowdBindingProof::to_bytes()` (bincode), and
//! [`index_proof`] walks it once, reading only length prefixes, to find where
//! each query proof starts and ends. Then:
//!
//! - the **header** is the same bytes with the query proofs spliced out (their
//!   `u64` count rewritten to 0), deserialized as an ordinary `Proof`;
//! - **query `i`** is its own byte span, deserialized as one `CircleQueryProof`
//!   and required to consume that span exactly.
//!
//! bincode is a sequential, prefix-free decoder, and Mersenne-31 decoding
//! rejects non-canonical limbs, so when every span decodes with exact
//! consumption the (header, queries) pair is precisely the `Proof` that
//! `bincode::deserialize` would have produced from the whole buffer. A wrong
//! index cannot smuggle a different proof through: it makes a span fail to
//! decode or fail exact consumption, and the stage rejects. (Soundness does not
//! even depend on that argument: whatever the staged path accepts, it accepts
//! only after running every monolithic check on the decoded structure.)

extern crate alloc;

use alloc::vec::Vec;

use bincode::Options;
use p3_air::Air;
use p3_circle::{CircleAlphaTables, CircleInputProof, CircleQueryProof, CircleStagedSetup, FriSetup};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::{
    ood_quotient, opening_claims, verifier_shape, verifier_transcript, verify_ood_against, Proof,
    StarkGenericConfig, VerifierConstraintFolder,
};

use crate::binding::CONTEXT_LEN;
use crate::crowd::{
    CrowdBindingAir, CrowdMembershipAir, CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS,
    CROWD_MEMBERSHIP_LOG_NUM_QUOTIENT_CHUNKS,
};
use crate::membership::DIGEST_LEN;
use crate::zk::{
    make_zk_config_bound, rejoin_random_openings, Challenge, Challenger, Seed, Val, ZkChallengeMmcs,
    ZkConfig, ZkValMmcs,
};

/// One query proof of a crowd proof, deserializable on its own.
pub type ZkQueryProof = CircleQueryProof<
    Challenge,
    ZkChallengeMmcs,
    CircleInputProof<Val, Challenge, ZkValMmcs, ZkChallengeMmcs>,
>;

/// The decoded proof minus its query proofs (their vector is empty).
pub type ZkProofHeader = Proof<ZkConfig>;

/// Which crowd relation a proof is for. Fixes the AIR and its pinned
/// quotient-chunk count; a program constant per buffer, never inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// `CrowdBindingAir`: publics `action(8) | round(8) | C(8) | nullifier(8)`.
    Binding,
    /// `CrowdMembershipAir`: publics `C(8) | root(8)`.
    Membership,
}

impl Relation {
    pub const fn num_public_values(self) -> usize {
        match self {
            Relation::Binding => 2 * CONTEXT_LEN + 2 * DIGEST_LEN,
            Relation::Membership => 2 * DIGEST_LEN,
        }
    }
}

/// What a verifier runs with: the FRI parameters (program constants
/// on-chain) and, for a recipient-bound proof, the recipient its transcript
/// was seeded with (`zk::make_zk_config_bound`). On-chain the recipient comes
/// from the buffer's own `B_RECIPIENT`, which is exactly what makes that field
/// proof-bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub num_queries: usize,
    pub log_blowup: usize,
    pub recipient: Option<[u8; 32]>,
}

/// Upper bound on query proofs an index will walk; anything larger is
/// rejected before any loop runs. The FRI setup separately requires the count
/// to equal `num_queries` exactly.
pub const MAX_QUERY_PROOFS: usize = 64;

/// Public values as field elements from canonical u32 limbs. `None` if any
/// limb is not canonical (`>= 2^31 - 1`). The monolithic API reduces mod p
/// instead; a byte-keyed consumer (every nullifier burn) must not, which is
/// why the staged path is strict here (see `crowd::canonicity`).
pub fn publics_from_limbs(limbs: &[u32]) -> Option<Vec<Val>> {
    const P: u32 = (1 << 31) - 1;
    limbs
        .iter()
        .map(|&v| (v < P).then(|| Val::from_u32(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// The byte index.
// ---------------------------------------------------------------------------

/// Where the query proofs sit inside a bincode-serialized crowd proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofIndex {
    /// Offset of the `u64` length prefix of `fri_proof.query_proofs`.
    pub queries_at: usize,
    /// `n + 1` boundaries for `n` query proofs: query `i` is
    /// `bounds[i]..bounds[i + 1]`. `bounds[0] == queries_at + 8`; the suffix
    /// (`final_poly`, `pow_witness`, `degree_bits`) starts at `bounds[n]`.
    pub bounds: Vec<usize>,
    /// One past the proof's last byte (the end of `degree_bits`). Bytes after
    /// it are ignored, as `bincode::deserialize` ignores trailing bytes.
    pub end: usize,
}

impl ProofIndex {
    pub fn num_query_proofs(&self) -> usize {
        self.bounds.len() - 1
    }
}

const VAL_BYTES: usize = 4;
const EXT_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const LEN_BYTES: usize = 8;

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        (end <= self.b.len()).then(|| self.pos = end)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.b.get(self.pos..self.pos.checked_add(8)?)?;
        self.pos += 8;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }
    /// A vector length, refused unless `n * min_elem` bytes could still follow.
    fn len(&mut self, min_elem: usize) -> Option<usize> {
        let n = usize::try_from(self.u64()?).ok()?;
        (n.checked_mul(min_elem)? <= self.b.len() - self.pos).then_some(n)
    }
    fn vec_fixed(&mut self, elem: usize) -> Option<()> {
        let n = self.len(elem)?;
        self.skip(n * elem)
    }
    fn vec_with(&mut self, min_elem: usize, mut f: impl FnMut(&mut Self) -> Option<()>) -> Option<()> {
        for _ in 0..self.len(min_elem)? {
            f(self)?;
        }
        Some(())
    }
    fn option(&mut self, f: impl FnOnce(&mut Self) -> Option<()>) -> Option<()> {
        match self.u8()? {
            0 => Some(()),
            1 => f(self),
            _ => None,
        }
    }
    /// `MerkleCap<_, [u8; 32]>`: a `Vec` of digests (its marker is zero bytes).
    fn commitment(&mut self) -> Option<()> {
        self.vec_fixed(DIGEST_BYTES)
    }
    /// A hiding-MMCS opening proof: `(salts: Vec<Vec<Val>>, siblings: Vec<[u8; 32]>)`.
    fn mmcs_proof(&mut self) -> Option<()> {
        self.vec_with(LEN_BYTES, |c| c.vec_fixed(VAL_BYTES))?;
        self.vec_fixed(DIGEST_BYTES)
    }
    /// `CircleQueryProof`: input openings (one `BatchOpening` per committed
    /// round), first-layer siblings and proof, then one commit-phase step per
    /// FRI round (`log_arity: u8`, sibling values, opening proof).
    fn query_proof(&mut self) -> Option<()> {
        self.vec_with(2 * LEN_BYTES, |c| {
            c.vec_with(LEN_BYTES, |c| c.vec_fixed(VAL_BYTES))?;
            c.mmcs_proof()
        })?;
        self.vec_fixed(EXT_BYTES)?;
        self.mmcs_proof()?;
        self.vec_with(1 + 3 * LEN_BYTES, |c| {
            c.skip(1)?;
            c.vec_fixed(EXT_BYTES)?;
            c.mmcs_proof()
        })
    }
}

/// Walk a bincode-serialized crowd proof (`to_bytes()` of either relation) and
/// locate its query proofs. Reads length prefixes only; validates nothing about
/// content (decoding does that). `None` on any truncation or absurd length.
pub fn index_proof(bytes: &[u8]) -> Option<ProofIndex> {
    let mut c = Cursor { b: bytes, pos: 0 };
    // commitments: trace, quotient_chunks, Option<random>
    c.commitment()?;
    c.commitment()?;
    c.option(|c| c.commitment())?;
    // opened_values: trace_local, trace_next?, preprocessed_local?,
    // preprocessed_next?, quotient_chunks, random?
    c.vec_fixed(EXT_BYTES)?;
    for _ in 0..3 {
        c.option(|c| c.vec_fixed(EXT_BYTES))?;
    }
    c.vec_with(LEN_BYTES, |c| c.vec_fixed(EXT_BYTES))?;
    c.option(|c| c.vec_fixed(EXT_BYTES))?;
    // opening_proof.0: the random-codeword openings, round/matrix/point/values
    c.vec_with(LEN_BYTES, |c| {
        c.vec_with(LEN_BYTES, |c| c.vec_with(LEN_BYTES, |c| c.vec_fixed(EXT_BYTES)))
    })?;
    // opening_proof.1: CirclePcsProof
    c.commitment()?; // first_layer_commitment
    c.vec_fixed(EXT_BYTES)?; // lambdas
    c.vec_with(LEN_BYTES, |c| c.commitment())?; // commit_phase_commits
    c.vec_fixed(VAL_BYTES)?; // commit_pow_witnesses
    let queries_at = c.pos;
    let n = c.len(LEN_BYTES)?;
    if n > MAX_QUERY_PROOFS {
        return None;
    }
    let mut bounds = Vec::with_capacity(n + 1);
    for _ in 0..n {
        bounds.push(c.pos);
        c.query_proof()?;
    }
    bounds.push(c.pos);
    c.skip(EXT_BYTES)?; // final_poly
    c.skip(VAL_BYTES)?; // pow_witness
    c.skip(LEN_BYTES)?; // degree_bits
    Some(ProofIndex { queries_at, bounds, end: c.pos })
}

fn exact() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

/// The proof with its query proofs spliced out: `bytes[..queries_at] ‖ 0u64 ‖
/// bytes[suffix..end]`, decoded exactly.
pub fn decode_header(bytes: &[u8], idx: &ProofIndex) -> Option<ZkProofHeader> {
    let suffix = *idx.bounds.last()?;
    let tail = bytes.get(suffix..idx.end)?;
    let mut spliced = Vec::with_capacity(idx.queries_at + LEN_BYTES + tail.len());
    spliced.extend_from_slice(bytes.get(..idx.queries_at)?);
    spliced.extend_from_slice(&0u64.to_le_bytes());
    spliced.extend_from_slice(tail);
    exact().deserialize(&spliced).ok()
}

/// Query proof `i`, decoded from exactly its span.
pub fn decode_query(bytes: &[u8], idx: &ProofIndex, i: usize) -> Option<ZkQueryProof> {
    let span = bytes.get(*idx.bounds.get(i)?..*idx.bounds.get(i + 1)?)?;
    exact().deserialize(span).ok()
}

// ---------------------------------------------------------------------------
// The persisted transcript.
// ---------------------------------------------------------------------------

/// Every Fiat-Shamir value the later stages need. Written by the transcript
/// stage into program-owned state; trusted only because only the program
/// writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// uni-stark constraint-combination challenge.
    pub alpha: Challenge,
    /// Out-of-domain point.
    pub zeta: Challenge,
    /// Circle PCS batch challenge.
    pub pcs_alpha: Challenge,
    /// First-layer (bivariate) fold challenge.
    pub bivariate_beta: Challenge,
    pub log_global_max_height: u32,
    pub log_max_height: u32,
    /// One per FRI commit-phase round.
    pub betas: Vec<Challenge>,
    /// One per query, in transcript order.
    pub indices: Vec<u32>,
    /// One per claimed evaluation, (batch, matrix, point) order: the
    /// query-independent half of every DEEP row reduction,
    /// `sum_k pcs_alpha^k * p_zeta[k]` (`CircleStagedSetup::claim_sums`).
    pub claim_sums: Vec<Challenge>,
}

/// One extension element as 16 bytes (four canonical u32 LE limbs), the
/// format every persisted challenge uses.
pub fn encode_ext(x: Challenge) -> [u8; 16] {
    let mut v = Vec::with_capacity(16);
    put_ext(&mut v, x);
    v.try_into().expect("16 bytes")
}

/// The inverse of [`encode_ext`].
pub fn decode_ext(b: &[u8; 16]) -> Option<Challenge> {
    get_ext(b)
}

fn put_ext(out: &mut Vec<u8>, x: Challenge) {
    for v in <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x) {
        out.extend_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
}

fn get_ext(b: &[u8]) -> Option<Challenge> {
    let vals: [Val; 4] = core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]))
    });
    <Challenge as BasedVectorSpace<Val>>::from_basis_coefficients_slice(&vals)
}

impl Transcript {
    /// Encoded size for `rounds` FRI rounds, `queries` queries and `claims`
    /// claimed evaluations.
    pub const fn encoded_len(rounds: usize, queries: usize, claims: usize) -> usize {
        4 * EXT_BYTES + 5 * 4 + rounds * EXT_BYTES + queries * 4 + claims * EXT_BYTES
    }

    /// `alpha | zeta | pcs_alpha | bivariate_beta | lgmh u32 | lmh u32 |
    /// n_betas u32 | n_indices u32 | n_claims u32 | betas | indices |
    /// claim_sums`, all little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::encoded_len(
            self.betas.len(),
            self.indices.len(),
            self.claim_sums.len(),
        ));
        for x in [self.alpha, self.zeta, self.pcs_alpha, self.bivariate_beta] {
            put_ext(&mut out, x);
        }
        out.extend_from_slice(&self.log_global_max_height.to_le_bytes());
        out.extend_from_slice(&self.log_max_height.to_le_bytes());
        out.extend_from_slice(&(self.betas.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.indices.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.claim_sums.len() as u32).to_le_bytes());
        for b in &self.betas {
            put_ext(&mut out, *b);
        }
        for i in &self.indices {
            out.extend_from_slice(&i.to_le_bytes());
        }
        for s in &self.claim_sums {
            put_ext(&mut out, *s);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let u32_at = |o: usize| -> Option<u32> { Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?)) };
        let ext_at = |o: usize| -> Option<Challenge> { get_ext(b.get(o..o + EXT_BYTES)?) };
        let head = 4 * EXT_BYTES;
        let n_betas = u32_at(head + 8)? as usize;
        let n_idx = u32_at(head + 12)? as usize;
        let n_claims = u32_at(head + 16)? as usize;
        if n_betas > 32 || n_idx > MAX_QUERY_PROOFS || n_claims > 64 {
            return None;
        }
        let betas_at = head + 20;
        let idx_at = betas_at + n_betas * EXT_BYTES;
        let claims_at = idx_at + 4 * n_idx;
        Some(Self {
            alpha: ext_at(0)?,
            zeta: ext_at(EXT_BYTES)?,
            pcs_alpha: ext_at(2 * EXT_BYTES)?,
            bivariate_beta: ext_at(3 * EXT_BYTES)?,
            log_global_max_height: u32_at(head)?,
            log_max_height: u32_at(head + 4)?,
            betas: (0..n_betas).map(|i| ext_at(betas_at + i * EXT_BYTES)).collect::<Option<_>>()?,
            indices: (0..n_idx).map(|i| u32_at(idx_at + 4 * i)).collect::<Option<_>>()?,
            claim_sums: (0..n_claims)
                .map(|i| ext_at(claims_at + i * EXT_BYTES))
                .collect::<Option<_>>()?,
        })
    }

    fn pcs_setup(&self) -> CircleStagedSetup<Challenge> {
        CircleStagedSetup {
            alpha: self.pcs_alpha,
            bivariate_beta: self.bivariate_beta,
            log_global_max_height: self.log_global_max_height as usize,
            fri: FriSetup {
                betas: self.betas.clone(),
                log_max_height: self.log_max_height as usize,
                indices: self.indices.iter().map(|&i| i as usize).collect(),
            },
            claim_sums: self.claim_sums.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// The stages.
// ---------------------------------------------------------------------------

/// `[cu-trace]` a labeled `sol_log_compute_units` probe, compiled only into a
/// Solana build with the measurement feature on. Zero effect otherwise.
macro_rules! cu {
    ($label:literal) => {
        #[cfg(all(target_os = "solana", feature = "cu-trace"))]
        {
            solana_program::msg!($label);
            solana_program::log::sol_log_compute_units();
        }
    };
}

fn config(p: Params) -> ZkConfig {
    // The verifier never draws from the prover-side generators; the seed is
    // irrelevant to verification (same as `verify_binding_crowd`).
    make_zk_config_bound(p.num_queries, p.log_blowup, Seed::reproducible(0), p.recipient.as_ref())
}

macro_rules! with_air {
    ($rel:expr, |$air:ident, $lnqc:ident| $body:expr) => {
        match $rel {
            Relation::Binding => {
                let $air = CrowdBindingAir::new();
                let $lnqc = CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS;
                $body
            }
            Relation::Membership => {
                let $air = CrowdMembershipAir::new();
                let $lnqc = CROWD_MEMBERSHIP_LOG_NUM_QUOTIENT_CHUNKS;
                $body
            }
        }
    };
}

/// Stage 1: the whole transcript. `num_query_proofs` is
/// [`ProofIndex::num_query_proofs`]; the header itself carries none.
pub fn stage_transcript(
    rel: Relation,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    num_query_proofs: usize,
) -> Option<Transcript> {
    with_air!(rel, |air, lnqc| transcript_air(&air, lnqc, p, header, publics, num_query_proofs))
}

fn transcript_air<A>(
    air: &A,
    lnqc: usize,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    num_query_proofs: usize,
) -> Option<Transcript>
where
    A: for<'a> Air<VerifierConstraintFolder<'a, ZkConfig>>,
{
    let config = config(p);
    let shape = verifier_shape(&config, air, header, publics, None, lnqc).ok()?;
    cu!("transcript: shape done");
    let (mut challenger, alpha, zeta) = verifier_transcript(&config, header, &shape, publics).ok()?;
    cu!("transcript: alpha, zeta done");
    let mut rounds = opening_claims(header, &shape, zeta).ok()?;
    let (rand, inner_proof) = &header.opening_proof;
    rejoin_random_openings::<_, _, _, (), ()>(&mut rounds, rand).ok()?;
    cu!("transcript: claims + rejoin done");
    let pcs = config
        .pcs()
        .inner
        .verify_staged_setup(&rounds, inner_proof, num_query_proofs, &mut challenger)
        .ok()?;
    cu!("transcript: PCS + FRI setup done");
    Some(Transcript {
        alpha,
        zeta,
        pcs_alpha: pcs.alpha,
        bivariate_beta: pcs.bivariate_beta,
        log_global_max_height: pcs.log_global_max_height as u32,
        log_max_height: pcs.fri.log_max_height as u32,
        betas: pcs.fri.betas,
        indices: pcs.fri.indices.iter().map(|&i| i as u32).collect(),
        claim_sums: pcs.claim_sums,
    })
}

/// Stage 2: `quotient(zeta)` from the opened chunks, for the program to
/// persist. `None` if the header does not have the AIR's shape.
pub fn stage_quotient(
    rel: Relation,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    t: &Transcript,
) -> Option<Challenge> {
    with_air!(rel, |air, lnqc| {
        let config = config(p);
        let shape = verifier_shape(&config, &air, header, publics, None, lnqc).ok()?;
        cu!("quotient: shape done");
        let q = ood_quotient(header, &shape, t.zeta);
        cu!("quotient: recomposed");
        Some(q)
    })
}

/// Stage 3: the out-of-domain constraint check, from the persisted
/// `(alpha, zeta)` and the persisted `quotient` of stage 2.
pub fn stage_ood(
    rel: Relation,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    t: &Transcript,
    quotient: Challenge,
) -> bool {
    with_air!(rel, |air, lnqc| {
        let config = config(p);
        match verifier_shape(&config, &air, header, publics, None, lnqc) {
            Ok(shape) => {
                cu!("ood: shape done");
                let ok = verify_ood_against(&air, header, &shape, publics, t.alpha, t.zeta, quotient)
                    .is_ok();
                cu!("ood: constraints checked");
                ok
            }
            Err(_) => false,
        }
    })
}

/// Stage 4: a batch of queries, each `(query position, its query proof)`.
/// The opening claims and alpha tables are rebuilt once per call from the
/// persisted transcript; every query is then checked independently.
pub fn stage_queries(
    rel: Relation,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    t: &Transcript,
    queries: &[(usize, ZkQueryProof)],
) -> bool {
    with_air!(rel, |air, lnqc| queries_air(&air, lnqc, p, header, publics, t, queries))
}

fn queries_air<A>(
    air: &A,
    lnqc: usize,
    p: Params,
    header: &ZkProofHeader,
    publics: &[Val],
    t: &Transcript,
    queries: &[(usize, ZkQueryProof)],
) -> bool
where
    A: for<'a> Air<VerifierConstraintFolder<'a, ZkConfig>>,
{
    let config = config(p);
    let Ok(shape) = verifier_shape(&config, air, header, publics, None, lnqc) else {
        return false;
    };
    let Ok(mut rounds) = opening_claims(header, &shape, t.zeta) else {
        return false;
    };
    let (rand, inner_proof) = &header.opening_proof;
    if rejoin_random_openings::<_, _, _, (), ()>(&mut rounds, rand).is_err() {
        return false;
    }
    cu!("queries: shape + claims + rejoin done");
    let setup = t.pcs_setup();
    let tables = CircleAlphaTables::new(&rounds, setup.alpha);
    cu!("queries: alpha tables done");
    let pcs = &config.pcs().inner;
    queries.iter().all(|(q, qp)| {
        pcs.verify_staged_query::<Challenge, Challenger>(&rounds, inner_proof, &setup, &tables, *q, qp)
            .is_ok()
    })
}

/// Every stage, in one process, over raw proof bytes: the reference driver the
/// tests compare against the monolithic verifier, and a template for what an
/// on-chain program does across transactions. `batch` queries per stage-3 call.
pub fn verify_staged_bytes(
    rel: Relation,
    p: Params,
    bytes: &[u8],
    publics: &[Val],
    batch: usize,
) -> bool {
    let Some(idx) = index_proof(bytes) else { return false };
    let Some(header) = decode_header(bytes, &idx) else { return false };
    let Some(t) = stage_transcript(rel, p, &header, publics, idx.num_query_proofs()) else {
        return false;
    };
    // Round-trip the transcript through its persisted encoding, as a program does.
    let Some(t) = Transcript::decode(&t.encode()) else { return false };
    let Some(quotient) = stage_quotient(rel, p, &header, publics, &t) else { return false };
    let Some(quotient) = decode_ext(&encode_ext(quotient)) else { return false };
    if !stage_ood(rel, p, &header, publics, &t, quotient) {
        return false;
    }
    let n = idx.num_query_proofs();
    let mut q = 0;
    while q < n {
        let end = core::cmp::min(q + batch.max(1), n);
        let mut batch_proofs = Vec::with_capacity(end - q);
        for i in q..end {
            let Some(qp) = decode_query(bytes, &idx, i) else { return false };
            batch_proofs.push((i, qp));
        }
        if !stage_queries(rel, p, &header, publics, &t, &batch_proofs) {
            return false;
        }
        q = end;
    }
    true
}

#[cfg(test)]
mod staged_tests;
