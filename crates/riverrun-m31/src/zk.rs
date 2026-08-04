//! The hiding (zero-knowledge) configuration: `HidingCirclePcs`, a circle-domain
//! port of Plonky3's `HidingFriPcs`, and the binding relation proved under it.
//!
//! `docs/PRIVACY.md` (riverrun-soroban) names the two missing pieces of witness
//! hiding: the composition that makes random values part of the committed
//! polynomial, and an AIR that tolerates them. This module supplies the first
//! and dissolves the second.
//!
//! ## The circle-domain port, stated precisely
//!
//! `HidingFriPcs` (p3-fri 0.6.2, `hiding_pcs.rs`) doubles the trace by
//! interleaving random rows: the real trace lands on the even indices of a
//! doubled multiplicative coset, which works because the even powers of a group
//! of order `2h` form its order-`h` subgroup. Circle domains refuse that move:
//! the natural-order alternating rows of a twin coset are its two half-cosets,
//! which are not negation-closed, so they are not twin cosets and carry no
//! low-degree vanishing polynomial. The standard domains of sizes `N` and `2N`
//! are even *disjoint* (points of order `4N` vs `2N`).
//!
//! The port therefore keeps the algebra and drops the index trick. What the
//! two-adic interleaving actually constructs is
//!
//! ```text
//!     T'  =  T  +  Z_D · R
//! ```
//!
//! the trace polynomial plus a uniformly random polynomial of the trace's own
//! dimension, multiplied by the vanishing polynomial of the trace domain `D`.
//! That form ports directly:
//!
//! - `Z_D(P) = v_n(x_P) - v_n(x_shift)` is closed-form on any twin coset
//!   (`CircleDomain::vanishing_poly`), `O(log)` per point;
//! - `D = standard(log_n)` is disjoint from the committed domain
//!   `standard(log_n + 1)` and from every LDE domain above it, so `Z_D` never
//!   vanishes at an opened point: each of up to `N` openings of `T'` is masked
//!   by an independent uniform value;
//! - `T'` restricted to `D` **is** `T`, so constraints keep holding on `D` and
//!   the AIR does not change at all. The "AIR that tolerates random rows"
//!   turns out not to be needed: the random degrees of freedom live above the
//!   constraint domain, not inside it.
//!
//! The other mechanisms of `HidingFriPcs` are domain-generic and are ported
//! with one adaptation each:
//!
//! - quotient chunks are randomized as `q'_i = q_i + Z_{D_i} · t_i` with the
//!   last chunk correcting the sum so the verifier's Lagrange recomposition at
//!   `zeta` is unchanged (Section 4.2 of <https://eprint.iacr.org/2024/1037>);
//!   the two-adic code builds `Z·t` from the closed form `(s·u)^h - 1` in
//!   coefficient space, which has no circle analogue, so here `Z_{D_i}` is
//!   evaluated pointwise over the chunk LDE instead;
//! - `num_random_codewords` random columns are appended to every committed
//!   matrix and their openings drained into the proof, so the caller sees
//!   exactly `air.width()` columns;
//! - a fully random polynomial is committed alongside the trace and folded
//!   into the FRI batch (`get_opt_randomization_poly_commitment`).
//!
//! Like upstream's, this construction is **statistically** zero-knowledge, not
//! perfect: `p3-uni-stark`'s own comment on the randomization commitment says
//! as much, and the claim is inherited here, not strengthened.
//!
//! ## What this module does NOT do
//!
//! Witness-hiding alone is half the fix. The leaf is still a public input; the
//! unlinkability half (commit to the leaf, compose on the commitment) is
//! separate work tracked in `docs/PRIVACY.md`.
//!
//! ## The randomness is part of the construction, not a detail around it
//!
//! An earlier version of this module drew its leaf salts and blinding
//! polynomials from a `SplitMix64` seeded by a `u64`. That is not a
//! configuration wart, it is a break: the salts are published inside the proof,
//! `SplitMix64`'s state inverts from a single output, and the two streams were
//! seeded by values a fixed XOR apart. Recovering one recovered the other, and
//! subtracting `Z_D · R` from the published openings recovered the witness the
//! proof was built to hide. See [`Seed`] for the attack as an audit stated it.
//!
//! The generator is now ChaCha20 ([`Csprng`]) over a 256-bit [`Seed`]. The salt
//! stream and the blinding stream are separated by ChaCha20's own nonce field,
//! so their independence is the cipher's PRF assumption and not a construction
//! this crate invented — an intermediate version *did* invent one, and
//! [`Csprng::from_seed`] records why it was worse than it looked.
//!
//! This is prover-side only: no verifier draws from either generator, so
//! nothing about it changed on-chain and no contract needed redeploying.

extern crate alloc;

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger, HashChallenger, SerializingChallenger32};
use p3_circle::{cfft_permute_slice, CfftPerm, CircleDomain, CircleEvaluations, CirclePcs, CirclePcsProof};
use p3_commit::{BuildPeriodicLdeTableFast, ExtensionMmcs, Mmcs, OpenedValues, Pcs, PeriodicLdeTable, PolynomialSpace};
use p3_field::extension::{BinomialExtensionField, ComplexExtendable};
use p3_field::{batch_multiplicative_inverse, BasedVectorSpace, ExtensionField, PrimeCharacteristicRing};
use p3_fri::verifier::FriError;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixCow};
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::row_index_mapped::RowIndexMappedView;
use p3_matrix::Matrix;
use p3_mersenne_31::Mersenne31;
use p3_poseidon2_air::{generate_vectorized_trace_rows, RoundConstants};
use p3_uni_stark::{prove, verify_with_known_quotient_chunks, Proof, StarkConfig};
use p3_util::log2_strict_usize;
use rand10::distr::{Distribution, StandardUniform};
use rand10::{Rng, RngExt};
use spin::Mutex;

use crate::binding::{public_values_for_hiding, BindingAir, CONTEXT_LEN, SECRET_LEN};
use crate::membership::DIGEST_LEN;
use crate::permutation::{permute, WIDTH};

/// The 256-bit seed behind every hiding value a proof carries.
///
/// This type exists because its predecessor was a bare `u64`, and the width of
/// that argument was the real security parameter of the whole hiding path. An
/// adversarial audit (`docs/AUDIT-2026-08-03.md`, C1) established the attack:
/// the leaf salts are *published inside the proof*
/// (`p3-merkle-tree`'s `BatchOpening::new(openings, (salts, siblings))`), and
/// the generator drawing them was a `SplitMix64` whose state inverts from a
/// single output. Recovering the salt stream recovered the blinding stream,
/// and subtracting `Z_D · R` from the published openings recovered the trace —
/// which `examples/privacy_audit.rs` shows is overdetermined for interpolation.
/// The witness came back out of a proof that claimed to hide it.
///
/// Replacing the generator without widening the seed would have moved the work
/// from roughly 2^33 to 2^64 and left the property still unclaimed, so both
/// changed together. There is deliberately no `From<u64>`: a caller that has
/// only 64 bits of entropy must say so at the call site, in
/// [`Seed::reproducible`], rather than have it inferred.
#[derive(Clone, Copy)]
pub struct Seed([u8; 32]);

impl Seed {
    /// A seed from caller-supplied bytes. The caller owns the guarantee that
    /// they are uniform; [`Seed::from_os`] is the way to get that for free.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A seed stretched from 64 bits, for fixtures and measurements that must
    /// reproduce byte-for-byte across runs.
    ///
    /// **This carries 64 bits of entropy, not 256.** It is sound — soundness
    /// does not depend on the prover's randomness at all — but it is not
    /// hiding against an adversary willing to spend 2^64. Never reach for it
    /// on a path whose output a real counterparty will see.
    pub const fn reproducible(seed: u64) -> Self {
        let b = seed.to_le_bytes();
        Self([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[0], b[1], b[2], b[3], b[4], b[5],
            b[6], b[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
        ])
    }

}

/// Stream indices separating the two uses of one seed. ChaCha20's nonce field
/// exists for exactly this, so the independence of the two keystreams is the
/// cipher's own PRF assumption rather than anything this crate invents.
const STREAM_SALTS: u64 = 1;
const STREAM_BLINDING: u64 = 2;

/// The cryptographic generator behind the leaf salts and the blinding
/// polynomials. ChaCha20, from `rand_chacha`, wrapped only to satisfy the
/// `Rng + Clone + Send` shape `p3-merkle-tree` and `HidingCirclePcs` require.
///
/// The predecessor, [`crate::hiding::SplitMix64`], remains in the codebase for
/// the cost instrument that measures the hiding machinery's price, where
/// reproducibility matters and secrecy does not. It must never come back here.
#[derive(Clone)]
pub struct Csprng(rand_chacha::ChaCha20Rng);

impl Csprng {
    /// The generator for one use of `seed`, separated from the other uses by
    /// ChaCha20's stream index.
    ///
    /// The first version of this fix derived a second seed by XOR-ing a tag in
    /// and pushing the result through the Poseidon2 permutation. That was worse
    /// than it looked, for two reasons worth recording. The permutation is not
    /// a key-derivation function — there is no sponge padding and no capacity
    /// separation, so nothing standard backs the claim that its output is a
    /// uniform key. And the arithmetic leaked: eight Mersenne-31 limbs written
    /// as four bytes each cannot exceed `2^31 - 2`, so the top bit of every
    /// 32-bit word of the derived key was *identically zero* and the key
    /// carried at most 248 bits, eight of them constant.
    ///
    /// Using the cipher's own nonce costs nothing, keeps all 256 bits of the
    /// key, and reduces independence of the two streams to the standard
    /// assumption that ChaCha20 is a PRF — which is the assumption already
    /// being made by using it at all.
    fn from_seed(seed: Seed, stream: u64) -> Self {
        use rand10::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.0);
        rng.set_stream(stream);
        Self(rng)
    }
}

impl rand10::TryRng for Csprng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

/// A hiding circle PCS: `CirclePcs` wrapped with the four randomization
/// mechanisms of `HidingFriPcs`, adapted to circle domains as described in the
/// module doc. Both MMCSs must themselves be hiding (salted); like upstream,
/// that is the configurer's responsibility, not enforced in types.
#[derive(Debug)]
pub struct HidingCirclePcs<Val: p3_field::Field, InputMmcs, FriMmcs, R> {
    pub inner: CirclePcs<Val, InputMmcs, FriMmcs>,
    pub num_random_codewords: usize,
    rng: Mutex<R>,
}

impl<Val, InputMmcs, FriMmcs, R> Clone for HidingCirclePcs<Val, InputMmcs, FriMmcs, R>
where
    Val: p3_field::Field,
    InputMmcs: Clone,
    FriMmcs: Clone,
    R: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            num_random_codewords: self.num_random_codewords,
            rng: Mutex::new(self.rng.lock().clone()),
        }
    }
}

impl<Val: p3_field::Field, InputMmcs, FriMmcs, R> HidingCirclePcs<Val, InputMmcs, FriMmcs, R> {
    pub const fn new(
        inner: CirclePcs<Val, InputMmcs, FriMmcs>,
        num_random_codewords: usize,
        rng: R,
    ) -> Self {
        Self { inner, num_random_codewords, rng: Mutex::new(rng) }
    }
}

/// Sample a height x width matrix of uniform field elements.
fn rand_matrix<Val, R: Rng>(rng: &mut R, height: usize, width: usize) -> RowMajorMatrix<Val>
where
    StandardUniform: Distribution<Val>,
    Val: Clone + Send + Sync,
{
    RowMajorMatrix::new((0..height * width).map(|_| rng.random()).collect(), width)
}

impl<Val, InputMmcs, FriMmcs, Challenge, Challenger, R> Pcs<Challenge, Challenger>
    for HidingCirclePcs<Val, InputMmcs, FriMmcs, R>
where
    Val: ComplexExtendable,
    StandardUniform: Distribution<Val>,
    Challenge: ExtensionField<Val>,
    InputMmcs: Mmcs<Val>,
    FriMmcs: Mmcs<Challenge>,
    Challenger: FieldChallenger<Val> + GrindingChallenger + CanObserve<FriMmcs::Commitment>,
    R: Rng + Send + Sync,
{
    type Domain = CircleDomain<Val>;
    type Commitment = InputMmcs::Commitment;
    type ProverData = InputMmcs::ProverData<RowMajorMatrix<Val>>;
    type EvaluationsOnDomain<'a> =
        HorizontallyTruncated<Val, RowIndexMappedView<CfftPerm, RowMajorMatrixCow<'a, Val>>>;
    /// The first item carries the drained openings of the random codeword
    /// columns; the second is the ordinary circle PCS proof.
    type Proof = (
        OpenedValues<Challenge>,
        CirclePcsProof<Val, Challenge, InputMmcs, FriMmcs, Challenger::Witness>,
    );
    type Error = <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::Error;

    const ZK: bool = true;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
            &self.inner,
            degree,
        )
    }

    fn log_max_lde_height(&self) -> usize {
        <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::log_max_lde_height(
            &self.inner,
        )
    }

    /// Commit to `T' = T + Z_D * R` on the doubled domain, plus
    /// `num_random_codewords` fully random columns.
    ///
    /// The caller (p3-uni-stark's ZK path) hands the *doubled* domain together
    /// with the *undoubled* evaluation matrix, exactly as it does for
    /// `HidingFriPcs`; the doubling is this method's job.
    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        let blinded: Vec<(Self::Domain, RowMajorMatrix<Val>)> = evaluations
            .into_iter()
            .map(|(ext_domain, mat)| {
                let h = mat.height();
                let w = mat.width();
                assert_eq!(
                    ext_domain.size(),
                    2 * h,
                    "the ZK commit expects the doubled domain alongside the undoubled trace"
                );
                let log_n = log2_strict_usize(h);
                let trace_domain = CircleDomain::<Val>::standard(log_n);

                // Stack T and R side by side so one CFFT pass extrapolates both
                // from the trace domain to the doubled domain.
                let r_small = rand_matrix::<Val, R>(&mut *self.rng.lock(), h, w);
                let mut stacked = Vec::with_capacity(h * 2 * w);
                for row in 0..h {
                    for col in 0..w {
                        stacked.push(mat.get(row, col).unwrap());
                    }
                    for col in 0..w {
                        stacked.push(r_small.get(row, col).unwrap());
                    }
                }
                let both = CircleEvaluations::from_natural_order(
                    trace_domain,
                    RowMajorMatrix::new(stacked, 2 * w),
                )
                .extrapolate(ext_domain)
                .to_natural_order()
                .to_row_major_matrix();

                // Z_D at each doubled-domain point (natural order). D and the
                // doubled domain are disjoint, so these are all nonzero.
                let z: Vec<Val> = ext_domain
                    .points()
                    .map(|p| trace_domain.vanishing_poly(p))
                    .collect();

                let ncw = self.num_random_codewords;
                let mut rng = self.rng.lock();
                let mut out = Vec::with_capacity(ext_domain.size() * (w + ncw));
                for (row, z_row) in z.iter().enumerate() {
                    for col in 0..w {
                        let t = both.get(row, col).unwrap();
                        let r = both.get(row, w + col).unwrap();
                        out.push(t + *z_row * r);
                    }
                    for _ in 0..ncw {
                        out.push(rng.random());
                    }
                }
                (ext_domain, RowMajorMatrix::new(out, w + ncw))
            })
            .collect();

        Pcs::<Challenge, Challenger>::commit(&self.inner, blinded)
    }

    /// Preprocessed traces are public, so they get the deterministic half of
    /// the same treatment: extrapolated to the doubled domain (`R = 0`), no
    /// random columns.
    fn commit_preprocessing(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        let padded: Vec<(Self::Domain, RowMajorMatrix<Val>)> = evaluations
            .into_iter()
            .map(|(ext_domain, mat)| {
                let log_n = log2_strict_usize(mat.height());
                assert_eq!(ext_domain.size(), 2 * mat.height());
                let ext = CircleEvaluations::from_natural_order(
                    CircleDomain::<Val>::standard(log_n),
                    mat,
                )
                .extrapolate(ext_domain)
                .to_natural_order()
                .to_row_major_matrix();
                (ext_domain, ext)
            })
            .collect();
        Pcs::<Challenge, Challenger>::commit(&self.inner, padded)
    }

    /// Randomize the quotient chunks: `q'_i = q_i + Z_{D_i} * t_i`, with the
    /// last chunk chosen so the verifier's Lagrange recomposition at `zeta`
    /// sees exactly the original quotient (Section 4.2, eprint 2024/1037).
    ///
    /// # Panics
    /// If `num_chunks < 2`: a single randomized chunk would not be hiding.
    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
        num_chunks: usize,
    ) -> Vec<RowMajorMatrix<Val>> {
        assert!(
            num_chunks > 1,
            "num_chunks must be > 1 to preserve hiding (got {num_chunks})"
        );
        let (domains, evals): (Vec<Self::Domain>, Vec<RowMajorMatrix<Val>>) =
            evaluations.into_iter().unzip();
        let cis = get_zp_cis::<Self::Domain>(&domains);
        let last = num_chunks - 1;
        let last_ci_inv = cis[last].inverse();

        // Widen each chunk with random codeword columns, then draw the masking
        // polynomials' coefficients: independent for chunks 0..last, and the
        // correcting combination for the last one.
        let mut rng = self.rng.lock();
        let widened: Vec<RowMajorMatrix<Val>> = evals
            .into_iter()
            .map(|m| append_random_codewords(m, self.num_random_codewords, &mut *rng))
            .collect();
        let h = widened[0].height();
        let w = widened[0].width();
        let mut ts: Vec<Vec<Val>> = (0..last)
            .map(|_| (0..h * w).map(|_| rng.random()).collect())
            .collect();
        drop(rng);
        let mut t_last = Val::zero_vec(h * w);
        for (j, t_j) in ts.iter().enumerate() {
            let mul_coeff = cis[j] * last_ci_inv;
            for (acc, v) in t_last.iter_mut().zip(t_j.iter()) {
                *acc -= *v * mul_coeff;
            }
        }
        ts.push(t_last);

        let log_blowup = self.inner.fri_params.log_blowup;
        domains
            .into_iter()
            .zip(widened)
            .zip(ts)
            .map(|((domain, evals), t_coeffs)| {
                let log_n = log2_strict_usize(h);
                // The randomized chunk has twice the chunk's dimension, so its
                // LDE lives one level higher, exactly as upstream's does.
                let target = CircleDomain::<Val>::standard(log_n + log_blowup + 1);
                let mut lde = CircleEvaluations::from_natural_order(domain, evals)
                    .extrapolate(target)
                    .to_cfft_order();
                let t_evals =
                    CircleEvaluations::evaluate(target, RowMajorMatrix::new(t_coeffs, w))
                        .to_cfft_order();
                let z_nat: Vec<Val> = target
                    .points()
                    .map(|p| domain.vanishing_poly(p))
                    .collect();
                let z_cfft = cfft_permute_slice(&z_nat);
                for (row, z_row) in z_cfft.iter().enumerate() {
                    for col in 0..w {
                        lde.values[row * w + col] += *z_row * t_evals.get(row, col).unwrap();
                    }
                }
                lde
            })
            .collect()
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<Val>>) -> (Self::Commitment, Self::ProverData) {
        Pcs::<Challenge, Challenger>::commit_ldes(&self.inner, ldes)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        let inner_evals = <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::get_evaluations_on_domain(
            &self.inner,
            prover_data,
            idx,
            domain,
        );
        let inner_width = inner_evals.width();
        // Hide the random codeword columns from the caller: the AIR indexes
        // exactly its own width.
        HorizontallyTruncated::new(inner_evals, inner_width - self.num_random_codewords).unwrap()
    }

    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        let inner_evals = <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::get_evaluations_on_domain(
            &self.inner,
            prover_data,
            idx,
            domain,
        );
        let inner_width = inner_evals.width();
        HorizontallyTruncated::new(inner_evals, inner_width).unwrap()
    }

    fn open(
        &self,
        rounds: Vec<(&Self::ProverData, Vec<Vec<Challenge>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        self.open_with_preprocessing(rounds, challenger, false)
    }

    fn open_with_preprocessing(
        &self,
        rounds: Vec<(&Self::ProverData, Vec<Vec<Challenge>>)>,
        challenger: &mut Challenger,
        is_preprocessing: bool,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        let (mut inner_opened_values, inner_proof) = <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<
            Challenge,
            Challenger,
        >>::open_with_preprocessing(
            &self.inner, rounds, challenger, is_preprocessing
        );
        // The inner openings include the random codeword columns. Drain them
        // into the proof so the caller sees only the real columns; `verify`
        // re-merges before delegating.
        let opened_values_rand = inner_opened_values
            .iter_mut()
            .enumerate()
            .map(|(idx, opened_values_for_round)| {
                opened_values_for_round
                    .iter_mut()
                    .map(|opened_values_for_mat| {
                        opened_values_for_mat
                            .iter_mut()
                            .map(|opened_values_for_point| {
                                let num_random_codewords = if is_preprocessing
                                    && idx
                                        == <Self as Pcs<Challenge, Challenger>>::PREPROCESSED_TRACE_IDX
                                {
                                    0
                                } else {
                                    self.num_random_codewords
                                };
                                let split =
                                    opened_values_for_point.len() - num_random_codewords;
                                opened_values_for_point.drain(split..).collect()
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        (inner_opened_values, (opened_values_rand, inner_proof))
    }

    fn verify(
        &self,
        mut rounds: Vec<(
            Self::Commitment,
            Vec<(Self::Domain, Vec<(Challenge, Vec<Challenge>)>)>,
        )>,
        proof: &Self::Proof,
        challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        let (opened_values_for_rand_cws, inner_proof) = proof;

        // Re-join the public and hidden halves of every opening, with the same
        // three-level shape checks as upstream's HidingFriPcs.
        if opened_values_for_rand_cws.len() != rounds.len() {
            return Err(FriError::HidingRandomOpeningRoundCountMismatch {
                expected: rounds.len(),
                got: opened_values_for_rand_cws.len(),
            });
        }
        for (round_idx, (round, rand_round)) in rounds
            .iter_mut()
            .zip(opened_values_for_rand_cws.iter())
            .enumerate()
        {
            if rand_round.len() != round.1.len() {
                return Err(FriError::HidingRandomOpeningMatrixCountMismatch {
                    round: round_idx,
                    expected: round.1.len(),
                    got: rand_round.len(),
                });
            }
            for (matrix_idx, (mat, rand_mat)) in
                round.1.iter_mut().zip(rand_round.iter()).enumerate()
            {
                if rand_mat.len() != mat.1.len() {
                    return Err(FriError::HidingRandomOpeningPointCountMismatch {
                        round: round_idx,
                        matrix: matrix_idx,
                        expected: mat.1.len(),
                        got: rand_mat.len(),
                    });
                }
                for (point, rand_point) in mat.1.iter_mut().zip(rand_mat.iter()) {
                    point.1.extend(rand_point);
                }
            }
        }
        <CirclePcs<Val, InputMmcs, FriMmcs> as Pcs<Challenge, Challenger>>::verify(
            &self.inner,
            rounds,
            inner_proof,
            challenger,
        )
    }

    /// The randomization polynomial the ZK prover path commits alongside the
    /// trace and folds into the FRI batch: fully random, over the doubled
    /// domain, wide enough to also carry the random codeword columns.
    fn get_opt_randomization_poly_commitment(
        &self,
        ext_trace_domains: impl IntoIterator<Item = Self::Domain>,
    ) -> Option<(Self::Commitment, Self::ProverData)> {
        let random_input_vals = ext_trace_domains
            .into_iter()
            .map(|domain| {
                let m = rand_matrix::<Val, R>(
                    &mut *self.rng.lock(),
                    domain.size(),
                    self.num_random_codewords + <Challenge as BasedVectorSpace<Val>>::DIMENSION,
                );
                (domain, m)
            })
            .collect::<Vec<_>>();
        let r_commit_and_data = Pcs::<Challenge, Challenger>::commit(&self.inner, random_input_vals);
        Some(r_commit_and_data)
    }
}

impl<Val, InputMmcs, FriMmcs, R> BuildPeriodicLdeTableFast
    for HidingCirclePcs<Val, InputMmcs, FriMmcs, R>
where
    Val: ComplexExtendable,
    InputMmcs: Mmcs<Val>,
{
    type PeriodicDomain = CircleDomain<Val>;

    fn maybe_build_periodic_lde_table_fast(
        &self,
        periodic_cols: &[Vec<p3_commit::Val<Self::PeriodicDomain>>],
        trace_domain: Self::PeriodicDomain,
        quotient_domain: Self::PeriodicDomain,
    ) -> Option<PeriodicLdeTable<p3_commit::Val<Self::PeriodicDomain>>>
    where
        p3_commit::Val<Self::PeriodicDomain>: Clone,
    {
        self.inner
            .maybe_build_periodic_lde_table_fast(periodic_cols, trace_domain, quotient_domain)
    }
}

/// Append `n` random columns to every row, drawn from `rng`.
fn append_random_codewords<Val, R: Rng>(
    mat: RowMajorMatrix<Val>,
    n: usize,
    rng: &mut R,
) -> RowMajorMatrix<Val>
where
    StandardUniform: Distribution<Val>,
    Val: Clone + Send + Sync,
{
    if n == 0 {
        return mat;
    }
    let (h, w) = (mat.height(), mat.width());
    let mut out = Vec::with_capacity(h * (w + n));
    for row in 0..h {
        for col in 0..w {
            out.push(mat.get(row, col).unwrap());
        }
        for _ in 0..n {
            out.push(rng.random());
        }
    }
    RowMajorMatrix::new(out, w + n)
}

/// The normalizing constants of the verifier's Lagrange recomposition, one per
/// chunk domain: `c_i = 1 / prod_{j != i} Z_{D_j}(first_point(D_i))`. Identical
/// to upstream's `get_zp_cis`; the algebra is domain-shape-agnostic.
fn get_zp_cis<D: PolynomialSpace>(qc_domains: &[D]) -> Vec<p3_commit::Val<D>> {
    batch_multiplicative_inverse(
        &qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        other_domain.vanishing_poly_at_point(domain.first_point())
                    })
                    .product()
            })
            .collect::<Vec<_>>(),
    )
}

// ---------------------------------------------------------------------------
// The binding relation, proved hiding.
// ---------------------------------------------------------------------------

type Val = Mersenne31;
/// The challenge field: the degree-4 extension `M31[i][u]` with `i² = -1` and
/// `u² = 2 + i`, 124 bits.
///
/// It was degree 3 (93 bits) until the soundness accounting showed the field
/// was the ceiling rather than the protocol: the additive error terms are
/// `domain / |E|`, the domain grows with the blowup, and at blowup 128 the
/// round-by-round error floored at `2^-74` while the query phase was offering
/// 84 bits. Ten bits thrown away by a type alias. See
/// `examples/qm31_ceiling.rs` for what each configuration recovers.
type Challenge = p3_mersenne_31::QM31;
type ByteHash = crate::keccak::SolKeccak256;
type FieldHash = p3_symmetric::SerializingHasher<ByteHash>;
type Compress = p3_symmetric::CompressionFunctionFromHasher<ByteHash, 2, 32>;

/// Salt elements per Merkle leaf: 4 Mersenne-31 elements, 124 bits.
const SALT_ELEMS: usize = 4;
/// Random codeword columns per committed matrix, following upstream's tests.
const NUM_RANDOM_CODEWORDS: usize = 2;

type ZkValMmcs = p3_merkle_tree::MerkleTreeHidingMmcs<
    <Val as p3_field::Field>::Packing,
    u8,
    FieldHash,
    Compress,
    Csprng,
    2,
    32,
    SALT_ELEMS,
>;
type ZkChallengeMmcs = ExtensionMmcs<Val, Challenge, ZkValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type ZkPcs = HidingCirclePcs<Val, ZkValMmcs, ZkChallengeMmcs, Csprng>;
pub(crate) type ZkConfig = StarkConfig<ZkPcs, Challenge, Challenger>;

/// log2 of the quotient-chunk count for [`BindingAir`] under the ZK
/// configuration, pinned for the same reason as
/// `binding::LOG_NUM_QUOTIENT_CHUNKS` (no symbolic pass in the verifier). The
/// ZK path raises the constraint degree by one (trace polynomials now have
/// twice the dimension), so this is 3 where the non-ZK value is 2. The test
/// `the_pinned_zk_quotient_chunk_count_matches_the_symbolic_pass` recomputes
/// it and fails if it drifts.
pub const LOG_NUM_QUOTIENT_CHUNKS_ZK: usize = 3;

/// Build the hiding config. `seed` feeds BOTH the blinding polynomials and the
/// leaf salts, through two domain-separated streams; two proofs of the same
/// statement under different seeds must differ everywhere. The verifier
/// constructs the same types and never draws from either generator, so its
/// seed value is irrelevant to soundness.
fn make_zk_config(num_queries: usize, seed: Seed) -> ZkConfig {
    make_zk_config_tuned(num_queries, 1, seed)
}

/// Same construction with the FRI blowup exposed. Soundness per query scales
/// with the blowup (roughly `log_blowup` bits per query before proof-of-work),
/// so `log_blowup = 2` at 20 queries buys what `log_blowup = 1` buys at 40,
/// while the proof carries half the query payloads. That trade is what lets
/// the hiding proof fit a Stellar transaction envelope; see
/// `price_the_zk_wire_sizes`.
pub(crate) fn make_zk_config_tuned(
    num_queries: usize,
    log_blowup: usize,
    seed: Seed,
) -> ZkConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ZkValMmcs::new(
        field_hash,
        compress,
        0,
        Csprng::from_seed(seed, STREAM_SALTS),
    );
    let challenge_mmcs = ZkChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let inner = CirclePcs {
        mmcs: val_mmcs,
        fri_params,
        _phantom: core::marker::PhantomData,
    };
    let pcs = ZkPcs::new(inner, NUM_RANDOM_CODEWORDS, Csprng::from_seed(seed, STREAM_BLINDING));
    StarkConfig::new(pcs, Challenger::from_hasher(Vec::new(), byte_hash))
}

/// A hiding proof of the binding relation.
pub struct ZkBindingProof {
    inner: Proof<ZkConfig>,
}

impl ZkBindingProof {
    /// log2 of the *committed* (doubled) polynomial dimension. The hiding
    /// margin is `2^degree_bits` random degrees of freedom per column against
    /// however many evaluations the verifier opens.
    pub fn degree_bits(&self) -> usize {
        self.inner.degree_bits
    }

    /// Serialize to bytes (`bincode`), the off-chain wire format.
    #[cfg(feature = "wire")]
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.inner).expect("Proof<ZkConfig> is always serializable")
    }

    /// Deserialize bytes from [`ZkBindingProof::to_bytes`]; `None` on garbage.
    #[cfg(feature = "wire")]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok().map(|inner| Self { inner })
    }

    /// Serialize with `postcard`, the no_std wire format a bare-wasm verifier
    /// (Soroban) reads from its host boundary.
    #[cfg(feature = "wire-postcard")]
    pub fn to_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.inner).expect("Proof<ZkConfig> is always serializable")
    }

    #[cfg(feature = "wire-postcard")]
    pub fn from_postcard(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok().map(|inner| Self { inner })
    }
}

/// Prove the binding relation hiding: salted MMCS, blinded trace commitment
/// (`T' = T + Z_D * R`), randomized quotient chunks, randomization-polynomial
/// commitment. `rng_seed` feeds all prover-side randomness; a production
/// caller MUST derive it from system entropy (see the module doc).
///
/// # Panics
/// If `2^log_rows < num_queries + 2`: the commitment must carry more random
/// degrees of freedom than the verifier opens (queries + the out-of-domain
/// point), or the "hiding" would be arithmetic-only theater.
pub fn prove_binding_zk(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
    log_rows: usize,
    seed: Seed,
) -> (ZkBindingProof, [u64; DIGEST_LEN], [u64; DIGEST_LEN]) {
    prove_binding_zk_tuned(secret, action, round, num_queries, 1, log_rows, seed)
}

/// Same as [`prove_binding_zk`] with the FRI blowup exposed; see
/// `make_zk_config_tuned` for why a higher blowup with fewer queries is the
/// configuration that fits an envelope.
pub fn prove_binding_zk_tuned(
    secret: [u64; SECRET_LEN],
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    num_queries: usize,
    log_blowup: usize,
    log_rows: usize,
    seed: Seed,
) -> (ZkBindingProof, [u64; DIGEST_LEN], [u64; DIGEST_LEN]) {
    assert!(log_rows >= 2, "CirclePcs cannot commit to fewer than 4 rows");
    assert!(
        (1usize << log_rows) >= num_queries + 2,
        "hiding needs more random degrees of freedom than opened evaluations: \
         2^log_rows must be >= num_queries + 2"
    );
    let leaf_input = pack(secret, action);
    let nullifier_input = pack(secret, round);
    // Truncated to digests: the full permutation state IS the witness once
    // pi is inverted, and the context is public beside it.
    let leaf_full = permute(leaf_input);
    let nullifier_full = permute(nullifier_input);
    let leaf_output: [u64; DIGEST_LEN] = core::array::from_fn(|i| leaf_full[i]);
    let nullifier_output: [u64; DIGEST_LEN] = core::array::from_fn(|i| nullifier_full[i]);

    let repeats = 1usize << log_rows;
    let mut inputs: Vec<[Val; WIDTH]> = Vec::with_capacity(2 * repeats);
    for _ in 0..repeats {
        inputs.push(to_field(leaf_input));
        inputs.push(to_field(nullifier_input));
    }
    let constants: RoundConstants<Val, WIDTH, 4, 14> = RoundConstants::new(
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_INTERNAL,
        p3_mersenne_31::MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL,
    );
    let trace: RowMajorMatrix<Val> =
        generate_vectorized_trace_rows::<Val, crate::binding::LinearLayersPub, WIDTH, 5, 0, 4, 14, 2>(
            inputs,
            &constants,
            0,
        );

    let air = BindingAir::new();
    let pis = public_values_for_hiding(action, round, leaf_output, nullifier_output);
    let config = make_zk_config_tuned(num_queries, log_blowup, seed);
    let proof = prove(&config, &air, trace, &pis);
    (ZkBindingProof { inner: proof }, leaf_output, nullifier_output)
}

/// Verify a [`ZkBindingProof`]. Same statement and public values as the
/// non-hiding verifier; only the commitment machinery differs.
pub fn verify_binding_zk(
    proof: &ZkBindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; DIGEST_LEN],
    nullifier: [u64; DIGEST_LEN],
    num_queries: usize,
) -> bool {
    verify_binding_zk_tuned(proof, action, round, leaf, nullifier, num_queries, 1)
}

/// Same as [`verify_binding_zk`] with the FRI blowup exposed; must match the
/// blowup the proof was produced with.
pub fn verify_binding_zk_tuned(
    proof: &ZkBindingProof,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    leaf: [u64; DIGEST_LEN],
    nullifier: [u64; DIGEST_LEN],
    num_queries: usize,
    log_blowup: usize,
) -> bool {
    let air = BindingAir::new();
    let config = make_zk_config_tuned(num_queries, log_blowup, Seed::reproducible(0));
    let pis = public_values_for_hiding(action, round, leaf, nullifier);
    verify_with_known_quotient_chunks(
        &config,
        &air,
        &proof.inner,
        &pis,
        None,
        LOG_NUM_QUOTIENT_CHUNKS_ZK,
    )
    .is_ok()
}

fn to_field(input: [u64; WIDTH]) -> [Val; WIDTH] {
    core::array::from_fn(|i| Val::from_u64(input[i]))
}

fn pack(secret: [u64; SECRET_LEN], context: [u64; CONTEXT_LEN]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    out[..SECRET_LEN].copy_from_slice(&secret);
    out[SECRET_LEN..].copy_from_slice(&context);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u64) -> [u64; SECRET_LEN] {
        core::array::from_fn(|i| byte * 1000 + i as u64)
    }

    fn context(byte: u64) -> [u64; CONTEXT_LEN] {
        core::array::from_fn(|i| byte * 2000 + i as u64)
    }

    /// Fast-but-real parameters for the roundtrip tests: 16 rows against 8
    /// queries satisfies the hiding margin (16 >= 8 + 2) at test speed.
    const TEST_QUERIES: usize = 8;
    const TEST_LOG_ROWS: usize = 4;

    #[test]
    fn the_pinned_zk_quotient_chunk_count_matches_the_symbolic_pass() {
        use p3_air::BaseAir;
        use p3_uni_stark::{get_log_num_quotient_chunks, AirLayout, StarkGenericConfig};
        let air = BindingAir::new();
        let config = make_zk_config(4, Seed::reproducible(0));
        assert_eq!(config.is_zk(), 1, "the hiding PCS must flip the ZK path on");
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: BaseAir::<Val>::width(&air),
            num_public_values: BaseAir::<Val>::num_public_values(&air),
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(&air),
            ..Default::default()
        };
        let recomputed =
            get_log_num_quotient_chunks::<Val, BindingAir>(&air, layout, config.is_zk());
        assert_eq!(
            LOG_NUM_QUOTIENT_CHUNKS_ZK, recomputed,
            "the pinned ZK constant must equal what the symbolic pass derives; \
             if the AIR changed, re-pin it to the recomputed value"
        );
    }

    #[test]
    fn a_hiding_binding_proof_proves_and_verifies() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(42));
        assert!(
            verify_binding_zk(&proof, action, round, leaf, nullifier, TEST_QUERIES),
            "a genuine hiding proof must verify"
        );
    }

    #[test]
    fn a_hiding_proof_does_not_verify_against_a_tampered_leaf() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(42));
        let mut wrong_leaf = leaf;
        wrong_leaf[0] ^= 1;
        assert!(
            !verify_binding_zk(&proof, action, round, wrong_leaf, nullifier, TEST_QUERIES),
            "soundness must survive the hiding machinery: tampered leaf rejected"
        );
    }

    #[test]
    fn a_hiding_proof_does_not_verify_against_a_tampered_nullifier() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(42));
        let mut wrong = nullifier;
        wrong[0] ^= 1;
        assert!(
            !verify_binding_zk(&proof, action, round, leaf, wrong, TEST_QUERIES),
            "soundness must survive the hiding machinery: tampered nullifier rejected"
        );
    }

    #[test]
    fn the_committed_dimension_exceeds_what_the_verifier_opens() {
        // The hiding margin, stated as an arithmetic fact of the proof itself:
        // the committed polynomial carries `2^degree_bits` degrees of freedom
        // per column, of which half are the blinding polynomial R; the
        // verifier opens `num_queries` LDE rows plus the out-of-domain point.
        // The non-hiding audit (privacy_audit.rs) measured 40 openings against
        // 4 rows: 5x overdetermined. Here it is underdetermined by design.
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, _, _) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(42));
        let random_dofs = 1usize << (proof.degree_bits() - 1);
        assert!(
            TEST_QUERIES + 1 < random_dofs,
            "openings ({}) must stay below the blinding degrees of freedom ({})",
            TEST_QUERIES + 1,
            random_dofs
        );
    }

    #[test]
    fn two_proofs_of_the_same_witness_differ_in_their_commitments() {
        // The blinding must actually randomize: same secret, same publics,
        // different seeds, byte-different proofs. If the seeds were ignored
        // the two serializations would collide.
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (a, leaf, nullifier) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(1));
        let (b, _, _) = prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(2));
        assert!(
            verify_binding_zk(&a, action, round, leaf, nullifier, TEST_QUERIES)
                && verify_binding_zk(&b, action, round, leaf, nullifier, TEST_QUERIES),
            "both seeded proofs must verify"
        );
        let bytes_a = a.to_bytes();
        let bytes_b = b.to_bytes();
        assert_ne!(
            bytes_a, bytes_b,
            "different blinding seeds must produce different proofs of the same statement"
        );
    }

    /// Not a correctness test: prints the wire sizes of the candidate
    /// production configurations, because yesterday's on-chain measurement
    /// showed transaction size, not CPU, is the binding constraint. Run with
    /// `cargo test --release price_the_zk_wire_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn price_the_zk_wire_sizes() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        // (log_rows, num_queries, log_blowup): conjectured query soundness is
        // roughly log_blowup bits per query, so 32q@blowup1, 16q@blowup2 and
        // 11q@blowup3 sit near the same ~32-bit pre-PoW target, and
        // 20q@blowup2 near 40q@blowup1.
        for (log_rows, queries, log_blowup) in [
            (6usize, 32usize, 1usize),
            (6, 40, 1),
            (5, 20, 2),
            (5, 16, 2),
            (4, 11, 3),
        ] {
            let (proof, leaf, nullifier) =
                prove_binding_zk_tuned(s, action, round, queries, log_blowup, log_rows, Seed::reproducible(42));
            assert!(
                verify_binding_zk_tuned(
                    &proof, action, round, leaf, nullifier, queries, log_blowup
                ),
                "the priced configuration must actually verify"
            );
            let bytes = proof.to_bytes();
            #[cfg(feature = "wire-postcard")]
            let pc = proof.to_postcard().len();
            #[cfg(not(feature = "wire-postcard"))]
            let pc = 0usize;
            println!(
                "zk binding, {} rows, {} queries, blowup {}: {} bytes bincode, {} bytes postcard",
                1 << log_rows,
                queries,
                1 << log_blowup,
                bytes.len(),
                pc
            );
        }
    }

    #[test]
    fn a_zk_proof_survives_a_byte_round_trip() {
        let s = secret(1);
        let action = context(1);
        let round = context(2);
        let (proof, leaf, nullifier) =
            prove_binding_zk(s, action, round, TEST_QUERIES, TEST_LOG_ROWS, Seed::reproducible(42));
        let bytes = proof.to_bytes();
        eprintln!("ZkBindingProof serialized size: {} bytes", bytes.len());
        let round_tripped =
            ZkBindingProof::from_bytes(&bytes).expect("valid bytes must deserialize");
        assert!(
            verify_binding_zk(&round_tripped, action, round, leaf, nullifier, TEST_QUERIES),
            "a hiding proof must still verify after a wire round trip"
        );
    }

    // ---------------------------------------------------------------- seeds
    //
    // These do not assert that the generator is good — ChaCha20's security is
    // assumed, not tested here. They falsify the two concrete defects this
    // code actually had: a seed whose bits were not all load-bearing, and two
    // streams related by something an adversary could invert.

    /// Every one of the 256 seed bits must reach the output.
    ///
    /// This is the test that would have caught the discarded intermediate
    /// derivation, where eight bits of the derived key were identically zero:
    /// flipping a seed bit that the key does not carry leaves the keystream
    /// untouched, and this loop would have found all eight.
    #[test]
    fn every_seed_bit_changes_the_keystream() {
        use rand10::TryRng;
        let base = [0u8; 32];
        let reference = {
            let mut rng = Csprng::from_seed(Seed::from_bytes(base), STREAM_SALTS);
            core::array::from_fn::<u64, 8, _>(|_| rng.try_next_u64().unwrap())
        };
        for bit in 0..256 {
            let mut flipped = base;
            flipped[bit / 8] ^= 1 << (bit % 8);
            let mut rng = Csprng::from_seed(Seed::from_bytes(flipped), STREAM_SALTS);
            let out = core::array::from_fn::<u64, 8, _>(|_| rng.try_next_u64().unwrap());
            assert_ne!(
                out, reference,
                "seed bit {bit} does not reach the keystream, so the seed is \
                 narrower than the 256 bits its type claims"
            );
        }
    }

    /// The salt stream and the blinding stream must not coincide, and must not
    /// be one another shifted: the predecessor seeded them from values a fixed
    /// XOR apart, which is what let recovering one recover the other.
    #[test]
    fn the_two_streams_of_one_seed_diverge() {
        use rand10::TryRng;
        let seed = Seed::from_bytes([7u8; 32]);
        let draw = |stream| {
            let mut rng = Csprng::from_seed(seed, stream);
            core::array::from_fn::<u64, 64, _>(|_| rng.try_next_u64().unwrap())
        };
        let salts = draw(STREAM_SALTS);
        let blinding = draw(STREAM_BLINDING);
        assert_ne!(salts, blinding, "the two streams must differ");
        for shift in 1..64 {
            assert_ne!(
                &salts[shift..],
                &blinding[..64 - shift],
                "the blinding stream must not be the salt stream offset by {shift}"
            );
        }
    }

    /// A seed is a seed: same bytes, same stream, same output. Reproducibility
    /// is what the fixtures rest on, so it is worth pinning.
    #[test]
    fn one_seed_reproduces_its_own_stream() {
        use rand10::TryRng;
        let seed = Seed::from_bytes([3u8; 32]);
        let mut a = Csprng::from_seed(seed, STREAM_BLINDING);
        let mut b = Csprng::from_seed(seed, STREAM_BLINDING);
        for _ in 0..32 {
            assert_eq!(a.try_next_u64().unwrap(), b.try_next_u64().unwrap());
        }
    }

    /// `Seed::reproducible` is documented as carrying 64 bits, not 256. That
    /// is a real limitation and the test states it rather than letting a
    /// reader assume the constructor is as strong as the type.
    #[test]
    fn the_reproducible_seed_carries_only_sixty_four_bits() {
        let s = Seed::reproducible(0x0123_4567_89AB_CDEF);
        let bytes = s.0;
        for chunk in bytes.chunks(8) {
            assert_eq!(chunk, &bytes[..8], "reproducible() repeats one u64 four times");
        }
    }
}
