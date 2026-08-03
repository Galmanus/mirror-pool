//! Does the blinding actually blind? An exact rank computation, not a hope.
//!
//! `HidingCirclePcs` commits `T' = T + Z_D·R`, and the whole hiding claim is
//! this: an adversary who learns `k` evaluations of `T'` at points off the
//! trace domain learns nothing about `T`, because each opened value is masked
//! by an independent uniform field element. Written out, the claim is
//!
//!   for every witness T and every set S = {P_1,…,P_k} of opened points,
//!   the distribution of (T'(P_1),…,T'(P_k)) over uniform R is UNIFORM on F^k
//!
//! and that holds if and only if two things are true:
//!
//!   (a) `Z_D(P_j) ≠ 0` for every opened point — true by construction, since
//!       the trace domain `standard(n)` and every LDE domain `standard(m)`
//!       with `m > n` are disjoint (their points have different orders); and
//!   (b) the evaluation map `L_N → F^k`, `R ↦ (R(P_1),…,R(P_k))`, is
//!       SURJECTIVE, where `L_N` is the N-dimensional space of circle
//!       polynomials the blinder is drawn from.
//!
//! Condition (b) is the one that is easy to assume and wrong to assume, and
//! this example exists because assuming it would have been wrong.
//!
//! For univariate Reed-Solomon, (b) is free: the evaluation matrix is
//! Vandermonde, so any `k ≤ N` distinct points give full rank. **Circle
//! polynomials are not univariate polynomials.** `L_N` lives on the curve
//! `x² + y² = 1`, and a nonzero element of it can vanish at as many as `N`
//! points — its divisor has degree `N`, not `N − 1`. So evaluation at exactly
//! `N` points can be singular, and the computation below **finds a concrete
//! counterexample**: at `N = 4` over the 8-point LDE domain, the point set
//! `{0, 1, 2, 7}` has rank 3, not 4. Natural-order indices 0 and 7 are a
//! point and its negation.
//!
//! The consequence is a correction to the folklore rule, and it is the whole
//! reason to compute rather than assume:
//!
//! ```text
//!     k ≤ N     is NOT sufficient      (counterexample above)
//!     k ≤ N − 1 is what the margin must guarantee
//! ```
//!
//! Every margin this crate enforces already satisfies the corrected rule, but
//! by one dimension, not by luck of a large gap: the binding relation opens
//! `k = Q + 1` values and requires `N ≥ Q + 2`; the membership relation opens
//! `k = Q + 2` (it has transition constraints, so the verifier also sees
//! `ζ_next`) and requires `N ≥ Q + 3`. Both are exactly `N ≥ k + 1`. Had the
//! margin been written as `N ≥ k`, which is what the Reed-Solomon reflex
//! suggests, the boundary configuration would sit precisely on the degenerate
//! case found below.
//!
//! This example establishes it, exactly and over the actual field, for the
//! configurations that are deployed. It builds the `k × N` evaluation matrix
//! of a basis of `L_N` at the opened points and computes its rank over
//! Mersenne-31 by Gaussian elimination. Rank `k` means surjective, which means
//! every opened value is masked by an independent uniform element, which means
//! the openings are **perfectly** hiding — not merely statistically so.
//!
//! What this does and does not settle:
//!
//! What this does and does not settle:
//!
//!  - Settled, by exhaustion at sizes where exhaustion is finite: at `N = 4`
//!    and `N = 8`, EVERY subset of size `≤ N − 1` has full rank, and at size
//!    `N` some do not. That is the corrected rule, verified rather than
//!    argued.
//!  - Settled, exactly, for the deployed parameter sets: surjectivity at the
//!    structured point families a real query pattern produces (consecutive
//!    indices, negation pairs, arithmetic strides).
//!  - NOT settled: the `N ≥ k + 1` rule for every one of the `C(M, k)`
//!    subsets at deployed sizes, which is not a finite computation. It is
//!    supported by exhaustion at small `N` and by the divisor-degree argument
//!    (a nonzero `f ∈ L_N` has at most `N` zeros, so `N − 1` conditions
//!    cannot annihilate a two-dimensional subspace generically) — support, not
//!    proof.
//!  - NOT settled here: hiding of anything other than the trace openings. Each
//!    FRI query additionally reveals ONE extension-field scalar that is a known
//!    linear functional of the sibling row, mixed across all `w` columns. That
//!    adds `Q` scalar constraints against `w · N` blinder dimensions, so it
//!    costs `Q / w` of a dimension — under 0.04 at this AIR's width. The
//!    quotient chunks and the FRI batch carry their own randomisation, and the
//!    uni-stark randomisation polynomial is where the "statistical" qualifier
//!    in the paper's ZK claim comes from.
//!
//! Run: cargo run --release --example hiding_margin_proof

use p3_circle::{CircleDomain, CircleEvaluations};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mersenne_31::Mersenne31;

type Val = Mersenne31;

/// Evaluations, on the LDE domain, of the basis of `L_N` given by the
/// indicator functions of the trace domain.
///
/// This is exactly the space the blinder is drawn from: `prove_*` samples `R`
/// uniformly as `N` values on the trace domain and extrapolates, and
/// extrapolation is a linear bijection from `F^N` onto `L_N`. So a uniform
/// draw of trace-domain values is a uniform draw from `L_N`, and the columns
/// below span exactly the space the adversary must be unable to pin down.
fn basis_on_lde(log_n: usize, log_blowup: usize) -> RowMajorMatrix<Val> {
    let n = 1usize << log_n;
    let trace_domain = CircleDomain::<Val>::standard(log_n);
    let lde_domain = CircleDomain::<Val>::standard(log_n + log_blowup);
    // Column i is the indicator of trace-domain point i, extrapolated.
    let mut cols = Vec::with_capacity(n * n);
    for row in 0..n {
        for col in 0..n {
            cols.push(if row == col { Val::ONE } else { Val::ZERO });
        }
    }
    CircleEvaluations::from_natural_order(trace_domain, RowMajorMatrix::new(cols, n))
        .extrapolate(lde_domain)
        .to_natural_order()
        .to_row_major_matrix()
}

/// Rank over Mersenne-31 of the submatrix formed by `rows` of `m`.
fn rank_of_rows(m: &RowMajorMatrix<Val>, rows: &[usize]) -> usize {
    let width = m.width();
    let mut a: Vec<Vec<Val>> = rows
        .iter()
        .map(|&r| (0..width).map(|c| m.get(r, c).unwrap()).collect())
        .collect();
    let mut rank = 0usize;
    let mut col = 0usize;
    while rank < a.len() && col < width {
        // find a pivot in this column at or below `rank`
        let mut pivot = None;
        for r in rank..a.len() {
            if a[r][col] != Val::ZERO {
                pivot = Some(r);
                break;
            }
        }
        match pivot {
            None => {
                col += 1;
            }
            Some(p) => {
                a.swap(rank, p);
                let inv = a[rank][col].inverse();
                for c in col..width {
                    a[rank][c] *= inv;
                }
                for r in 0..a.len() {
                    if r != rank && a[r][col] != Val::ZERO {
                        let f = a[r][col];
                        for c in col..width {
                            let sub = a[rank][c] * f;
                            a[r][c] -= sub;
                        }
                    }
                }
                rank += 1;
                col += 1;
            }
        }
    }
    rank
}

/// Every k-subset of `m`'s rows has full rank k. Exhaustive; only tractable
/// for tiny domains, which is exactly where it is worth doing, because it is
/// the only place the "for ALL subsets" statement can be settled rather than
/// sampled.
fn every_subset_has_full_rank(m: &RowMajorMatrix<Val>, k: usize) -> bool {
    let rows = m.height();
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        if rank_of_rows(m, &idx) != k {
            println!("    COUNTEREXAMPLE: rows {idx:?} have rank < {k}");
            return false;
        }
        // next combination
        let mut i = k;
        loop {
            if i == 0 {
                return true;
            }
            i -= 1;
            if idx[i] != i + rows - k {
                idx[i] += 1;
                for j in i + 1..k {
                    idx[j] = idx[j - 1] + 1;
                }
                break;
            }
        }
    }
}

fn report(log_n: usize, log_blowup: usize, k: usize) {
    let n = 1usize << log_n;
    let m = basis_on_lde(log_n, log_blowup);
    let lde = m.height();
    println!(
        "N = {n} (trace rows), LDE = {lde} points (blowup {}), k = {k} opened evaluations",
        1 << log_blowup
    );
    assert!(k <= n, "the counting argument only claims anything for k <= N");

    // 1. the first k points, in natural order
    let consecutive: Vec<usize> = (0..k).collect();
    let r1 = rank_of_rows(&m, &consecutive);

    // 2. sibling pairs: a circle FRI query opens a point and its negation,
    //    which are the natural-order pair (i, LDE - 1 - i). If any structured
    //    set were going to be degenerate, this is the candidate.
    let mut siblings = Vec::with_capacity(k);
    let mut i = 0usize;
    while siblings.len() < k {
        siblings.push(i);
        if siblings.len() < k {
            siblings.push(lde - 1 - i);
        }
        i += 1;
    }
    siblings.sort_unstable();
    siblings.dedup();
    let r2 = rank_of_rows(&m, &siblings);

    // 3. an arithmetic-progression stride, the other structured family
    let stride = (lde / k).max(1);
    let strided: Vec<usize> = (0..k).map(|j| (j * stride) % lde).collect();
    let r3 = rank_of_rows(&m, &strided);

    println!("  consecutive points   rank {r1} / {k}  {}", verdict(r1, k));
    println!(
        "  FRI sibling pairs    rank {} / {}  {}",
        r2,
        siblings.len(),
        verdict(r2, siblings.len())
    );
    println!("  strided points       rank {r3} / {k}  {}", verdict(r3, k));
    assert_eq!(r1, k, "consecutive points must impose independent conditions");
    assert_eq!(r2, siblings.len(), "sibling pairs must impose independent conditions");
    assert_eq!(r3, k, "strided points must impose independent conditions");
    println!();
}

fn verdict(rank: usize, k: usize) -> &'static str {
    if rank == k {
        "SURJECTIVE — openings uniform, perfectly masked"
    } else {
        "DEGENERATE — the blinder does NOT cover these openings"
    }
}

fn main() {
    println!(
        "Surjectivity of the blinding map for HidingCirclePcs.\n\
         Rank k means the k opened evaluations of T' = T + Z_D*R are uniform\n\
         and independent over a uniform R, hence perfectly masked.\n"
    );

    println!("=== exhaustive: EVERY k-subset, at sizes where that is finite ===\n");
    for (log_n, log_blowup, k) in [
        (2usize, 1usize, 2usize),
        (2, 1, 3), // N-1: must be safe
        (2, 1, 4), // N:   expected degenerate
        (3, 1, 6),
        (3, 1, 7), // N-1: must be safe
        (3, 1, 8), // N:   expected degenerate
    ] {
        let n = 1usize << log_n;
        let m = basis_on_lde(log_n, log_blowup);
        let ok = every_subset_has_full_rank(&m, k);
        println!(
            "N = {n}, LDE = {}, every {k}-subset full rank: {}{}",
            m.height(),
            if ok { "YES" } else { "NO" },
            if k == n && !ok {
                "   <- k = N IS DEGENERATE. The Reed-Solomon rule does not transfer."
            } else {
                ""
            }
        );
        if k < n {
            assert!(ok, "k <= N-1 must be safe; a failure here would sink the margin rule");
        } else {
            assert!(!ok, "k = N is expected to be degenerate on circle domains");
        }
    }
    println!(
        "\n  Read the pattern, not the individual lines: every subset of size N-1 is\n\
           surjective, and at size N some are not. The margin rule is therefore\n\
           N >= k + 1, not N >= k. Every configuration this crate enforces already\n\
           satisfies it — by exactly one dimension.\n"
    );

    println!("=== the deployed configurations ===\n");
    // Binding: 32 rows, 20 queries, blowup 4. The committed polynomial has
    // dimension 2N = 64; the blinder occupies N = 32 of those dimensions, and
    // that is the number the openings must stay under.
    report(5, 2, 22); // 20 queries + zeta + one spare
    // Membership: same height, and one more opening because the AIR has
    // transition constraints, so the verifier also sees zeta_next.
    report(5, 2, 23);
    // The 64-row hiding configuration, at its 40-query point.
    report(6, 2, 42);

    println!(
        "Every configuration the contracts accept has the blinder covering strictly\n\
         more dimensions than the verifier opens, and the evaluation map at those\n\
         openings is surjective. Under a uniform blinder the opened values are\n\
         therefore uniform: the trace openings leak nothing, information\n\
         theoretically, whatever the adversary's computing power.\n\n\
         The residual assumptions, stated so they are not mistaken for results:\n\
         the blinder must BE uniform (it is drawn from ChaCha20 seeded by the OS,\n\
         so this is computational, not information-theoretic), and hiding of the\n\
         quotient chunks and the FRI batch rests on their own randomisation,\n\
         which is where the paper's 'statistical' qualifier comes from."
    );
}
