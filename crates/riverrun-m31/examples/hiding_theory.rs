//! The hiding argument, proved rather than measured.
//!
//! `examples/hiding_margin_proof.rs` computes ranks and finds counterexamples.
//! That is evidence. This file supplies the structure theory those ranks are
//! instances of, states three theorems, and verifies each one's hypotheses and
//! conclusions computationally over Mersenne-31, so that a reader can check the
//! algebra and the arithmetic against each other.
//!
//! Throughout: `p = 2^31 - 1`, `C = {(x,y) : x² + y² = 1}` over `F_p`, and
//! `L_N` is the `N`-dimensional space of circle polynomials that `CircleEvaluations`
//! interpolates into, `N = 2^n`. `D` is the trace domain `standard(n)` and `L`
//! is an LDE domain `standard(n + β)`, disjoint from `D`.
//!
//! ---
//!
//! ## Theorem A (structure of `L_N`)
//!
//! ```text
//!     L_N = { a(x) + y·b(x)  :  deg a < N/2,  deg b < N/2 }
//! ```
//!
//! *Proof of the normal form.* Let `R = F[x,y]/(x² + y² − 1)` be the
//! coordinate ring of the circle. The defining relation gives `y² = 1 − x²`,
//! so every occurrence of `y²` rewrites into `F[x]`: by induction every
//! monomial `y^k` equals a polynomial in `x` when `k` is even and `y` times
//! one when `k` is odd. Hence `R = F[x] ⊕ y·F[x]` as an `F[x]`-module, free of
//! rank two on the basis `{1, y}`, and every element of `R` is `a(x) + y·b(x)`
//! for a UNIQUE pair `(a, b)`: uniqueness because `a + yb = a' + yb'` forces
//! `(a − a') = y(b' − b)`, and comparing the free-module components gives
//! `a = a'`, `b = b'`. ∎
//!
//! What that argument does NOT settle is which `(a, b)` degree bounds cut out
//! the particular `N`-dimensional subspace that `CircleEvaluations`
//! interpolates into. That is a fact about the CFFT construction rather than
//! about the ring, and it is settled here by computation: `main` checks the two
//! spans coincide as subspaces of `F^|L|` by comparing the ranks of both
//! generator matrices and of their concatenation. So the normal form is
//! proved, the degree bounds are verified, and the difference between the two
//! is stated rather than blurred.
//!
//! Two consequences used below, both immediate:
//!
//!  - **Negation acts by sign on the odd part.** `-(x,y) = (x,-y)`, so
//!    `f(-P) = a(x) - y·b(x)`. Hence `f(P) = f(-P) = 0` forces
//!    `a(x₀) = b(x₀) = 0`: a negation PAIR is not two generic conditions, it is
//!    two conditions concentrated at one abscissa. This is the exact mechanism
//!    behind the degenerate sets found by the companion example, both of which
//!    are "the first `N-1` points plus the negation of the first".
//!  - **Distinct points share an abscissa only if they are a negation pair**,
//!    since `x` determines `y` up to sign.
//!
//! ## Theorem B (unconditional surjectivity below half)
//!
//! If `S ⊂ L` consists of `k ≤ N/2` distinct points, then `L_N → F^k`,
//! `f ↦ (f(P))_{P∈S}`, is surjective. **No hypothesis on negation pairs.**
//!
//! *Proof.* Write `h = N/2`. Split `S` into `m` negation pairs and `s`
//! singletons, so `k = 2m + s`; by Theorem A's corollary the abscissae of the
//! `m` pairs and the `s` singletons are `m + s` distinct values. Let
//! `f = a + y·b` lie in the kernel. Each pair forces `a(x_i) = b(x_i) = 0`, so
//! `V_p = Π_{i} (x - x_i)` divides both: `a = V_p·a'`, `b = V_p·b'` with
//! `deg a', deg b' < h - m`. Since `V_p(x_j) ≠ 0` at every singleton abscissa,
//! the singleton conditions become `a'(x_j) + y_j·b'(x_j) = 0`. Those `s`
//! conditions have matrix `[ V | Y·V ]` with `V` the `s × (h-m)` Vandermonde
//! in the distinct `x_j`; and `s = k - 2m ≤ h - 2m ≤ h - m`, so `V` alone has
//! rank `s` and the conditions are independent. Counting: the kernel has
//! dimension `N - 2m - s = N - k`, so the rank is `k`. ∎
//!
//! No genericity, no computation, no dependence on the `y_j`, and — the part
//! worth noticing — no need to exclude negation pairs. A pair costs two
//! dimensions and pays for them; the Vandermonde argument survives the passage
//! from the line to the circle by living on the even part, and the pairs are
//! absorbed by dividing out their vanishing polynomial first.
//!
//! ## Theorem C (the Singleton defect is exactly one)
//!
//! (i) A nonzero `f ∈ L_N` has at most `N` zeros on `C`.
//! (ii) Consequently, for any `S ⊂ L` with `|S| = k ≤ N` and `|L| ≥ N + 1`,
//!      the evaluation map has rank at least `k - 1`.
//! (iii) The bound in (ii) is attained: rank `k - 1` occurs.
//!
//! *Proof of (i).* Write `f = a + y·b` and put `g(x) = a(x)² - (1-x²)·b(x)²`,
//! of degree at most `N`. If `g ≡ 0` then `(1-x²) = (a/b)²` in `F(x)` for
//! `b ≠ 0`, impossible because `1 - x²` is squarefree — its roots `±1` are
//! distinct for odd `p` — while a square of a rational function has even
//! multiplicities; so `b = 0`, then `a = 0`, then `f = 0`. So `g ≢ 0` and `g`
//! has at most `N` roots. Every zero of `f` lies over a root of `g`, and a
//! zero occurring at BOTH signs of `y` over one abscissa `x₀` forces
//! `a(x₀) = b(x₀) = 0`, hence `(x - x₀)² | g`. Counting with multiplicity,
//! the number of zeros of `f` is at most `deg g ≤ N`. ∎
//!
//! *Proof of (ii).* Suppose the rank is `k - d` with `d ≥ 2`. The kernel has
//! dimension `N - k + d`. Choose `N - k + d - 1` points of `L \ S`; each cuts
//! the kernel by at most one dimension, so some nonzero `f` in the kernel
//! vanishes on all of them as well, giving `f` at least
//! `k + (N - k + d - 1) = N + d - 1 ≥ N + 1` zeros, contradicting (i). ∎
//!
//! *(iii)* is the companion example's counterexamples, re-derived here.
//!
//! ## What the three together say about the deployment
//!
//! Let `k` be the number of evaluations of a committed column the verifier
//! learns: `Q + 1` for an AIR without transition constraints (`Q` query rows
//! and `ζ`), `Q + 2` when `ζ_next` is also opened.
//!
//!  - `k ≤ N/2` and no negation pair among the opened points  ⟹  **surjective,
//!    unconditionally** (Theorem B): the openings are uniform and the trace
//!    leaks nothing, for every witness and every adversary.
//!  - `N/2 < k ≤ N - 1`  ⟹  **rank ≥ k - 1 unconditionally** (Theorem C), so at
//!    most one linear functional of the witness can leak, and whether it does
//!    is a property of the specific point set, decidable by rank computation.
//!  - `k = N`  ⟹  degenerate sets exist (Theorem C(iii)); a margin written as
//!    `N ≥ k` sits on them.
//!
//! The configuration this project has been deploying is `N = 32` with `k = 22`,
//! which lands in the middle band: computation says surjective, theory says
//! "at most one dimension, and here is how to check". Raising the trace to
//! `N = 64` moves the same `k` into Theorem B's unconditional band. `main`
//! prints both so the choice is made against numbers rather than taste.
//!
//! Run: cargo run --release --example hiding_theory

use p3_circle::{CircleDomain, CircleEvaluations};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mersenne_31::Mersenne31;

type Val = Mersenne31;

/// Points of `standard(log_n)` in natural order.
fn domain_points(log_n: usize) -> Vec<(Val, Val)> {
    CircleDomain::<Val>::standard(log_n)
        .points()
        .map(|p| (p.x, p.y))
        .collect()
}

/// Column `i` is the indicator of trace point `i`, extrapolated to the LDE
/// domain: a generating set for `L_N` as a space of functions on `L`.
fn interpolation_basis(log_n: usize, log_blowup: usize) -> RowMajorMatrix<Val> {
    let n = 1usize << log_n;
    let mut cols = Vec::with_capacity(n * n);
    for row in 0..n {
        for col in 0..n {
            cols.push(if row == col { Val::ONE } else { Val::ZERO });
        }
    }
    CircleEvaluations::from_natural_order(
        CircleDomain::<Val>::standard(log_n),
        RowMajorMatrix::new(cols, n),
    )
    .extrapolate(CircleDomain::<Val>::standard(log_n + log_blowup))
    .to_natural_order()
    .to_row_major_matrix()
}

/// The basis of Theorem A: `x^i` and `y·x^i` for `i < N/2`, evaluated on `L`.
fn structural_basis(log_n: usize, log_blowup: usize) -> RowMajorMatrix<Val> {
    let n = 1usize << log_n;
    let h = n / 2;
    let pts = domain_points(log_n + log_blowup);
    let mut vals = Vec::with_capacity(pts.len() * n);
    for (x, y) in &pts {
        let mut pow = Val::ONE;
        let mut evens = Vec::with_capacity(h);
        for _ in 0..h {
            evens.push(pow);
            pow *= *x;
        }
        for e in &evens {
            vals.push(*e);
        }
        for e in &evens {
            vals.push(*y * *e);
        }
    }
    RowMajorMatrix::new(vals, n)
}

/// Rank over `F_p` of the given rows of `m` (all columns).
fn rank_rows(m: &RowMajorMatrix<Val>, rows: &[usize]) -> usize {
    let w = m.width();
    let a: Vec<Vec<Val>> = rows
        .iter()
        .map(|&r| (0..w).map(|c| m.get(r, c).unwrap()).collect())
        .collect();
    rank(a)
}

/// Rank of the whole matrix, viewed columnwise (rank is the same either way).
fn rank_all(m: &RowMajorMatrix<Val>) -> usize {
    let rows: Vec<usize> = (0..m.height()).collect();
    rank_rows(m, &rows)
}

/// Rank of the horizontal concatenation of two matrices with equal height.
fn rank_concat(a: &RowMajorMatrix<Val>, b: &RowMajorMatrix<Val>) -> usize {
    assert_eq!(a.height(), b.height());
    let (wa, wb) = (a.width(), b.width());
    let mut vals = Vec::with_capacity(a.height() * (wa + wb));
    for r in 0..a.height() {
        for c in 0..wa {
            vals.push(a.get(r, c).unwrap());
        }
        for c in 0..wb {
            vals.push(b.get(r, c).unwrap());
        }
    }
    rank_all(&RowMajorMatrix::new(vals, wa + wb))
}

fn rank(mut a: Vec<Vec<Val>>) -> usize {
    if a.is_empty() {
        return 0;
    }
    let w = a[0].len();
    let (mut r, mut c) = (0usize, 0usize);
    while r < a.len() && c < w {
        let mut piv = None;
        for i in r..a.len() {
            if a[i][c] != Val::ZERO {
                piv = Some(i);
                break;
            }
        }
        match piv {
            None => c += 1,
            Some(i) => {
                a.swap(r, i);
                let inv = a[r][c].inverse();
                for j in c..w {
                    a[r][j] *= inv;
                }
                for i2 in 0..a.len() {
                    if i2 != r && a[i2][c] != Val::ZERO {
                        let f = a[i2][c];
                        for j in c..w {
                            let s = a[r][j] * f;
                            a[i2][j] -= s;
                        }
                    }
                }
                r += 1;
                c += 1;
            }
        }
    }
    r
}

/// Theorem A, checked as an equality of subspaces of `F^|L|`.
fn check_theorem_a(log_n: usize, log_blowup: usize) {
    let n = 1usize << log_n;
    let interp = interpolation_basis(log_n, log_blowup);
    let structural = structural_basis(log_n, log_blowup);
    let (ri, rs) = (rank_all(&interp), rank_all(&structural));
    let rc = rank_concat(&interp, &structural);
    println!(
        "  N = {n:3}: rank(interpolation) = {ri}, rank(a + y·b) = {rs}, rank(concat) = {rc}"
    );
    assert_eq!(ri, n, "the interpolation basis must have full rank N");
    assert_eq!(rs, n, "the structural basis must have full rank N");
    assert_eq!(
        rc, n,
        "equal ranks with a concatenation of the same rank means equal spans"
    );
}

/// Theorem A's corollary: a negation pair kills both parts at one abscissa,
/// so it imposes two conditions that a generic pair of points does not.
fn check_negation_structure(log_n: usize, log_blowup: usize) {
    let pts = domain_points(log_n + log_blowup);
    let m = pts.len();
    // In natural order the negation of index i is index m-1-i.
    for i in 0..m {
        let (x, y) = pts[i];
        let (xn, yn) = pts[m - 1 - i];
        assert_eq!(x, xn, "a negation pair must share its abscissa");
        assert_eq!(y, -yn, "a negation pair must have opposite ordinates");
    }
    // And distinct points with equal abscissa are exactly negation pairs.
    let mut shared = 0usize;
    for i in 0..m {
        for j in (i + 1)..m {
            if pts[i].0 == pts[j].0 {
                shared += 1;
                assert_eq!(j, m - 1 - i, "equal abscissae only for negation pairs");
            }
        }
    }
    println!(
        "  log_n = {log_n}, blowup 2^{log_blowup}: {shared} abscissa-sharing pairs, all negations"
    );
}

/// Theorem B, checked EXHAUSTIVELY where that is finite: every k-subset with
/// k = N/2 is surjective, including the ones containing negation pairs, which
/// the corrected statement no longer needs to exclude.
fn check_theorem_b_exhaustive(log_n: usize, log_blowup: usize) {
    let n = 1usize << log_n;
    let h = n / 2;
    let interp = interpolation_basis(log_n, log_blowup);
    let m = interp.height();
    let mut checked = 0usize;
    let mut with_pairs = 0usize;
    let mut idx: Vec<usize> = (0..h).collect();
    loop {
        let r = rank_rows(&interp, &idx);
        assert_eq!(
            r, h,
            "Theorem B is FALSE at {idx:?}: rank {r}, expected {h}"
        );
        // Does this subset contain a negation pair? (i and m-1-i both present)
        if idx.iter().any(|&i| idx.contains(&(m - 1 - i))) {
            with_pairs += 1;
        }
        checked += 1;
        let mut i = h;
        let done = loop {
            if i == 0 {
                break true;
            }
            i -= 1;
            if idx[i] != i + m - h {
                idx[i] += 1;
                for j in i + 1..h {
                    idx[j] = idx[j - 1] + 1;
                }
                break false;
            }
        };
        if done {
            break;
        }
    }
    println!(
        "  N = {n:3}, k = N/2 = {h:3}: ALL {checked} subsets surjective ({with_pairs} of them contain a negation pair)"
    );
}

/// The same claim spot-checked at deployed sizes, where exhaustion is not
/// finite, together with the Vandermonde block the proof leans on.
fn check_theorem_b(log_n: usize, log_blowup: usize) {
    let n = 1usize << log_n;
    let h = n / 2;
    let interp = interpolation_basis(log_n, log_blowup);
    let m = interp.height();
    // Take the first h points; none of them is the negation of another, since
    // negations sit at m-1-i and h <= m/2.
    let s: Vec<usize> = (0..h).collect();
    let full = rank_rows(&interp, &s);
    // The Vandermonde block alone.
    let pts = domain_points(log_n + log_blowup);
    let vander: Vec<Vec<Val>> = s
        .iter()
        .map(|&j| {
            let mut pow = Val::ONE;
            let mut row = Vec::with_capacity(h);
            for _ in 0..h {
                row.push(pow);
                pow *= pts[j].0;
            }
            row
        })
        .collect();
    let rv = rank(vander);
    println!(
        "  N = {n:3}, k = N/2 = {h:3}: rank(evaluation) = {full}, rank(Vandermonde block) = {rv}"
    );
    assert_eq!(rv, h, "distinct abscissae make the even part full rank");
    assert_eq!(full, h, "a full-rank block forces the whole matrix full rank");
}

/// Theorem C(i): a nonzero element of `L_N` has at most `N` zeros.
///
/// Testing this with RANDOM elements would be vacuous — a random element of
/// `L_N` has no zeros at all on the domain with overwhelming probability, so
/// the assertion would pass without ever approaching the bound. The test has
/// to CONSTRUCT elements with many zeros and push against `N`.
///
/// Construction: pick a set `S` of `j` points, compute the kernel of the
/// evaluation map at `S` by elimination, and take a nonzero kernel element.
/// By definition it vanishes on all of `S`, so it has at least `j` zeros; then
/// count how many it actually has over the whole LDE domain, and report the
/// maximum found. The bound `N` must never be exceeded, and the interesting
/// question is how close the construction gets to it.
fn check_theorem_c_zero_bound(log_n: usize, log_blowup: usize) {
    let n = 1usize << log_n;
    let interp = interpolation_basis(log_n, log_blowup);
    let m = interp.height();
    let mut worst = 0usize;
    let mut worst_at = 0usize;

    // Force as many zeros as the space allows: j = N-1 leaves a kernel of
    // dimension at least 1, and the degenerate sets of Theorem C(iii) push to
    // j = N.
    for j in 1..=n {
        // Every window of j consecutive points, plus the negation-closed
        // families that produced the counterexamples.
        for start in 0..m {
            let mut s: Vec<usize> = (0..j).map(|t| (start + t) % m).collect();
            if j >= 2 {
                // swap the last for the negation of the first: the shape that
                // attains the defect.
                s[j - 1] = m - 1 - start;
            }
            s.sort_unstable();
            s.dedup();
            if s.len() < j {
                continue;
            }
            if let Some(f) = kernel_element(&interp, &s) {
                let mut zeros = 0usize;
                for r in 0..m {
                    let mut acc = Val::ZERO;
                    for (c, coeff) in f.iter().enumerate() {
                        acc += interp.get(r, c).unwrap() * *coeff;
                    }
                    if acc == Val::ZERO {
                        zeros += 1;
                    }
                }
                assert!(
                    zeros <= n,
                    "Theorem C(i) is FALSE: a nonzero element has {zeros} zeros, bound is {n}"
                );
                if zeros > worst {
                    worst = zeros;
                    worst_at = j;
                }
            }
        }
    }
    println!(
        "  N = {n:3}: constructed elements reach {worst} zeros (bound {n}), first attained forcing {worst_at} of them"
    );
    assert!(worst > 0, "the construction must actually produce zeros, or the test is vacuous");
}

/// A nonzero element of `L_N` vanishing on `rows`, or `None` if the only such
/// element is zero. Returned in the interpolation basis.
fn kernel_element(m: &RowMajorMatrix<Val>, rows: &[usize]) -> Option<Vec<Val>> {
    let w = m.width();
    let mut a: Vec<Vec<Val>> = rows
        .iter()
        .map(|&r| (0..w).map(|c| m.get(r, c).unwrap()).collect())
        .collect();
    // Reduced row echelon form, tracking pivot columns.
    let mut pivots: Vec<usize> = Vec::new();
    let (mut r, mut c) = (0usize, 0usize);
    while r < a.len() && c < w {
        let mut piv = None;
        for i in r..a.len() {
            if a[i][c] != Val::ZERO {
                piv = Some(i);
                break;
            }
        }
        match piv {
            None => c += 1,
            Some(i) => {
                a.swap(r, i);
                let inv = a[r][c].inverse();
                for j in c..w {
                    a[r][j] *= inv;
                }
                for i2 in 0..a.len() {
                    if i2 != r && a[i2][c] != Val::ZERO {
                        let f = a[i2][c];
                        for j in c..w {
                            let s = a[r][j] * f;
                            a[i2][j] -= s;
                        }
                    }
                }
                pivots.push(c);
                r += 1;
                c += 1;
            }
        }
    }
    // A free column gives a kernel vector.
    let free = (0..w).find(|c| !pivots.contains(c))?;
    let mut v = vec![Val::ZERO; w];
    v[free] = Val::ONE;
    for (i, &pc) in pivots.iter().enumerate() {
        v[pc] = -a[i][free];
    }
    Some(v)
}

/// Theorem C(ii)+(iii): the rank deficiency is never more than one, and one is
/// attained. Exhaustive at sizes where exhaustion is finite.
fn check_theorem_c_defect(log_n: usize, log_blowup: usize) {
    let n = 1usize << log_n;
    let interp = interpolation_basis(log_n, log_blowup);
    let m = interp.height();
    let mut worst_defect = 0usize;
    let mut witness: Option<Vec<usize>> = None;
    // All k-subsets for k = N (the boundary where degeneracy is possible).
    let k = n;
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        let r = rank_rows(&interp, &idx);
        let d = k - r;
        if d > worst_defect {
            worst_defect = d;
            witness = Some(idx.clone());
        }
        let mut i = k;
        let done = loop {
            if i == 0 {
                break true;
            }
            i -= 1;
            if idx[i] != i + m - k {
                idx[i] += 1;
                for j in i + 1..k {
                    idx[j] = idx[j - 1] + 1;
                }
                break false;
            }
        };
        if done {
            break;
        }
    }
    println!(
        "  N = {n:3}, k = N = {k}: worst deficiency over ALL subsets = {worst_defect}{}",
        match &witness {
            Some(w) if worst_defect > 0 => format!("  attained at {w:?}"),
            _ => String::new(),
        }
    );
    assert!(worst_defect <= 1, "Theorem C(ii) would be false");
    assert_eq!(worst_defect, 1, "Theorem C(iii): defect one should be attained");
}

fn band(n: usize, k: usize) -> String {
    let half = n / 2;
    if k <= half {
        format!("Theorem B band: k = {k} <= N/2 = {half}. UNCONDITIONALLY surjective.")
    } else if k <= n - 1 {
        format!(
            "middle band: N/2 = {half} < k = {k} <= N-1 = {}. Rank >= k-1 unconditionally; \
surjectivity is a property of the point set, decided by computation.",
            n - 1
        )
    } else {
        format!("boundary: k = {k} >= N = {n}. Degenerate sets EXIST here.")
    }
}

fn main() {
    println!("Theorem A — L_N = {{ a(x) + y·b(x) : deg a, deg b < N/2 }}\n");
    for (log_n, log_blowup) in [(2usize, 1usize), (3, 1), (4, 1), (5, 2)] {
        check_theorem_a(log_n, log_blowup);
    }
    println!("\n  corollary — negation is the only way two points share an abscissa:");
    for (log_n, log_blowup) in [(2usize, 1usize), (3, 1)] {
        check_negation_structure(log_n, log_blowup);
    }

    println!("\nTheorem B — k <= N/2 is unconditionally surjective, pairs included\n");
    for (log_n, log_blowup) in [(2usize, 1usize), (3, 1)] {
        check_theorem_b_exhaustive(log_n, log_blowup);
    }
    for (log_n, log_blowup) in [(4usize, 1usize), (5, 2), (6, 2)] {
        check_theorem_b(log_n, log_blowup);
    }

    println!("\nTheorem C(i) — a nonzero element of L_N has at most N zeros\n");
    for (log_n, log_blowup) in [(2usize, 1usize), (3, 1), (4, 1)] {
        check_theorem_c_zero_bound(log_n, log_blowup);
    }

    println!("\nTheorem C(ii,iii) — deficiency is at most one, and one is attained\n");
    for (log_n, log_blowup) in [(2usize, 1usize), (3, 1)] {
        check_theorem_c_defect(log_n, log_blowup);
    }

    println!("\nWhere the deployed configurations sit\n");
    for (name, n, k) in [
        ("crowd binding, 32 rows, 20 queries", 32usize, 21usize),
        ("crowd membership, 32 rows, 20 queries", 32, 22),
        ("binding at 64 rows, 20 queries", 64, 21),
        ("membership at 64 rows, 20 queries", 64, 22),
        ("binding at 64 rows, 30 queries", 64, 31),
    ] {
        println!("  {name}\n    {}", band(n, k));
    }

    println!(
        "\nThe operative sentence: at 32 rows the deployed openings sit ABOVE N/2, so their\n\
         safety rests on a computed rank rather than on Theorem B. At 64 rows the same\n\
         openings fall inside Theorem B, where surjectivity holds for every point set,\n\
         every witness and every adversary, with no computation and no genericity.\n\
         That is what the extra trace height buys, and it is why the next measurement\n\
         to take is the cost of 64 rows at 20 queries."
    );
}
