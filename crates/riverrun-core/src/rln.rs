//! Rate-limiting the cloak — act at most `N` times per context, and the `N+1`-th
//! act unmasks you.
//!
//! The other powers of the [rotatable piece](crate::rotatable) hide *who* acted.
//! This one adds an accountable rate limit **without** giving that up, using Shamir
//! secret sharing:
//!
//! - For a context `θ` with limit `N`, the holder's identity `s` is the constant
//!   term of a degree-`N` polynomial `P` whose other coefficients are derived
//!   deterministically from `s` and `θ` (so the holder cannot lie about `P`).
//! - Each action reveals **one point** `(x, P(x))`, where `x` comes from the action
//!   itself (so the point cannot be chosen freely). One point per action.
//! - Up to `N` points leave `P` (degree `N`) under-determined: `s` stays hidden, the
//!   holder stays anonymous. The `N+1`-th point over-determines `P`: anyone can
//!   Lagrange-interpolate `P(0) = s` and unmask the over-actor. Spam is priced in
//!   your own de-anonymization.
//!
//! This is the standard RLN (rate-limiting nullifier) construction, over a prime
//! field, keyed by a hash-derived polynomial — post-quantum and transparent like the
//! rest of `riverrun-core`. The field arithmetic here is a small, self-contained
//! `p = 2^61 - 1` implementation; a production circuit would use the pool's STARK
//! field, but the relation and the recovery are identical.

use crate::commitment::Secret;
use crate::{tagged_hash, Hash};

/// The prime field the shares live in: the Mersenne prime `2^61 - 1`. Small enough
/// that products fit in a `u128`, large enough that a hash-derived point is
/// effectively uniform.
const P: u128 = (1u128 << 61) - 1;

const RLN_COEF: &[u8] = b"riverrun/rln-coef/v1";
const RLN_X: &[u8] = b"riverrun/rln-x/v1";

/// What can go wrong recovering a secret from shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlnError {
    /// Two interpolation points share an `x`-coordinate — a malformed or adversarial
    /// transcript. Recovery at `x=0` is undefined, so [`recover`] refuses rather than
    /// dividing by zero. Callers must supply points with distinct `x`.
    DuplicateX,
}

fn fadd(a: u128, b: u128) -> u128 {
    (a + b) % P
}
fn fsub(a: u128, b: u128) -> u128 {
    (a + P - b % P) % P
}
fn fmul(a: u128, b: u128) -> u128 {
    (a % P) * (b % P) % P
}
fn fpow(mut a: u128, mut e: u128) -> u128 {
    let mut r = 1u128;
    a %= P;
    while e > 0 {
        if e & 1 == 1 {
            r = fmul(r, a);
        }
        a = fmul(a, a);
        e >>= 1;
    }
    r
}
/// Multiplicative inverse via Fermat's little theorem (`a^(p-2)`); `a` must be nonzero.
fn finv(a: u128) -> u128 {
    fpow(a, P - 2)
}

/// Map a 32-byte value to a field element (its first 8 bytes, reduced).
fn to_field(bytes: &[u8; 32]) -> u128 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[..8]);
    (u64::from_le_bytes(b) as u128) % P
}

/// The identity value that the `N+1`-th action recovers: the piece's secret, as a
/// field element. This is what unmasks an over-actor.
pub fn identity(secret: &Secret) -> u128 {
    to_field(secret.as_bytes())
}

/// The `i`-th (1-based) polynomial coefficient for `(secret, θ)`: `H(secret ‖ θ ‖ i)`
/// reduced to the field. Deterministic and bound to the context, so the holder
/// commits to one polynomial per context and cannot equivocate.
fn coefficient(secret: &Secret, theta: u64, i: usize) -> u128 {
    let h: Hash = tagged_hash(
        RLN_COEF,
        &[secret.as_bytes(), &theta.to_le_bytes(), &(i as u64).to_le_bytes()],
    );
    to_field(&h)
}

/// The action point `x` for a use in context `θ` acting on `action`:
/// `H(RLN_X ‖ θ ‖ action)` reduced to the field (remapped away from `0`).
///
/// Deriving `x` from the action content — rather than letting the actor choose it — is
/// a **security requirement**, not a convenience. It makes `x` unpredictable and binds
/// it to the act, so (a) two distinct actions yield two distinct points, which is what
/// makes the `N+1`-th action over-determine the polynomial, and (b) an actor cannot
/// suppress that point by replaying an `x`, nor pick `x=0` (which would publish `P(0)=s`
/// directly). This is the invariant the whole rate limit rests on.
pub fn action_point(theta: u64, action: &[u8]) -> u128 {
    let h: Hash = tagged_hash(RLN_X, &[&theta.to_le_bytes(), action]);
    match to_field(&h) {
        0 => 1, // x=0 would reveal the secret as P(0); ~2^-61 event, remapped
        x => x,
    }
}

/// The `(x, P(x))` point a use publishes, with `x` correctly derived from the action
/// via [`action_point`]. **Prefer this** over calling [`share`] with a hand-chosen `x`;
/// the low-level `share` is for callers who derive `x` themselves and understand the
/// invariant above.
pub fn share_for_action(secret: &Secret, theta: u64, limit: usize, action: &[u8]) -> (u128, u128) {
    let x = action_point(theta, action);
    (x, share(secret, theta, limit, x))
}

/// The share revealed by one action: `P(x) = s + a_1·x + … + a_N·x^N`, where the
/// action's point is `x`. `limit` is `N` (the number of actions allowed before the
/// secret leaks). Returns the field element `P(x)`; the pair `(x, P(x))` is what the
/// action publishes.
///
/// `x` **must** be unpredictable, nonzero, and unique per action — use [`action_point`]
/// (or [`share_for_action`]) to produce it. A freely chosen or repeated `x` breaks the
/// rate limit; `x=0` publishes the secret.
pub fn share(secret: &Secret, theta: u64, limit: usize, x: u128) -> u128 {
    let x = x % P;
    let mut acc = identity(secret); // P(0) = s
    let mut xp = 1u128;
    for i in 1..=limit {
        xp = fmul(xp, x);
        acc = fadd(acc, fmul(coefficient(secret, theta, i), xp));
    }
    acc
}

/// Recover `P(0)` from a set of `(x, P(x))` points by Lagrange interpolation at 0.
/// Given `N+1` genuine points from the same context, this returns the holder's
/// [`identity`] — the over-actor is unmasked. Given fewer than `N+1`, it interpolates
/// a *different* polynomial and returns some other value, so `s` stays hidden.
///
/// Returns [`RlnError::DuplicateX`] if two points share an `x` (a malformed or
/// adversarial transcript). It does **not** panic: recovery runs on inputs an attacker
/// may craft, so a bad transcript must be an error, not a crash.
pub fn recover(points: &[(u128, u128)]) -> Result<u128, RlnError> {
    let mut acc = 0u128;
    for (j, &(xj, yj)) in points.iter().enumerate() {
        let mut num = 1u128; // ∏_{m≠j} (0 - x_m)
        let mut den = 1u128; // ∏_{m≠j} (x_j - x_m)
        for (m, &(xm, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            num = fmul(num, fsub(0, xm));
            let d = fsub(xj, xm);
            if d == 0 {
                return Err(RlnError::DuplicateX);
            }
            den = fmul(den, d);
        }
        acc = fadd(acc, fmul(yj, fmul(num, finv(den))));
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes([byte; 32])
    }

    #[test]
    fn the_n_plus_one_th_action_unmasks_the_over_actor() {
        // limit N=2: two actions are fine, the third recovers the secret.
        let s = secret(1);
        let theta = 42u64;
        let limit = 2;
        // three distinct action points in the same context
        let pts: Vec<(u128, u128)> = [7u128, 99, 12345]
            .iter()
            .map(|&x| (x, share(&s, theta, limit, x)))
            .collect();
        assert_eq!(recover(&pts).unwrap(), identity(&s), "N+1 points must recover the secret");
    }

    #[test]
    fn staying_under_the_limit_keeps_the_secret_hidden() {
        // Only N=2 points revealed (the limit): the degree-2 secret is not pinned.
        let s = secret(1);
        let theta = 42u64;
        let limit = 2;
        let pts: Vec<(u128, u128)> =
            [7u128, 99].iter().map(|&x| (x, share(&s, theta, limit, x))).collect();
        // interpolating 2 points as a line gives a different constant term than s
        assert_ne!(recover(&pts).unwrap(), identity(&s), "N points must not reveal the secret");
    }

    #[test]
    fn points_from_different_contexts_do_not_combine() {
        // Acting once in each of three different epochs is NOT over-acting: the
        // polynomials differ, so the points do not lie on one curve and recovery
        // yields garbage, not the secret.
        let s = secret(1);
        let limit = 2;
        let pts: Vec<(u128, u128)> = [(100u64, 7u128), (200, 7), (300, 7)]
            .iter()
            .map(|&(theta, x)| (x + theta as u128, share(&s, theta, limit, x)))
            .collect();
        assert_ne!(recover(&pts).unwrap(), identity(&s), "cross-context points must not unmask");
    }

    #[test]
    fn a_share_is_deterministic() {
        let s = secret(1);
        assert_eq!(share(&s, 42, 2, 7), share(&s, 42, 2, 7));
        // and different actors give different shares at the same point
        assert_ne!(share(&s, 42, 2, 7), share(&secret(2), 42, 2, 7));
    }

    #[test]
    fn field_inverse_is_correct() {
        for a in [1u128, 2, 3, 7, 12345, P - 1] {
            assert_eq!(fmul(a, finv(a)), 1, "a * a^-1 must be 1");
        }
    }

    #[test]
    fn the_action_point_is_bound_to_the_action_and_context() {
        // F2: x is derived from the action, so distinct actions give distinct points,
        // the same action is deterministic, and the context separates them.
        assert_ne!(action_point(1, b"buy"), action_point(1, b"sell"), "distinct actions -> distinct x");
        assert_eq!(action_point(1, b"buy"), action_point(1, b"buy"), "deterministic");
        assert_ne!(action_point(1, b"buy"), action_point(2, b"buy"), "context separates x");
        // and x is never 0 (x=0 would publish P(0)=s)
        for a in [b"".as_slice(), b"buy", b"x", b"a longer action payload"] {
            assert_ne!(action_point(7, a), 0, "x must never be 0");
        }
    }

    #[test]
    fn share_for_action_uses_the_derived_point() {
        let s = secret(1);
        let (x, y) = share_for_action(&s, 42, 2, b"vote yes");
        assert_eq!(x, action_point(42, b"vote yes"));
        assert_eq!(y, share(&s, 42, 2, x));
    }

    #[test]
    fn n_plus_one_distinct_actions_unmask_via_action_point() {
        // The rate limit enforced end-to-end through the safe API: limit N=2, three
        // distinct actions in one context each yield a distinct point, and the third
        // over-determines the polynomial, recovering the secret.
        let s = secret(1);
        let theta = 42u64;
        let pts: Vec<(u128, u128)> = [b"act-1".as_slice(), b"act-2", b"act-3"]
            .iter()
            .map(|a| share_for_action(&s, theta, 2, a))
            .collect();
        assert_eq!(recover(&pts).unwrap(), identity(&s), "N+1 distinct actions unmask");
    }

    #[test]
    fn recover_errors_on_duplicate_x_instead_of_panicking() {
        // F3: a malformed transcript (two points sharing an x) is an error, not a crash.
        let pts = [(7u128, 100u128), (7u128, 200u128)];
        assert_eq!(recover(&pts), Err(RlnError::DuplicateX));
    }
}
