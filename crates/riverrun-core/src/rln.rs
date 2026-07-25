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

/// The share revealed by one action: `P(x) = s + a_1·x + … + a_N·x^N`, where the
/// action's point is `x`. `limit` is `N` (the number of actions allowed before the
/// secret leaks). Returns the field element `P(x)`; the pair `(x, P(x))` is what the
/// action publishes.
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
/// Panics if two points share an `x` (a malformed transcript, not a normal input).
pub fn recover(points: &[(u128, u128)]) -> u128 {
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
            assert!(d != 0, "duplicate x in interpolation");
            den = fmul(den, d);
        }
        acc = fadd(acc, fmul(yj, fmul(num, finv(den))));
    }
    acc
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
        assert_eq!(recover(&pts), identity(&s), "N+1 points must recover the secret");
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
        assert_ne!(recover(&pts), identity(&s), "N points must not reveal the secret");
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
        assert_ne!(recover(&pts), identity(&s), "cross-context points must not unmask");
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
}
