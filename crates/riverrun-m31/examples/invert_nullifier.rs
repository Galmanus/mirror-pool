//! Recover a credential secret from public on-chain data alone.
//!
//! The crowd relation publishes `nullifier = π(secret ‖ round)` in FULL — all
//! sixteen limbs (`crowd.rs:331`) — while `round` is public too. π is the
//! Poseidon2 permutation, and a permutation is a bijection, so
//!
//!     (secret ‖ round) = π⁻¹(nullifier)
//!
//! is not an attack that needs the proof, the queries, or any interpolation.
//! It is a function of two values the chain already publishes. This example
//! builds π⁻¹ and runs it, so the claim is demonstrated rather than argued.
//!
//! Run: cargo run --release --example invert_nullifier

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_mersenne_31::{
    GenericPoseidon2LinearLayersMersenne31 as LL, Mersenne31,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL, MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    MERSENNE31_POSEIDON2_RC_16_INTERNAL,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use riverrun_m31::permutation::{permute, WIDTH};

type F = Mersenne31;
const P: u64 = (1 << 31) - 1;
/// `5⁻¹ mod (p−1)`, so `x ↦ x^D` inverts the S-box `x ↦ x⁵`. Pinned by
/// `permutation.rs`'s `the_sbox_exponent_is_invertible_over_the_field`.
const D: u64 = 1_717_986_917;

fn pow(mut b: u64, mut e: u64) -> u64 {
    let (mut acc, m) = (1u128, P as u128);
    b %= P;
    let mut base = b as u128;
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % m;
        }
        base = base * base % m;
        e >>= 1;
    }
    acc as u64
}

/// Extract a linear layer as an explicit matrix by evaluating it on the basis.
/// The layers are `PrimeCharacteristicRing`-generic precisely so the AIR can
/// see them symbolically, which also means anyone can read the matrix out.
fn matrix_of(layer: fn(&mut [F; WIDTH])) -> [[u64; WIDTH]; WIDTH] {
    let mut m = [[0u64; WIDTH]; WIDTH];
    for j in 0..WIDTH {
        let mut e = [F::ZERO; WIDTH];
        e[j] = F::ONE;
        layer(&mut e);
        for i in 0..WIDTH {
            m[i][j] = e[i].as_canonical_u32() as u64;
        }
    }
    m
}

/// Gauss-Jordan over F_p.
fn invert(m: [[u64; WIDTH]; WIDTH]) -> [[u64; WIDTH]; WIDTH] {
    let mut a = m;
    let mut inv = [[0u64; WIDTH]; WIDTH];
    for i in 0..WIDTH {
        inv[i][i] = 1;
    }
    for col in 0..WIDTH {
        let piv = (col..WIDTH)
            .find(|&r| a[r][col] != 0)
            .expect("the linear layer must be invertible");
        a.swap(col, piv);
        inv.swap(col, piv);
        let s = pow(a[col][col], P - 2); // Fermat inverse
        for k in 0..WIDTH {
            a[col][k] = (a[col][k] as u128 * s as u128 % P as u128) as u64;
            inv[col][k] = (inv[col][k] as u128 * s as u128 % P as u128) as u64;
        }
        for r in 0..WIDTH {
            if r != col && a[r][col] != 0 {
                let f = a[r][col];
                for k in 0..WIDTH {
                    a[r][k] = (a[r][k] + P - (f as u128 * a[col][k] as u128 % P as u128) as u64) % P;
                    inv[r][k] =
                        (inv[r][k] + P - (f as u128 * inv[col][k] as u128 % P as u128) as u64) % P;
                }
            }
        }
    }
    inv
}

fn apply(m: &[[u64; WIDTH]; WIDTH], v: &[u64; WIDTH]) -> [u64; WIDTH] {
    core::array::from_fn(|i| {
        let mut acc = 0u128;
        for j in 0..WIDTH {
            acc += m[i][j] as u128 * v[j] as u128;
        }
        (acc % P as u128) as u64
    })
}

fn rc(row: [Mersenne31; WIDTH]) -> [u64; WIDTH] {
    core::array::from_fn(|i| row[i].as_canonical_u32() as u64)
}

/// π⁻¹, undoing Poseidon2's rounds in reverse.
fn inverse_permute(out: [u64; WIDTH]) -> [u64; WIDTH] {
    let ext = matrix_of(LL::external_linear_layer::<F>);
    let int = matrix_of(LL::internal_linear_layer::<F>);
    let ext_inv = invert(ext);
    let int_inv = invert(int);

    let rc_init: Vec<[u64; WIDTH]> =
        MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL.iter().map(|r| rc(*r)).collect();
    let rc_final: Vec<[u64; WIDTH]> =
        MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL.iter().map(|r| rc(*r)).collect();
    let rc_int: Vec<u64> = MERSENNE31_POSEIDON2_RC_16_INTERNAL
        .iter()
        .map(|c| c.as_canonical_u32() as u64)
        .collect();

    let mut s = out;
    // Final full rounds, reversed: each is  add RC -> sbox -> M_E.
    for r in rc_final.iter().rev() {
        s = apply(&ext_inv, &s);
        for i in 0..WIDTH {
            s[i] = pow(s[i], D);
            s[i] = (s[i] + P - r[i]) % P;
        }
    }
    // Partial rounds, reversed: add RC to lane 0 -> sbox lane 0 -> M_I.
    for c in rc_int.iter().rev() {
        s = apply(&int_inv, &s);
        s[0] = pow(s[0], D);
        s[0] = (s[0] + P - *c) % P;
    }
    // Initial full rounds, reversed.
    for r in rc_init.iter().rev() {
        s = apply(&ext_inv, &s);
        for i in 0..WIDTH {
            s[i] = pow(s[i], D);
            s[i] = (s[i] + P - r[i]) % P;
        }
    }
    // The very first linear layer.
    apply(&ext_inv, &s)
}

fn main() {
    // A credential secret nobody publishes, and a public challenge.
    let secret: [u64; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    let round: [u64; 8] = [900, 901, 902, 903, 904, 905, 906, 907];

    let mut input = [0u64; WIDTH];
    input[..8].copy_from_slice(&secret);
    input[8..].copy_from_slice(&round);

    // Exactly what crowd.rs publishes: the FULL 16-limb permutation output.
    let nullifier = permute(input);

    println!("published on-chain:");
    println!("  round     = {round:?}");
    println!("  nullifier = {nullifier:?}");
    println!("never published:");
    println!("  secret    = {secret:?}");

    let recovered = inverse_permute(nullifier);
    let recovered_secret = &recovered[..8];
    let recovered_round = &recovered[8..];

    println!("\nrecovered by inverting the permutation on public data alone:");
    println!("  secret    = {recovered_secret:?}");
    println!("  round     = {recovered_round:?}");

    assert_eq!(recovered_round, &round, "the recovered round must match the public one");
    assert_eq!(recovered_secret, &secret, "SECRET RECOVERED FROM PUBLIC DATA");
    println!("\nMATCH. The credential secret is a public function of published values.");

    // Optional second run against a nullifier taken off the chain: pass the
    // sixteen limbs, then the eight round limbs that transaction used. The
    // round coming back out is the check that the inversion is the real one,
    // since nothing about the round was used to compute it.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 24 {
        let v: Vec<u64> = args.iter().map(|a| a.parse().unwrap()).collect();
        let on_chain: [u64; WIDTH] = core::array::from_fn(|i| v[i]);
        let claimed_round: [u64; 8] = core::array::from_fn(|i| v[16 + i]);
        let back = inverse_permute(on_chain);
        println!("\n--- a nullifier taken off the chain ---");
        println!("  recovered secret = {:?}", &back[..8]);
        println!("  recovered round  = {:?}", &back[8..]);
        println!("  round it should be = {claimed_round:?}");
        assert_eq!(&back[8..], &claimed_round, "the recovered round must match");
        println!("  MATCH: this is a real credential secret, read off public data.");
    }
}
