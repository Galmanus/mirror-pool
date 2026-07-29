//! keccak256 as the transcript / MMCS hash, routed to Solana's `keccak`
//! syscall on-chain and to `p3_keccak`'s software implementation everywhere
//! else.
//!
//! Why this exists, measured: with `p3_keccak::Keccak256Hash` (keccak-f
//! executed as ordinary SBF bytecode) the on-chain verification of a
//! 4-FRI-query `BindingProof` costs 6,170,726 CU — 4.4x Solana's 1.4M
//! per-transaction cap — and a Circle-STARK verifier is hash-dominated:
//! every Fiat-Shamir observation and every MMCS Merkle step is a keccak256
//! call. Solana prices the same function as a syscall
//! (`sol_keccak256`) at a base of ~85 CU plus a small per-byte cost.
//!
//! This is a routing change, not a cryptographic one: both paths compute
//! standard keccak256, so prover (native) and verifier (SBF) produce the
//! same transcript. That equivalence is not merely asserted — it is enforced
//! end to end by Fiat-Shamir itself: if the two ever diverged on any byte,
//! the on-chain verifier's challenges would differ from the prover's and
//! every honest proof would be rejected. The on-chain acceptance test in
//! `programs/riverrun-m31-verifier/tests/cu.rs` is therefore also the
//! cross-implementation equivalence test.

extern crate alloc;

use p3_symmetric::CryptographicHasher;

/// keccak256 with the same `CryptographicHasher<u8, [u8; 32]>` contract as
/// `p3_keccak::Keccak256Hash`, dispatched by target: Solana's keccak syscall
/// under `target_os = "solana"`, `p3_keccak`'s software keccak otherwise.
#[derive(Copy, Clone, Debug)]
pub struct SolKeccak256;

#[cfg(target_os = "solana")]
impl CryptographicHasher<u8, [u8; 32]> for SolKeccak256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: alloc::vec::Vec<u8> = input.into_iter().collect();
        solana_program::keccak::hashv(&[&bytes]).to_bytes()
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let slices: alloc::vec::Vec<&[u8]> = input.into_iter().collect();
        solana_program::keccak::hashv(&slices).to_bytes()
    }
}

#[cfg(not(target_os = "solana"))]
impl CryptographicHasher<u8, [u8; 32]> for SolKeccak256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        p3_keccak::Keccak256Hash.hash_iter(input)
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        p3_keccak::Keccak256Hash.hash_iter_slices(input)
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod tests {
    use super::*;

    #[test]
    fn matches_the_software_keccak_it_replaces() {
        let cases: [&[u8]; 4] = [b"", b"riverrun", &[0u8; 200], &[0xffu8; 31]];
        for case in cases {
            assert_eq!(
                SolKeccak256.hash_iter(case.iter().copied()),
                p3_keccak::Keccak256Hash.hash_iter(case.iter().copied()),
            );
            assert_eq!(
                SolKeccak256.hash_iter_slices([case]),
                p3_keccak::Keccak256Hash.hash_iter_slices([case]),
            );
        }
    }
}
