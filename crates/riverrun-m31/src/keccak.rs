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

/// Soroban guest arm: route to the host's native `keccak256` (metered as one
/// cheap host-function call instead of thousands of metered wasm
/// instructions per keccak-f). Same standard keccak256 as every other arm;
/// the prover stays on software keccak, and Fiat-Shamir enforces that the
/// two implementations agree on every byte or every honest proof would be
/// rejected — the same equivalence argument (and test) as the Solana
/// syscall arm above.
#[cfg(all(
    target_family = "wasm",
    not(target_os = "solana"),
    feature = "soroban-host-keccak"
))]
impl CryptographicHasher<u8, [u8; 32]> for SolKeccak256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: alloc::vec::Vec<u8> = input.into_iter().collect();
        soroban_host_keccak256(&bytes)
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bytes = alloc::vec::Vec::new();
        for s in input {
            bytes.extend_from_slice(s);
        }
        soroban_host_keccak256(&bytes)
    }
}

#[cfg(all(
    target_family = "wasm",
    not(target_os = "solana"),
    feature = "soroban-host-keccak"
))]
fn soroban_host_keccak256(bytes: &[u8]) -> [u8; 32] {
    use soroban_env_common::{Env, U32Val};
    use soroban_env_guest::Guest;

    let g = Guest;
    // Guest-side host errors trap the VM rather than returning, so these
    // Results are infallible in practice; unwrap_or_else keeps this
    // panic-message-free (no fmt machinery in the deployed wasm).
    let input = g
        .bytes_new_from_linear_memory(
            U32Val::from(bytes.as_ptr() as u32),
            U32Val::from(bytes.len() as u32),
        )
        .unwrap_or_else(|_| core::arch::wasm32::unreachable());
    let digest = g
        .compute_hash_keccak256(input)
        .unwrap_or_else(|_| core::arch::wasm32::unreachable());
    let mut out = [0u8; 32];
    g.bytes_copy_to_linear_memory(
        digest,
        U32Val::from(0),
        U32Val::from(out.as_mut_ptr() as u32),
        U32Val::from(32),
    )
    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
    out
}

#[cfg(all(
    not(target_os = "solana"),
    not(all(target_family = "wasm", feature = "soroban-host-keccak"))
))]
impl CryptographicHasher<u8, [u8; 32]> for SolKeccak256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        #[cfg(feature = "keccak-count")]
        {
            let bytes: alloc::vec::Vec<u8> = input.into_iter().collect();
            count::record(bytes.len());
            return p3_keccak::Keccak256Hash.hash_iter(bytes);
        }
        #[cfg(not(feature = "keccak-count"))]
        p3_keccak::Keccak256Hash.hash_iter(input)
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        #[cfg(feature = "keccak-count")]
        {
            let slices: alloc::vec::Vec<&[u8]> = input.into_iter().collect();
            count::record(slices.iter().map(|s| s.len()).sum());
            return p3_keccak::Keccak256Hash.hash_iter_slices(slices);
        }
        #[cfg(not(feature = "keccak-count"))]
        p3_keccak::Keccak256Hash.hash_iter_slices(input)
    }
}

/// Measurement-only keccak call/byte accounting (`keccak-count` feature, std
/// targets only). Exists to size the win of routing keccak to a chain's native
/// hash (Solana syscall did 6.17M→fits; Soroban host function is the open
/// question this answers before any porting work).
#[cfg(feature = "keccak-count")]
pub mod count {
    use core::sync::atomic::{AtomicU64, Ordering};

    static CALLS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn record(len: usize) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// (calls, total input bytes) since the last `reset`.
    pub fn snapshot() -> (u64, u64) {
        (CALLS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed))
    }

    pub fn reset() {
        CALLS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
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
