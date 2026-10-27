//! The staged verifier must accept exactly what the monolithic one accepts.
//! Every test here runs at the production crowd parameters (12 queries,
//! blowup 128, 128 rows); nothing is measured at a reduced-security point.

use std::sync::OnceLock;
use std::format;
use std::vec::Vec;

use super::*;
use crate::crowd::{
    prove_binding_crowd, prove_membership_crowd, verify_binding_crowd, verify_membership_crowd,
    CrowdBindingProof, CrowdMembershipProof, BLINDER_LEN, CROWD_DEPTH,
};
use crate::membership::{compress, PathStep};
use crate::binding::SECRET_LEN;
use crate::zk::Seed;

const Q: usize = 12;
const LOG_B: usize = 7;
const LOG_ROWS: usize = 7;
const P: Params = Params { num_queries: Q, log_blowup: LOG_B, recipient: None };

struct Fixture {
    binding: Vec<u8>,
    membership: Vec<u8>,
    action: [u64; CONTEXT_LEN],
    round: [u64; CONTEXT_LEN],
    c: [u64; DIGEST_LEN],
    nullifier: [u64; DIGEST_LEN],
    root: [u64; DIGEST_LEN],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
        let action: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 100 + i as u64);
        let round: [u64; CONTEXT_LEN] = core::array::from_fn(|i| 200 + i as u64);
        let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 7000 + i as u64);
        let (bp, c, leaf, nullifier) = prove_binding_crowd(
            secret, action, round, blinder, Q, LOG_B, LOG_ROWS, Seed::reproducible(42),
        );
        let path: [PathStep; CROWD_DEPTH] = core::array::from_fn(|i| PathStep {
            sibling: core::array::from_fn(|j| (i as u64 + 1) * 4000 + j as u64),
            node_on_right: i % 3 == 1,
        });
        let (mp, c2, root) = prove_membership_crowd(leaf, blinder, &path, Q, LOG_B, Seed::reproducible(43));
        assert_eq!(c, c2);
        let _ = compress;
        Fixture { binding: bp.to_bytes(), membership: mp.to_bytes(), action, round, c, nullifier, root }
    })
}

fn limbs<const N: usize>(v: [u64; N]) -> Vec<u32> {
    v.iter().map(|&x| x as u32).collect()
}

fn binding_publics(f: &Fixture, nullifier: [u64; DIGEST_LEN]) -> Vec<Val> {
    let mut l = limbs(f.action);
    l.extend(limbs(f.round));
    l.extend(limbs(f.c));
    l.extend(limbs(nullifier));
    publics_from_limbs(&l).unwrap()
}

fn membership_publics(f: &Fixture) -> Vec<Val> {
    let mut l = limbs(f.c);
    l.extend(limbs(f.root));
    publics_from_limbs(&l).unwrap()
}

fn mono_binding(bytes: &[u8], f: &Fixture, nullifier: [u64; DIGEST_LEN]) -> bool {
    CrowdBindingProof::from_bytes(bytes)
        .is_some_and(|p| verify_binding_crowd(&p, f.action, f.round, f.c, nullifier, Q, LOG_B))
}

fn staged_binding(bytes: &[u8], f: &Fixture, nullifier: [u64; DIGEST_LEN], batch: usize) -> bool {
    verify_staged_bytes(Relation::Binding, P, bytes, &binding_publics(f, nullifier), batch)
}

fn mono_membership(bytes: &[u8], f: &Fixture) -> bool {
    CrowdMembershipProof::from_bytes(bytes)
        .is_some_and(|p| verify_membership_crowd(&p, f.c, f.root, Q, LOG_B))
}

fn staged_membership(bytes: &[u8], f: &Fixture, batch: usize) -> bool {
    verify_staged_bytes(Relation::Membership, P, bytes, &membership_publics(f), batch)
}

#[test]
fn honest_proofs_verify_both_ways_at_every_batch_size() {
    let f = fixture();
    std::println!("crowd binding: {} B bincode, membership: {} B bincode", f.binding.len(), f.membership.len());
    assert!(mono_binding(&f.binding, f, f.nullifier));
    assert!(mono_membership(&f.membership, f));
    for batch in [1, 2, 3, 4, 12] {
        assert!(staged_binding(&f.binding, f, f.nullifier, batch), "binding, batch {batch}");
        assert!(staged_membership(&f.membership, f, batch), "membership, batch {batch}");
    }
}

/// The index cuts the canonical bytes exactly: each query span and the spliced
/// header decode and re-serialize to the very bytes they were cut from.
#[test]
fn the_index_cuts_the_canonical_bytes_exactly() {
    let f = fixture();
    for bytes in [&f.binding, &f.membership] {
        let idx = index_proof(bytes).expect("index");
        assert_eq!(idx.num_query_proofs(), Q);
        assert_eq!(idx.end, bytes.len(), "an honest to_bytes() has no trailing bytes");
        assert_eq!(idx.bounds[0], idx.queries_at + 8);
        for i in 0..Q {
            let qp = decode_query(bytes, &idx, i).expect("query decodes");
            let re = bincode::serialize(&qp).unwrap();
            assert_eq!(&re[..], &bytes[idx.bounds[i]..idx.bounds[i + 1]], "query {i}");
        }
        let header = decode_header(bytes, &idx).expect("header decodes");
        let re = bincode::serialize(&header).unwrap();
        let mut spliced = bytes[..idx.queries_at].to_vec();
        spliced.extend_from_slice(&0u64.to_le_bytes());
        spliced.extend_from_slice(&bytes[idx.bounds[Q]..idx.end]);
        assert_eq!(re, spliced);
        std::println!(
            "header {} B, query spans {:?} B",
            spliced.len(),
            (0..Q).map(|i| idx.bounds[i + 1] - idx.bounds[i]).collect::<Vec<_>>()
        );
    }
}

#[test]
fn the_transcript_round_trips_its_encoding() {
    let f = fixture();
    let idx = index_proof(&f.binding).unwrap();
    let header = decode_header(&f.binding, &idx).unwrap();
    let t = stage_transcript(Relation::Binding, P, &header, &binding_publics(f, f.nullifier), Q).unwrap();
    let enc = t.encode();
    assert_eq!(enc.len(), Transcript::encoded_len(t.betas.len(), t.indices.len(), t.claim_sums.len()));
    assert_eq!(Transcript::decode(&enc).unwrap(), t);
    std::println!("transcript: {} FRI rounds, {} B encoded, indices {:?}", t.betas.len(), enc.len(), t.indices);
}

/// The refactor itself, against the code it replaced: the split uni-stark body
/// vs its verbatim upstream reference, and the split circle PCS `verify` vs its
/// verbatim upstream reference, on honest and tampered inputs.
#[test]
fn the_split_verifier_agrees_with_the_upstream_reference() {
    use p3_uni_stark::{verify_with_known_quotient_chunks, verify_with_known_quotient_chunks_upstream_reference};
    let f = fixture();
    let config = super::config(P);
    let air = CrowdBindingAir::new();
    let honest = CrowdBindingProof::from_bytes(&f.binding).unwrap();
    let mut wrong_n = f.nullifier;
    wrong_n[3] ^= 1;
    for (label, n, expect) in [("honest", f.nullifier, true), ("wrong nullifier", wrong_n, false)] {
        let pis = binding_publics(f, n);
        let a = verify_with_known_quotient_chunks(&config, &air, &honest.inner, &pis, None, CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS).is_ok();
        let b = verify_with_known_quotient_chunks_upstream_reference(&config, &air, &honest.inner, &pis, None, CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS).is_ok();
        assert_eq!((a, b), (expect, expect), "{label}");
    }

    // PCS level: same rounds, same challenger state, split vs upstream body.
    let pis = binding_publics(f, f.nullifier);
    let check_pcs = |proof: &ZkProofHeader| -> (bool, bool) {
        let shape = verifier_shape(&config, &air, proof, &pis, None, CROWD_BINDING_LOG_NUM_QUOTIENT_CHUNKS).unwrap();
        let (ch, _, zeta) = verifier_transcript(&config, proof, &shape, &pis).unwrap();
        let mut rounds = opening_claims(proof, &shape, zeta).unwrap();
        let (rand, inner) = &proof.opening_proof;
        rejoin_random_openings::<_, _, _, (), ()>(&mut rounds, rand).unwrap();
        let split = config.pcs().inner.verify_staged_setup(&rounds, inner, Q, &mut ch.clone()).is_ok() && {
            use p3_commit::Pcs;
            <_ as Pcs<Challenge, Challenger>>::verify(&config.pcs().inner, rounds.clone(), inner, &mut ch.clone()).is_ok()
        };
        let upstream = config.pcs().inner.verify_upstream_reference::<Challenge, Challenger>(rounds, inner, &mut ch.clone()).is_ok();
        (split, upstream)
    };
    assert_eq!(check_pcs(&honest.inner), (true, true));
    // Tamper inside the PCS proof (query proofs, FRI data): flip bytes past the
    // header's opened values and compare both PCS bodies on what still decodes.
    let idx = index_proof(&f.binding).unwrap();
    let mut compared = 0;
    for off in (idx.bounds[0]..idx.end).step_by(997) {
        let mut b = f.binding.clone();
        b[off] ^= 0x01;
        if let Some(p) = CrowdBindingProof::from_bytes(&b) {
            let (s, u) = check_pcs(&p.inner);
            assert_eq!(s, u, "split and upstream PCS disagree at byte {off}");
            assert!(!s, "a flipped byte at {off} must not verify");
            compared += 1;
        }
    }
    assert!(compared > 20, "the sweep must actually compare something ({compared})");
}

/// Targeted tampering of each named region: monolithic and staged both reject.
#[test]
fn tampered_regions_are_rejected_by_both_paths() {
    let f = fixture();
    let idx = index_proof(&f.binding).unwrap();
    let n = idx.num_query_proofs();
    let cases: Vec<(&str, usize)> = vec![
        ("trace commitment", 8 + 5),
        ("first opened trace value", {
            // commitments: trace cap (8 + 32), quotient cap (8 + 32), Some(random cap) (1 + 8 + 32)
            (8 + 32) * 2 + 1 + 8 + 32 + 8 + 2
        }),
        ("query 5 input opening", idx.bounds[5] + 8 + 8 + 8 + 1),
        ("query 11 last byte", idx.bounds[n] - 1),
        ("FRI final poly", idx.bounds[n] + 2),
        ("query PoW witness", idx.bounds[n] + 16),
        ("degree_bits", idx.bounds[n] + 16 + 4),
    ];
    for (label, off) in cases {
        let mut b = f.binding.clone();
        b[off] ^= 0x01;
        let m = mono_binding(&b, f, f.nullifier);
        let s = staged_binding(&b, f, f.nullifier, 3);
        assert_eq!((m, s), (false, false), "{label} (byte {off})");
    }
    // A public input, not the proof.
    let mut wrong = f.nullifier;
    wrong[0] ^= 1;
    assert!(!mono_binding(&f.binding, f, wrong));
    assert!(!staged_binding(&f.binding, f, wrong, 3));
}

/// A sweep of single-bit flips across the WHOLE proof, both relations: the two
/// paths must agree on every one (and every one must be rejected).
#[test]
fn a_byte_flip_sweep_never_separates_the_two_paths() {
    let f = fixture();
    let mut checked = 0;
    for (rel, bytes) in [(Relation::Binding, &f.binding), (Relation::Membership, &f.membership)] {
        let step = bytes.len() / 150;
        for off in (0..bytes.len()).step_by(step).chain([bytes.len() - 1]) {
            for bit in [0u8, 6] {
                let mut b = bytes.clone();
                b[off] ^= 1 << bit;
                let (m, s) = match rel {
                    Relation::Binding => (mono_binding(&b, f, f.nullifier), staged_binding(&b, f, f.nullifier, 4)),
                    Relation::Membership => (mono_membership(&b, f), staged_membership(&b, f, 4)),
                };
                assert_eq!(m, s, "{rel:?}: paths disagree on bit {bit} of byte {off}");
                assert!(!m, "{rel:?}: a flip at byte {off} bit {bit} was accepted");
                checked += 1;
            }
        }
    }
    std::println!("{checked} single-bit flips, all rejected by both paths");
}

/// Stage-level misuse: the persisted transcript and query proofs are bound to
/// the proof they came from and to their position.
#[test]
fn stages_reject_mixed_proofs_and_wrong_positions() {
    let f = fixture();
    let pis = binding_publics(f, f.nullifier);
    let idx = index_proof(&f.binding).unwrap();
    let header = decode_header(&f.binding, &idx).unwrap();
    let t = stage_transcript(Relation::Binding, P, &header, &pis, Q).unwrap();
    let q0 = decode_query(&f.binding, &idx, 0).unwrap();
    let q1 = decode_query(&f.binding, &idx, 1).unwrap();
    let quotient = stage_quotient(Relation::Binding, P, &header, &pis, &t).unwrap();
    assert!(stage_ood(Relation::Binding, P, &header, &pis, &t, quotient));
    // A wrong persisted quotient is refused.
    assert!(!stage_ood(Relation::Binding, P, &header, &pis, &t, quotient + Challenge::ONE));
    assert!(stage_queries(Relation::Binding, P, &header, &pis, &t, &[(0, q0.clone())]));
    // Query proof 1 presented as query 0, and vice versa.
    assert!(!stage_queries(Relation::Binding, P, &header, &pis, &t, &[(0, q1.clone())]));
    assert!(!stage_queries(Relation::Binding, P, &header, &pis, &t, &[(1, q0.clone())]));
    // A position past the last query.
    assert!(!stage_queries(Relation::Binding, P, &header, &pis, &t, &[(Q, q0.clone())]));

    // A second, independently valid proof of the same statement (fresh seed):
    // its query proofs and transcript must not mix with the first's.
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 7000 + i as u64);
    let (other, ..) = prove_binding_crowd(secret, f.action, f.round, blinder, Q, LOG_B, LOG_ROWS, Seed::reproducible(99));
    let ob = other.to_bytes();
    assert!(staged_binding(&ob, f, f.nullifier, 12), "the second proof is itself valid");
    let oidx = index_proof(&ob).unwrap();
    let oheader = decode_header(&ob, &oidx).unwrap();
    let ot = stage_transcript(Relation::Binding, P, &oheader, &pis, Q).unwrap();
    let oq0 = decode_query(&ob, &oidx, 0).unwrap();
    assert_ne!(t, ot);
    // Other proof's query under our transcript/header.
    assert!(!stage_queries(Relation::Binding, P, &header, &pis, &t, &[(0, oq0.clone())]));
    // Our transcript with the other header (proof swapped after setup).
    let oq = stage_quotient(Relation::Binding, P, &oheader, &pis, &t).unwrap();
    assert!(!stage_ood(Relation::Binding, P, &oheader, &pis, &t, oq));
    assert!(!stage_ood(Relation::Binding, P, &oheader, &pis, &t, quotient));
    assert!(!stage_queries(Relation::Binding, P, &oheader, &pis, &t, &[(0, oq0)]));
    // A membership transcript is not a binding one.
    assert!(stage_transcript(Relation::Membership, P, &header, &pis, Q).is_none());
}

/// The two exact rearrangements made for SBF cost, value for value against
/// the upstream code they replace: the quotient recomposition (at the real
/// zeta of both proofs and at 64 pseudo-random points) and the DEEP input
/// reduction (every query of both proofs: identical reduced openings for the
/// honest claims; the identical refusal when one claimed value is perturbed).
#[test]
fn the_cost_rearrangements_compute_the_same_field_elements() {
    use p3_uni_stark::{recompose_quotient_from_chunks, recompose_quotient_from_chunks_upstream_reference};
    let f = fixture();
    let config = super::config(P);
    for (rel, bytes, pis) in [
        (Relation::Binding, &f.binding, binding_publics(f, f.nullifier)),
        (Relation::Membership, &f.membership, membership_publics(f)),
    ] {
        let idx = index_proof(bytes).unwrap();
        let header = decode_header(bytes, &idx).unwrap();
        let proof = match rel {
            Relation::Binding => CrowdBindingProof::from_bytes(bytes).unwrap().inner,
            Relation::Membership => CrowdMembershipProof::from_bytes(bytes).unwrap().inner,
        };
        let shape = with_air!(rel, |air, lnqc| verifier_shape(&config, &air, &header, &pis, None, lnqc).ok().unwrap());
        let (ch, _, zeta) = verifier_transcript(&config, &header, &shape, &pis).unwrap();

        // Quotient recomposition.
        let chunks = &header.opened_values.quotient_chunks;
        let mut point = zeta;
        for k in 0..65 {
            let a = recompose_quotient_from_chunks::<ZkConfig>(&shape.quotient_chunks_domains, chunks, point);
            let b = recompose_quotient_from_chunks_upstream_reference::<ZkConfig>(&shape.quotient_chunks_domains, chunks, point);
            assert_eq!(a, b, "{rel:?}: recomposition differs at point {k}");
            point = point * zeta + Challenge::from_u32(k + 7);
        }

        // DEEP input reduction, honest claims then a perturbed claim.
        for perturb in [false, true] {
            let mut rounds = opening_claims(&header, &shape, zeta).unwrap();
            let (rand, inner) = &header.opening_proof;
            rejoin_random_openings::<_, _, _, (), ()>(&mut rounds, rand).unwrap();
            if perturb {
                rounds[1].1[0].1[0].1[3] += Challenge::ONE;
            }
            let setup = config.pcs().inner.verify_staged_setup(&rounds, inner, Q, &mut ch.clone());
            // A perturbed claim moves every challenge; the PoW check may then
            // refuse the transcript (probability 255/256). Re-derive the setup
            // from the honest claims in that case: the comparison only needs
            // SOME alpha and indices, applied identically to both reductions.
            let setup = match setup {
                Ok(s) => s,
                Err(_) => {
                    let mut honest = opening_claims(&header, &shape, zeta).unwrap();
                    rejoin_random_openings::<_, _, _, (), ()>(&mut honest, rand).unwrap();
                    let mut s = config.pcs().inner.verify_staged_setup(&honest, inner, Q, &mut ch.clone()).unwrap();
                    s.claim_sums = recompute_claim_sums(&rounds, s.alpha);
                    s
                }
            };
            for q in 0..Q {
                let qp = decode_query(bytes, &idx, q).unwrap();
                let (opt, reference) = config.pcs().inner.compare_open_input(&rounds, inner, &setup, q, &qp);
                if perturb {
                    // A wrong claim moves every reduced opening, so the
                    // first-layer Merkle check downstream refuses: both sides
                    // must refuse identically.
                    assert_eq!(
                        format!("{:?}", opt.err()),
                        format!("{:?}", reference.err()),
                        "{rel:?}: query {q} perturbed outcomes differ"
                    );
                } else {
                    assert_eq!(opt.unwrap(), reference.unwrap(), "{rel:?}: query {q} reduced openings differ");
                }
            }
        }
        let _ = proof;
    }
}

/// `sum_k alpha^k * values[k]` per claim, the test's independent computation
/// (forward powers, not Horner).
fn recompute_claim_sums(rounds: &[p3_circle::CircleOpeningRound<Val, Challenge, <ZkValMmcs as p3_commit::Mmcs<Val>>::Commitment>], alpha: Challenge) -> Vec<Challenge> {
    rounds
        .iter()
        .flat_map(|(_, mats)| mats.iter())
        .flat_map(|(_, pv)| pv.iter())
        .map(|(_, values)| {
            let mut pow = Challenge::ONE;
            let mut acc = Challenge::ZERO;
            for &v in values {
                acc += pow * v;
                pow *= alpha;
            }
            acc
        })
        .collect()
}

/// Non-canonical limbs are refused before any verification runs.
#[test]
fn non_canonical_public_limbs_are_refused() {
    assert!(publics_from_limbs(&[(1 << 31) - 1]).is_none());
    assert!(publics_from_limbs(&[u32::MAX]).is_none());
    assert!(publics_from_limbs(&[(1 << 31) - 2]).is_some());
}

/// Item 3, the front-running fix: a recipient-bound proof verifies only for
/// the recipient it was made for, through both paths, and a copy re-targeted
/// at another recipient (or presented as unbound) is rejected by both.
#[test]
fn a_recipient_bound_proof_verifies_only_for_its_recipient() {
    use crate::crowd::{
        prove_binding_crowd_for, prove_membership_crowd_for, verify_binding_crowd_for,
        verify_membership_crowd_for,
    };
    let f = fixture();
    let alice = [0xA1u8; 32];
    let mallory = [0x3Au8; 32];
    let secret: [u64; SECRET_LEN] = core::array::from_fn(|i| 1000 + i as u64);
    let blinder: [u64; BLINDER_LEN] = core::array::from_fn(|i| 7000 + i as u64);
    let (bp, c, leaf, n) = prove_binding_crowd_for(
        &alice, secret, f.action, f.round, blinder, Q, LOG_B, LOG_ROWS, Seed::reproducible(5),
    );
    assert_eq!((c, n), (f.c, f.nullifier), "binding to a recipient changes no public value");
    let path: [PathStep; CROWD_DEPTH] = core::array::from_fn(|i| PathStep {
        sibling: core::array::from_fn(|j| (i as u64 + 1) * 4000 + j as u64),
        node_on_right: i % 3 == 1,
    });
    let (mp, _, root) =
        prove_membership_crowd_for(&alice, leaf, blinder, &path, Q, LOG_B, Seed::reproducible(6));
    assert_eq!(root, f.root);
    let (bb, mb) = (bp.to_bytes(), mp.to_bytes());
    let bpis = binding_publics(f, f.nullifier);
    let mpis = membership_publics(f);
    let staged = |rel, bytes: &[u8], pis: &[Val], r: Option<[u8; 32]>| {
        verify_staged_bytes(rel, Params { recipient: r, ..P }, bytes, pis, 4)
    };
    // Its own recipient: both paths accept.
    assert!(verify_binding_crowd_for(&alice, &bp, f.action, f.round, f.c, f.nullifier, Q, LOG_B));
    assert!(verify_membership_crowd_for(&alice, &mp, f.c, f.root, Q, LOG_B));
    assert!(staged(Relation::Binding, &bb, &bpis, Some(alice)));
    assert!(staged(Relation::Membership, &mb, &mpis, Some(alice)));
    // Re-targeted to another recipient, or presented as unbound: both reject.
    assert!(!verify_binding_crowd_for(&mallory, &bp, f.action, f.round, f.c, f.nullifier, Q, LOG_B));
    assert!(!verify_binding_crowd(&bp, f.action, f.round, f.c, f.nullifier, Q, LOG_B));
    assert!(!verify_membership_crowd_for(&mallory, &mp, f.c, f.root, Q, LOG_B));
    assert!(!staged(Relation::Binding, &bb, &bpis, Some(mallory)));
    assert!(!staged(Relation::Binding, &bb, &bpis, None));
    assert!(!staged(Relation::Membership, &mb, &mpis, Some(mallory)));
    // And an unbound proof is not accepted as bound to anyone.
    assert!(!staged(Relation::Binding, &f.binding, &bpis, Some(alice)));
}
