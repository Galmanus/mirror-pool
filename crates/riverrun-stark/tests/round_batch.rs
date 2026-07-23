//! One round, one proof.
//!
//! riverrun's whole thesis is a *synchronized round*: k members perform the same
//! action at the same time. That is precisely the structure that batches. Proving
//! each member separately costs k proofs and k verifications — 64 members is
//! 1.09 MB of proof. Laying the k sub-traces into one trace costs one proof and
//! one verification.
//!
//! A pairing-based system batches only through recursion, which is a different
//! and much harder project than making a trace longer.

use riverrun_stark::{
    leaf_of, nullifier, prove_round, verify_round, BaseElement, Hash, MembershipSet, RoundClaim,
};

fn action(tag: u128) -> [BaseElement; 2] {
    [BaseElement::new(0xAC01 + tag), BaseElement::new(0xAC02 + tag)]
}

fn secret(i: u128) -> [BaseElement; 2] {
    [BaseElement::new(1000 + i), BaseElement::new(2000 + i)]
}

/// A 4-member set where every member committed the same action.
fn round_set(act: [BaseElement; 2]) -> MembershipSet {
    MembershipSet::new((0..4u128).map(|i| leaf_of(secret(i), act)).collect())
}

#[test]
fn a_whole_round_settles_with_one_proof() {
    let act = action(0);
    let set = round_set(act);
    let round = BaseElement::new(7);
    let members: Vec<(usize, [BaseElement; 2])> =
        (0..4).map(|i| (i, secret(i as u128))).collect();

    let proof = prove_round(&set, &members, round, act);

    let claim = RoundClaim {
        root: set.root(),
        round,
        action: act,
        nullifiers: (0..4).map(|i| nullifier(secret(i as u128), round)).collect(),
    };
    assert!(verify_round(&claim, &proof), "the whole round verifies at once");
}

#[test]
fn one_proof_is_far_smaller_than_one_proof_per_member() {
    let act = action(0);
    let set = round_set(act);
    let round = BaseElement::new(7);
    let members: Vec<(usize, [BaseElement; 2])> =
        (0..4).map(|i| (i, secret(i as u128))).collect();

    let batched = prove_round(&set, &members, round, act).len();
    let separate: usize = members
        .iter()
        .map(|(i, s)| set.prove_bound(*s, *i, round, act).len())
        .sum();

    println!("BATCH 4 members: batched {batched} B vs separate {separate} B");
    assert!(
        batched < separate,
        "batching must win: {batched} vs {separate}"
    );
}

#[test]
fn a_round_claiming_a_nullifier_no_member_produced_is_rejected() {
    // The soundness gate. If the batched proof did not bind each sub-trace to its
    // own announced nullifier, a round could smuggle in an extra actor.
    let act = action(0);
    let set = round_set(act);
    let round = BaseElement::new(7);
    let members: Vec<(usize, [BaseElement; 2])> =
        (0..4).map(|i| (i, secret(i as u128))).collect();

    let proof = prove_round(&set, &members, round, act);

    let mut nullifiers: Vec<Hash> =
        (0..4).map(|i| nullifier(secret(i as u128), round)).collect();
    nullifiers[2] = nullifier(secret(99), round); // nobody in the set

    let claim = RoundClaim { root: set.root(), round, action: act, nullifiers };
    assert!(!verify_round(&claim, &proof), "a foreign nullifier must break the round");
}

#[test]
fn a_round_for_a_different_action_is_rejected() {
    let act = action(0);
    let set = round_set(act);
    let round = BaseElement::new(7);
    let members: Vec<(usize, [BaseElement; 2])> =
        (0..4).map(|i| (i, secret(i as u128))).collect();

    let proof = prove_round(&set, &members, round, act);
    let claim = RoundClaim {
        root: set.root(),
        round,
        action: action(1),
        nullifiers: (0..4).map(|i| nullifier(secret(i as u128), round)).collect(),
    };
    assert!(!verify_round(&claim, &proof), "the round is bound to its action");
}
