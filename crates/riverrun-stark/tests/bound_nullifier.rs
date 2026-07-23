//! Audit-critical #1c: the membership proof must *bind* the nullifier.
//!
//! One proof, three public inputs `{root, nullifier, round}`, one private secret.
//! The gate for calling 1c done is not the happy path — it is the negative tests
//! below: a proof must not verify against a nullifier it does not witness.
//!
//! See `docs/1c-nullifier-binding-design.md`.

use riverrun_stark::{leaf_of, nullifier, BaseElement, Hash, MembershipSet};

/// A set of `n` leaves with `value`'s leaf planted at `index`.
///
/// The bound scheme spends one extra hash cycle on the nullifier, so the trace
/// length is `(depth + 2) * 8` and must stay a power of two: only depths 2, 6 and
/// 14 (4, 64 and 16384 leaves) are valid.
fn set_with(value: [BaseElement; 2], index: usize, n: u128) -> MembershipSet {
    let mut leaves: Vec<Hash> = (0..n)
        .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
        .collect();
    leaves[index] = leaf_of(value);
    MembershipSet::new(leaves)
}

#[test]
fn bound_membership_proves_and_verifies() {
    let value = [BaseElement::new(42), BaseElement::new(43)];
    let round = BaseElement::new(7);
    let index = 2;
    let set = set_with(value, index, 4);

    let proof = set.prove_bound(value, index, round);
    let n = nullifier(value, round);

    assert!(
        riverrun_stark::verify_bound(set.root(), n, round, &proof),
        "a valid member must verify against the nullifier the proof witnesses"
    );
}

#[test]
fn bound_membership_works_on_a_64_leaf_set() {
    let value = [BaseElement::new(1234), BaseElement::new(5678)];
    let round = BaseElement::new(3);
    let index = 41;
    let set = set_with(value, index, 64);

    let proof = set.prove_bound(value, index, round);
    assert!(riverrun_stark::verify_bound(set.root(), nullifier(value, round), round, &proof));
}

#[test]
fn wrong_nullifier_is_rejected() {
    // THE binding test. Without this failing for a wrong `n`, the nullifier is
    // decoration and a member could act twice per round under two nullifiers.
    let value = [BaseElement::new(42), BaseElement::new(43)];
    let round = BaseElement::new(7);
    let index = 1;
    let set = set_with(value, index, 4);

    let proof = set.prove_bound(value, index, round);
    let real = nullifier(value, round).to_elements();
    let forged = Hash::new(real[1], real[0]);

    assert!(
        !riverrun_stark::verify_bound(set.root(), forged, round, &proof),
        "a proof must not verify against a nullifier it does not witness"
    );
}

#[test]
fn nullifier_of_another_member_is_rejected() {
    // Member A proves membership but presents member B's nullifier: rejected.
    // This is the "act under someone else's nullifier" attack.
    let a = [BaseElement::new(42), BaseElement::new(43)];
    let b = [BaseElement::new(99), BaseElement::new(100)];
    let round = BaseElement::new(7);
    let index = 3;

    let mut leaves: Vec<Hash> = (0..4u128)
        .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
        .collect();
    leaves[index] = leaf_of(a);
    leaves[0] = leaf_of(b);
    let set = MembershipSet::new(leaves);

    let proof = set.prove_bound(a, index, round);

    assert!(
        !riverrun_stark::verify_bound(set.root(), nullifier(b, round), round, &proof),
        "A's proof must not verify against B's nullifier"
    );
}

#[test]
fn wrong_round_is_rejected() {
    let value = [BaseElement::new(42), BaseElement::new(43)];
    let round = BaseElement::new(7);
    let index = 2;
    let set = set_with(value, index, 4);

    let proof = set.prove_bound(value, index, round);
    let other = BaseElement::new(8);

    assert!(
        !riverrun_stark::verify_bound(set.root(), nullifier(value, round), other, &proof),
        "the round is public and bound: a proof for round 7 must not pass as round 8"
    );
}

#[test]
fn wrong_root_is_rejected() {
    let value = [BaseElement::new(42), BaseElement::new(43)];
    let round = BaseElement::new(7);
    let index = 2;
    let set = set_with(value, index, 4);

    let proof = set.prove_bound(value, index, round);
    let real = set.root().to_elements();
    let wrong = Hash::new(real[1], real[0]);

    assert!(
        !riverrun_stark::verify_bound(wrong, nullifier(value, round), round, &proof),
        "membership is still bound to the public set root"
    );
}

#[test]
fn the_bound_proof_does_not_carry_the_secret() {
    use winterfell::math::StarkField;

    // Over many secrets, not one: a single sample gave false comfort here. The
    // first version of this AIR held the carry constant for the whole trace, and a
    // constant column has a constant low-degree extension — the secret landed in
    // every FRI opening, 20 proofs out of 20. One lucky sample would have hidden
    // that. This is a "not verbatim on the wire" check, not a formal
    // zero-knowledge guarantee (Winterfell 0.13 has no witness randomization).
    let round = BaseElement::new(11);
    for k in 0..20u128 {
        let value = [BaseElement::new(0xDEAD_BEEF_0000 + k), BaseElement::new(0xC0FFEE_0000 + k)];
        let index = (k % 4) as usize;
        let set = set_with(value, index, 4);

        let proof = set.prove_bound(value, index, round);
        let secret_bytes: Vec<u8> = value.iter().flat_map(|e| e.as_int().to_le_bytes()).collect();

        assert!(
            !proof.windows(secret_bytes.len()).any(|w| w == secret_bytes),
            "secret {k} appears verbatim in the transmitted proof"
        );
    }
}
