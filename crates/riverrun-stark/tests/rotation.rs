//! Proving a *rotation* in zero knowledge — the turn of a rotatable piece.
//!
//! A piece (a secret) that appeared as a shape under the previous angle's set root
//! rotates to the next angle, revealing only its migration tag. The proof reveals
//! `{prev_root, turn_tag, angle}` and nothing else: which piece rotated, and its
//! shape, stay hidden. This is `riverrun_core::rotatable::check_turn` enforced in
//! zero knowledge, and it reuses the bound-membership STARK verbatim: the turn is
//! *structurally* a membership proof (the shape is in the previous set) bound to a
//! nullifier (the turn tag) from the same secret. The angle plays the role of the
//! round and the shape's action.

use riverrun_stark::{leaf_of, nullifier, BaseElement, Hash, MembershipSet};

/// An angle, encoded as the shape's action `[θ, 0]`.
fn angle(theta: u128) -> [BaseElement; 2] {
    [BaseElement::new(theta), BaseElement::new(0)]
}
/// The same angle as the round element the turn tag is derived against.
fn round_of(theta: u128) -> BaseElement {
    BaseElement::new(theta)
}

/// The previous angle's set: `n` shapes, with our piece's shape planted at `index`.
/// A shape at angle θ is `leaf_of(piece, angle(θ))` = Rescue(piece ‖ θ). Valid sizes
/// for the bound trace are 4, 64, 16384.
fn set_at_angle(piece: [BaseElement; 2], theta: u128, index: usize, n: u128) -> MembershipSet {
    let mut leaves: Vec<Hash> = (0..n)
        .map(|i| Hash::new(BaseElement::new(7 * i + 3), BaseElement::new(7 * i + 5)))
        .collect();
    leaves[index] = leaf_of(piece, angle(theta));
    MembershipSet::new(leaves)
}

#[test]
fn a_rotation_is_provable_in_zero_knowledge() {
    let piece = [BaseElement::new(0xB0FF), BaseElement::new(0xCAFE)];
    let theta = 4u128;
    let index = 2;
    let prev_set = set_at_angle(piece, theta, index, 4);

    // Prove: this piece's shape is under prev_root, and the revealed turn tag comes
    // from the same piece. The piece itself never appears in the proof.
    let proof = prev_set.prove_bound(piece, index, round_of(theta), angle(theta));
    let turn_tag = nullifier(piece, round_of(theta));

    assert!(
        riverrun_stark::verify_bound(prev_set.root(), turn_tag, round_of(theta), angle(theta), &proof),
        "a genuine rotation must verify in zero knowledge"
    );
}

#[test]
fn a_forged_turn_tag_does_not_verify() {
    // The binding: a proof of one piece's rotation must not verify against a turn
    // tag it does not witness (someone else's tag, or a made-up one).
    let piece = [BaseElement::new(0xB0FF), BaseElement::new(0xCAFE)];
    let theta = 4u128;
    let index = 2;
    let prev_set = set_at_angle(piece, theta, index, 4);
    let proof = prev_set.prove_bound(piece, index, round_of(theta), angle(theta));

    let other_piece = [BaseElement::new(1), BaseElement::new(2)];
    let forged = nullifier(other_piece, round_of(theta));
    assert!(
        !riverrun_stark::verify_bound(prev_set.root(), forged, round_of(theta), angle(theta), &proof),
        "a turn tag not witnessed by the proof must be rejected"
    );
}

#[test]
fn a_tag_from_a_different_angle_does_not_verify() {
    // No replay across angles: the turn tag for angle θ must not settle angle θ'.
    let piece = [BaseElement::new(0xB0FF), BaseElement::new(0xCAFE)];
    let theta = 4u128;
    let index = 2;
    let prev_set = set_at_angle(piece, theta, index, 4);
    let proof = prev_set.prove_bound(piece, index, round_of(theta), angle(theta));

    // the same piece's tag, but for a different angle
    let wrong_angle_tag = nullifier(piece, round_of(9));
    assert!(
        !riverrun_stark::verify_bound(prev_set.root(), wrong_angle_tag, round_of(theta), angle(theta), &proof),
        "a turn tag from another angle must be rejected"
    );
}
