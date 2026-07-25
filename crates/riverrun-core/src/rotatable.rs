//! The rotatable piece — one secret, an angle for every context.
//!
//! Picture a puzzle piece. It has a shape. Turn it to a new angle and it presents
//! a *different* shape, each with its own matching counterpart. A rotatable piece
//! is that idea made cryptographic: a single [`Secret`] is the piece, and any
//! public **angle** `θ` (an epoch, a round, a verifier, a domain — any label)
//! derives its own **shape** and its own **fit**.
//!
//! Three properties hold, and they are the reason this is a *construction* and not
//! a metaphor:
//!
//! - **Binding within an angle.** At a fixed angle, the secret determines exactly
//!   one shape and one fit. You cannot present a different shape for the same
//!   `(secret, angle)` without a hash collision.
//! - **Unlinkability across angles.** `shape(θ)` and `shape(θ')` are independent
//!   PRF outputs. An observer cannot tell they came from the same piece, so turning
//!   the piece across contexts does not build a linkable trail.
//! - **Only the holder can turn it.** Advancing to the next angle (the [`turn`]
//!   tag) requires the secret. Others see disconnected shapes; the holder can later
//!   *prove in zero knowledge* that two angles are the same piece (spending the turn
//!   tag once, so one piece cannot fork into many seats) — this is riverrun's
//!   *ricorso* (see `docs/M31_CIRCLE_STARK.md` §1d and [[project_riverrun...]]).
//!
//! Everything is one collision-resistant hash (BLAKE3), so the whole construction
//! is post-quantum and transparent, exactly like the rest of `riverrun-core`.
//!
//! [`turn`]: Piece::turn

use crate::commitment::Secret;
use crate::{tagged_hash, Hash};

/// A public angle: any label that names a context the piece is viewed from.
/// The label space is unbounded — a piece has an angle for every context there is.
pub type Angle = u64;

// Domain-separated so a shape can never be reinterpreted as a fit or a turn tag,
// and none of them collide with a commitment, nullifier, or Merkle node.
const SHAPE: &[u8] = b"riverrun/piece-shape/v1";
const FIT: &[u8] = b"riverrun/piece-fit/v1";
const TURN: &[u8] = b"riverrun/piece-turn/v1";

/// A rotatable piece: a single [`Secret`] viewed from any angle. Borrow one with
/// [`Secret::piece`].
pub struct Piece<'a>(&'a Secret);

impl Secret {
    /// View this secret as a rotatable piece.
    pub fn piece(&self) -> Piece<'_> {
        Piece(self)
    }
}

impl Piece<'_> {
    /// The piece's **shape** at angle `θ`: `H(shape ‖ secret ‖ θ)`. What the piece
    /// looks like in this context — the value it publishes (e.g. a commitment leaf
    /// for the angle's anonymity set).
    pub fn shape(&self, theta: Angle) -> Hash {
        tagged_hash(SHAPE, &[self.0.as_bytes(), &theta.to_le_bytes()])
    }

    /// The piece's **fit** at angle `θ`: `H(fit ‖ secret ‖ θ)`. The matching
    /// counterpart revealed when the piece acts in this context (the per-angle
    /// nullifier — spent once, unlinkable to any other angle).
    pub fn fit(&self, theta: Angle) -> Hash {
        tagged_hash(FIT, &[self.0.as_bytes(), &theta.to_le_bytes()])
    }

    /// The **turn** tag from angle `θ` to `θ+1`: `H(turn ‖ secret ‖ θ ‖ θ+1)`.
    /// Derivable only with the secret, so only the holder can rotate the piece. It
    /// is the witness that two angles are the same piece; revealed once (as a
    /// migration nullifier) it proves continuity in zero knowledge while stopping a
    /// piece from forking into several.
    pub fn turn(&self, theta: Angle) -> Hash {
        tagged_hash(
            TURN,
            &[
                self.0.as_bytes(),
                &theta.to_le_bytes(),
                &theta.wrapping_add(1).to_le_bytes(),
            ],
        )
    }
}

// ---------------------------------------------------------------------------
// The turn relation — what a zero-knowledge proof of a rotation establishes.
// ---------------------------------------------------------------------------

use crate::commitment::Commitment;
use crate::merkle::{verify as merkle_verify, InclusionProof};

/// The **public** statement a rotation proof reveals: rotate a piece that was a
/// member of the previous angle's set, revealing only the migration tag.
///
/// It says: *"the holder of some piece that appeared as a leaf under `prev_root`
/// rotated it from `angle`, and the migration tag they reveal is `turn_tag`"* —
/// without revealing the piece, its shape, or its position. Revealing `turn_tag`
/// exactly once (an on-chain registry rejects repeats) is what stops one piece
/// from rotating into several seats.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TurnStatement {
    /// The set root the piece must have been a member of at `angle`.
    pub prev_root: Hash,
    /// The angle being rotated *from* (to `angle + 1`).
    pub angle: Angle,
    /// The migration tag revealed by the rotation (spent once).
    pub turn_tag: Hash,
}

/// The **private** witness — never revealed by the proof.
#[derive(Clone, Debug)]
pub struct TurnWitness {
    /// The piece itself.
    pub secret: Secret,
    /// A path showing the piece's shape at `angle` sits under `prev_root`.
    pub inclusion: InclusionProof,
}

/// Evaluate the turn relation in the clear. Returns `true` iff the witness proves
/// the statement. This is the single source of truth for what a zero-knowledge
/// STARK of a rotation must enforce (the same discipline as
/// [`crate::membership::check_relation`]); it takes the witness as input, so it is
/// **not** itself a proof.
///
/// Two constraints, and they are exactly the rotatable-piece properties:
/// 1. **Turn binding:** `turn_tag == secret.piece().turn(angle)` — the revealed
///    migration tag came from the same piece being rotated. A forger without the
///    secret cannot produce it (only-the-holder-can-turn), and it cannot be lifted
///    onto a different piece.
/// 2. **Prior membership:** `secret.piece().shape(angle)` verifies under
///    `prev_root` — the piece really was in the set at the angle it rotates from.
pub fn check_turn(statement: &TurnStatement, witness: &TurnWitness) -> bool {
    let piece = witness.secret.piece();
    if piece.turn(statement.angle) != statement.turn_tag {
        return false;
    }
    let shape = Commitment(piece.shape(statement.angle));
    merkle_verify(&statement.prev_root, &shape, &witness.inclusion)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Secret {
        Secret::from_bytes([byte; 32])
    }

    #[test]
    fn binding_within_an_angle() {
        // At a fixed angle the shape and fit are determined by the secret: a piece
        // cannot present two different shapes for the same (secret, angle).
        let s = secret(1);
        assert_eq!(s.piece().shape(7), s.piece().shape(7));
        assert_eq!(s.piece().fit(7), s.piece().fit(7));
    }

    #[test]
    fn unlinkable_across_angles() {
        // Turning the piece gives a different shape at every angle, with no visible
        // relation between them: an observer cannot tell shape(3) is the same piece
        // as shape(2) rather than a fresh secret.
        let s = secret(1);
        let a = s.piece().shape(2);
        let b = s.piece().shape(3);
        assert_ne!(a, b, "different angles must give different shapes");

        // shape(3) of this piece vs shape(3) of another piece are both just PRF
        // outputs; neither reveals which underlying secret produced it.
        let other = secret(2);
        assert_ne!(b, other.piece().shape(3));
        // and a fit never coincides with a shape at the same angle (domain separation)
        assert_ne!(s.piece().shape(3), s.piece().fit(3));
    }

    #[test]
    fn only_the_holder_can_turn_the_piece() {
        // The turn tag requires the true secret; a different secret produces an
        // unrelated value, so no one without the piece can rotate it.
        let s = secret(1);
        let forger = secret(2);
        assert_ne!(s.piece().turn(2), forger.piece().turn(2));
        // the turn is deterministic for the holder (so it can be checked / spent once)
        assert_eq!(s.piece().turn(2), s.piece().turn(2));
        // and turning from a different angle is a distinct tag (no replay across angles)
        assert_ne!(s.piece().turn(2), s.piece().turn(3));
    }

    #[test]
    fn a_freshly_minted_piece_rotates() {
        // The end-to-end shape: mint a real secret, view it from several angles,
        // and confirm all shapes/fits are distinct — one piece, many valid fits.
        let s = Secret::random();
        let shapes: Vec<Hash> = (0..5).map(|t| s.piece().shape(t)).collect();
        for i in 0..shapes.len() {
            for j in (i + 1)..shapes.len() {
                assert_ne!(shapes[i], shapes[j], "each angle is its own shape");
            }
        }
    }

    // --- the turn relation (what a ZK proof of a rotation enforces) ---

    fn shape_set(members: &[Secret], theta: Angle) -> crate::merkle::MerkleTree {
        let leaves: Vec<Commitment> =
            members.iter().map(|s| Commitment(s.piece().shape(theta))).collect();
        crate::merkle::MerkleTree::build(&leaves).unwrap()
    }

    #[test]
    fn a_valid_rotation_proves() {
        let theta = 4u64;
        let me = secret(1);
        let members = [secret(9), me, secret(7), secret(5)];
        let tree = shape_set(&members, theta);
        let stmt = TurnStatement {
            prev_root: tree.root(),
            angle: theta,
            turn_tag: me.piece().turn(theta),
        };
        let wit = TurnWitness { secret: me, inclusion: tree.prove(1).unwrap() };
        assert!(check_turn(&stmt, &wit), "a genuine rotation of a member piece must verify");
    }

    #[test]
    fn a_forged_turn_tag_fails() {
        // the migration tag comes from a DIFFERENT piece than the one being proven
        let theta = 4u64;
        let me = secret(1);
        let members = [secret(9), me, secret(7), secret(5)];
        let tree = shape_set(&members, theta);
        let stmt = TurnStatement {
            prev_root: tree.root(),
            angle: theta,
            turn_tag: secret(2).piece().turn(theta), // not my piece
        };
        let wit = TurnWitness { secret: me, inclusion: tree.prove(1).unwrap() };
        assert!(!check_turn(&stmt, &wit), "a turn tag not from this piece must fail");
    }

    #[test]
    fn a_piece_not_in_the_previous_set_fails() {
        // an outsider borrows a real member's inclusion path but has their own secret
        let theta = 4u64;
        let outsider = secret(42);
        let members = [secret(9), secret(1), secret(7), secret(5)];
        let tree = shape_set(&members, theta);
        let stmt = TurnStatement {
            prev_root: tree.root(),
            angle: theta,
            turn_tag: outsider.piece().turn(theta),
        };
        let wit = TurnWitness { secret: outsider, inclusion: tree.prove(1).unwrap() };
        assert!(!check_turn(&stmt, &wit), "a piece not in the set must not rotate");
    }

    // --- riverrun ID: the whole identity loop, demonstrated as one coherent thing ---

    /// One secret is a full identity layer: it acts in many contexts, unlinkably,
    /// one action per context, and can prove continuity between contexts in zero
    /// knowledge. This test is the `docs/RIVERRUN_ID.md` §8 developer surface made
    /// runnable — the primitive as a whole, not one property at a time.
    #[test]
    fn the_riverrun_id_loop_holds() {
        let me = Secret::random();

        // pick two unrelated contexts (a DAO voting round, an airdrop epoch)
        let dao_round: Angle = 0xD40;
        let airdrop_epoch: Angle = 0xA1D_2026;

        // my identity + my one-action token in each context
        let dao_id = me.piece().shape(dao_round);
        let vote = me.piece().fit(dao_round); // spend once => one vote
        let airdrop_id = me.piece().shape(airdrop_epoch);
        let claim = me.piece().fit(airdrop_epoch); // spend once => one claim

        // 1. UNLINKABLE: my DAO identity and my airdrop identity share no visible link
        assert_ne!(dao_id, airdrop_id, "identities across contexts must differ");
        assert_ne!(vote, claim, "action tokens across contexts must differ");
        // even the two *kinds* at one context are distinct (domain separation)
        assert_ne!(dao_id, vote);

        // 2. SYBIL-RESISTANT PER CONTEXT: my token in a context is fixed — acting
        //    twice reveals the same token, which an on-chain registry rejects.
        assert_eq!(vote, me.piece().fit(dao_round), "one token per context, deterministic");

        // 3. PROVABLE CONTINUITY, HIDDEN: I can prove my airdrop identity is the
        //    same entity that held a DAO identity, revealing only the migration tag.
        //    Build the DAO round's identity set with my dao_id in it, then prove the turn.
        let members = [secret(2), secret(3)];
        let mut leaves: Vec<Commitment> =
            members.iter().map(|s| Commitment(s.piece().shape(dao_round))).collect();
        leaves.push(Commitment(dao_id)); // I am a member of the DAO round
        leaves.push(Commitment(secret(4).piece().shape(dao_round)));
        let dao_set = crate::merkle::MerkleTree::build(&leaves).unwrap();

        let stmt = TurnStatement {
            prev_root: dao_set.root(),
            angle: dao_round,
            turn_tag: me.piece().turn(dao_round),
        };
        let wit = TurnWitness { secret: me, inclusion: dao_set.prove(2).unwrap() };
        assert!(
            check_turn(&stmt, &wit),
            "I can prove continuity from my DAO identity without revealing which member I am"
        );

        // and nobody else can claim my continuity: a different secret fails.
        let impostor = TurnStatement {
            prev_root: dao_set.root(),
            angle: dao_round,
            turn_tag: secret(99).piece().turn(dao_round),
        };
        assert!(
            !check_turn(&impostor, &TurnWitness { secret: secret(99), inclusion: dao_set.prove(2).unwrap() }),
            "only the holder of my secret can prove my continuity"
        );
    }
}
