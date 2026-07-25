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
const GRANT: &[u8] = b"riverrun/piece-grant/v1";

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

    /// A **scoped delegation grant**: `H(grant ‖ secret ‖ θ ‖ delegate)`. Authorizes
    /// `delegate` to act as this piece in context `θ` — and **only** there. Derivable
    /// only by the holder (it needs the secret), bound to the specific `delegate`
    /// (someone else's key cannot use it) and to the single angle `θ` (it grants
    /// nothing anywhere else). Let an agent act as an anonymous member of one DAO
    /// round, one pool, one vote — never your whole identity.
    pub fn grant(&self, theta: Angle, delegate: &[u8; 32]) -> Hash {
        tagged_hash(GRANT, &[self.0.as_bytes(), &theta.to_le_bytes(), delegate])
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

// ---------------------------------------------------------------------------
// Selective linkage — the cloak's dual: unlinkable by default, linkable only by
// you, only to whom you choose, only for the contexts you pick.
// ---------------------------------------------------------------------------

/// The public statement of a *chosen* link: "these two shapes are the same piece."
///
/// By default a piece's shapes at different angles are unlinkable (that is the
/// whole point). This is the holder's opt-in override: they can prove to a verifier
/// of their choosing that two specific shapes come from one secret — for portable
/// reputation, an accountability disclosure, or "yes, that was also me" — while
/// revealing **nothing** about the secret and **nothing** about any *other* angle.
/// The verifier learns only that `shape_a` (at `angle_a`) and `shape_b` (at
/// `angle_b`) share a holder. Any third identity stays as unlinkable as before.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStatement {
    pub shape_a: Hash,
    pub angle_a: Angle,
    pub shape_b: Hash,
    pub angle_b: Angle,
}

/// The private witness — the piece itself, never revealed.
#[derive(Clone, Debug)]
pub struct LinkWitness {
    pub secret: Secret,
}

/// Evaluate the selective-link relation in the clear. Returns `true` iff one secret
/// produces both shapes — the statement a zero-knowledge proof of a chosen link
/// enforces (same STARK machinery as the rest: two shape derivations over one
/// secret). It reveals only the two chosen angles; the secret and every other angle
/// stay hidden.
pub fn check_link(statement: &LinkStatement, witness: &LinkWitness) -> bool {
    let piece = witness.secret.piece();
    piece.shape(statement.angle_a) == statement.shape_a
        && piece.shape(statement.angle_b) == statement.shape_b
}

// ---------------------------------------------------------------------------
// Scoped delegation — let an agent act as you in one context, and only there.
// ---------------------------------------------------------------------------

/// The public statement of a scoped delegation: "a genuine member of the set at
/// `angle` authorizes `delegate` to act there, and the proof of that authorization
/// is `grant_tag`."
///
/// The holder proves it once (in zero knowledge); the verifier learns only
/// `{set_root, angle, delegate, grant_tag}` — never which member granted it. The
/// grant is bound to this `delegate` (not stealable by another key) and to this
/// single `angle` (it authorizes nothing elsewhere), and it is spent once. An agent
/// (a bot, a co-signer, a service) can then act as an anonymous member of exactly
/// that context, on the holder's authority, without ever touching the master secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DelegationStatement {
    /// The set root the granting member must belong to at `angle`.
    pub set_root: Hash,
    /// The single context the grant is scoped to.
    pub angle: Angle,
    /// The public identifier of the authorized delegate (e.g. their public key).
    pub delegate: [u8; 32],
    /// The grant, revealed and spent once.
    pub grant_tag: Hash,
}

/// The private witness — the granting piece, never revealed.
#[derive(Clone, Debug)]
pub struct DelegationWitness {
    pub secret: Secret,
    /// A path showing the granting piece's shape at `angle` sits under `set_root`.
    pub inclusion: InclusionProof,
}

/// Evaluate the scoped-delegation relation in the clear — what a zero-knowledge
/// proof of a delegation enforces. Two constraints:
/// 1. **Authorized by a real member:** the granting secret's shape at `angle` is a
///    member under `set_root` (only a legitimate member of that context can grant).
/// 2. **Grant binding:** `grant_tag == secret.piece().grant(angle, delegate)` — the
///    grant is this member's, for this delegate, for this angle. A different member,
///    a different delegate, or a different angle all fail.
pub fn check_delegation(statement: &DelegationStatement, witness: &DelegationWitness) -> bool {
    let piece = witness.secret.piece();
    if piece.grant(statement.angle, &statement.delegate) != statement.grant_tag {
        return false;
    }
    let shape = Commitment(piece.shape(statement.angle));
    merkle_verify(&statement.set_root, &shape, &witness.inclusion)
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

    // --- selective linkage: the cloak's dual ---

    #[test]
    fn the_holder_can_link_two_of_their_identities_on_demand() {
        // I choose to prove that my DAO persona and my forum persona are the same me.
        let me = secret(1);
        let dao: Angle = 100;
        let forum: Angle = 200;
        let stmt = LinkStatement {
            shape_a: me.piece().shape(dao),
            angle_a: dao,
            shape_b: me.piece().shape(forum),
            angle_b: forum,
        };
        assert!(
            check_link(&stmt, &LinkWitness { secret: me }),
            "the holder can prove two of their own shapes share one secret"
        );
    }

    #[test]
    fn an_impostor_cannot_forge_a_link_between_someone_elses_identities() {
        // Two shapes that really belong to `me`; an impostor tries to claim them.
        let me = secret(1);
        let dao: Angle = 100;
        let forum: Angle = 200;
        let stmt = LinkStatement {
            shape_a: me.piece().shape(dao),
            angle_a: dao,
            shape_b: me.piece().shape(forum),
            angle_b: forum,
        };
        let impostor = secret(2);
        assert!(
            !check_link(&stmt, &LinkWitness { secret: impostor }),
            "no one but the holder can link the holder's identities"
        );
    }

    #[test]
    fn linking_two_contexts_reveals_nothing_about_a_third() {
        // Proving dao <-> forum are the same piece must not expose my identity in a
        // third context: the link statement never mentions it, and that third shape
        // remains an independent PRF output, unlinkable as before.
        let me = secret(1);
        let (dao, forum, secret_vote): (Angle, Angle, Angle) = (100, 200, 300);
        let stmt = LinkStatement {
            shape_a: me.piece().shape(dao),
            angle_a: dao,
            shape_b: me.piece().shape(forum),
            angle_b: forum,
        };
        assert!(check_link(&stmt, &LinkWitness { secret: me }));
        // the third identity appears nowhere in the proven statement...
        let third = me.piece().shape(secret_vote);
        assert_ne!(third, stmt.shape_a);
        assert_ne!(third, stmt.shape_b);
        // ...and is indistinguishable from a stranger's shape at the same angle.
        assert_ne!(third, secret(2).piece().shape(secret_vote));
    }

    // --- scoped delegation ---

    #[test]
    fn a_member_can_delegate_one_context_to_an_agent() {
        let theta: Angle = 7;
        let me = secret(1);
        let agent = [0xA6u8; 32]; // the agent's public id
        let members = [secret(9), me, secret(3), secret(5)];
        let set = shape_set(&members, theta);
        let stmt = DelegationStatement {
            set_root: set.root(),
            angle: theta,
            delegate: agent,
            grant_tag: me.piece().grant(theta, &agent),
        };
        let wit = DelegationWitness { secret: me, inclusion: set.prove(1).unwrap() };
        assert!(check_delegation(&stmt, &wit), "a member can delegate their own context");
    }

    #[test]
    fn a_grant_is_bound_to_the_named_delegate() {
        // a grant issued for agent A must not authorize agent B
        let theta: Angle = 7;
        let me = secret(1);
        let members = [secret(9), me, secret(3), secret(5)];
        let set = shape_set(&members, theta);
        let stmt = DelegationStatement {
            set_root: set.root(),
            angle: theta,
            delegate: [0xBBu8; 32], // a DIFFERENT agent than the grant was for
            grant_tag: me.piece().grant(theta, &[0xA6u8; 32]),
        };
        let wit = DelegationWitness { secret: me, inclusion: set.prove(1).unwrap() };
        assert!(!check_delegation(&stmt, &wit), "a grant for one agent must not work for another");
    }

    #[test]
    fn a_grant_is_scoped_to_one_context() {
        // a grant for angle 7 must not authorize acting at angle 8
        let (theta, other): (Angle, Angle) = (7, 8);
        let me = secret(1);
        let agent = [0xA6u8; 32];
        let set = shape_set(&[secret(9), me, secret(3), secret(5)], other); // set at the OTHER angle
        let stmt = DelegationStatement {
            set_root: set.root(),
            angle: other,
            delegate: agent,
            grant_tag: me.piece().grant(theta, &agent), // grant was for theta, not other
        };
        let wit = DelegationWitness { secret: me, inclusion: set.prove(1).unwrap() };
        assert!(!check_delegation(&stmt, &wit), "a grant for one angle must not work at another");
    }

    #[test]
    fn a_non_member_cannot_delegate() {
        let theta: Angle = 7;
        let outsider = secret(42);
        let agent = [0xA6u8; 32];
        let set = shape_set(&[secret(9), secret(1), secret(3), secret(5)], theta);
        let stmt = DelegationStatement {
            set_root: set.root(),
            angle: theta,
            delegate: agent,
            grant_tag: outsider.piece().grant(theta, &agent),
        };
        // outsider borrows a real member's path but isn't in the set
        let wit = DelegationWitness { secret: outsider, inclusion: set.prove(1).unwrap() };
        assert!(!check_delegation(&stmt, &wit), "only a member of the context can delegate it");
    }
}
