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
}
