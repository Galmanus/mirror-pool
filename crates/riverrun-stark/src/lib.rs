//! # riverrun-stark
//!
//! A **transparent, post-quantum STARK proof of anonymous set membership**:
//! prove knowledge of a leaf preimage whose Rescue-Prime hash sits under a public
//! Merkle root — *without revealing which leaf*. Hash-based (Rescue-Prime over the
//! 128-bit field) and FRI-based, so post-quantum; no trusted setup, no ceremony.
//!
//! This is the succinct zero-knowledge upgrade of riverrun's membership seam. The
//! Rescue-Prime Merkle-path AIR (`air.rs`, `prover.rs`, `utils/`) is adapted from
//! the Winterfell v0.13 `merkle` example (MIT, Facebook/Meta); the public API and
//! tests here wrap it as a clean membership prover/verifier.
//!
//! Two provers live here. `prove_membership` proves set membership alone. The
//! **bound** prover (`bound_air.rs`, `bound_prover.rs`) proves the whole riverrun
//! relation in one STARK: public inputs `{root, nullifier, round, action}`, and a
//! single private secret that must simultaneously sit under the root as
//! `Rescue(secret, action)` and produce the revealed `Rescue(secret, round)`. That
//! is what makes an execution *the* committed intent of *a* member, rather than
//! either half on its own.

// Used only by this module's public API.
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::MerkleTree;
use winterfell::{AcceptableOptions, BatchingMethod, FieldExtension, Proof, VerifierError};

mod air;
mod bound_air;
mod bound_prover;
mod prover;
mod round_air;
mod round_prover;
mod utils;

// Crate-root re-exports so the ported `air.rs` / `prover.rs` resolve their
// `crate::{...}` imports (they were `super::{...}` in the Winterfell example),
// and so this module can name them too.
pub(crate) use air::{MerkleAir, PublicInputs};
pub(crate) use bound_air::{BoundMerkleAir, BoundPublicInputs};
pub(crate) use bound_prover::BoundMerkleProver;
pub(crate) use core::marker::PhantomData;
pub(crate) use prover::MerkleProver;
pub(crate) use round_air::{RoundAir, RoundPublicInputs};
pub(crate) use round_prover::{MemberWitness, RoundProver};
pub(crate) use rescue::{
    CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS, STATE_WIDTH as HASH_STATE_WIDTH,
};
pub(crate) use utils::rescue;
pub(crate) use winterfell::crypto::{DefaultRandomCoin, ElementHasher};
pub(crate) use winterfell::math::FieldElement;
pub(crate) use winterfell::{ProofOptions, Prover};

/// The field over which the in-circuit Rescue hash and leaf preimages live.
pub use winterfell::math::fields::f128::BaseElement;

pub(crate) const TRACE_WIDTH: usize = 7;

/// Trace width of the nullifier-binding AIR: the seven columns above plus the two
/// carry columns that hold the secret constant across the whole trace.
pub(crate) const BOUND_TRACE_WIDTH: usize = 9;
pub(crate) const CARRY_0: usize = 7;
pub(crate) const CARRY_1: usize = 8;

/// The in-circuit Merkle hash is Rescue-Prime; re-exported for building trees.
pub use rescue::{Hash, Rescue128};

/// The STARK's own commitment / Fiat-Shamir hash (distinct from the in-circuit
/// Rescue). Any collision-resistant hash works; BLAKE3 keeps the whole stack
/// hash-based and post-quantum.
type StarkHash = Blake3_256<BaseElement>;

/// Proof options: 28 queries at blow-up factor 8, no grinding, no field extension
/// → only **~84 bits** of conjectured security (28 × log2(8)), NOT production
/// strength. A production deployment must raise this (more queries, grinding, or
/// a field extension) to ~128 bits, and use the full-round Rescue parameters.
/// These example-grade parameters are for demonstrating the proof end-to-end.
fn proof_options() -> ProofOptions {
    ProofOptions::new(
        28,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Proof options with a chosen query count and blow-up, for measuring how far the
/// on-chain verification cost can be pushed down. Fewer queries = lower security
/// and lower CU. Used only by the on-chain verifier's cost study; the shipped
/// path uses [`proof_options`].
pub fn proof_options_tuned(queries: usize, blowup: usize) -> ProofOptions {
    ProofOptions::new(
        queries,
        blowup,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Prove a bound membership with explicit proof options — for the on-chain cost
/// measurement only.
pub fn prove_bound_tuned(
    set: &MembershipSet,
    value: [BaseElement; 2],
    index: usize,
    round: BaseElement,
    action: [BaseElement; 2],
    options: ProofOptions,
) -> Vec<u8> {
    let (leaf, path) = set.tree.prove(index).expect("valid index");
    let mut branch = vec![leaf];
    branch.extend_from_slice(&path);
    let prover = BoundMerkleProver::<StarkHash>::new(options);
    prover.prove(prover.build_trace(value, &branch, index, round, action)).unwrap().to_bytes()
}

/// Build a Rescue-Prime Merkle tree (the anonymity set) from its leaves.
pub fn build_tree(leaves: Vec<Hash>) -> MerkleTree<Rescue128> {
    MerkleTree::new(leaves).expect("power-of-two leaf count")
}

/// Prove, in zero knowledge, that `value` is the preimage of the leaf at `index`
/// of `tree` — i.e. that a member with this leaf is in the set with `tree`'s root.
/// The proof reveals only the root; `value` and `index` stay private.
pub fn prove_membership(
    tree: &MerkleTree<Rescue128>,
    value: [BaseElement; 2],
    index: usize,
) -> Proof {
    let (leaf, path) = tree.prove(index).expect("valid index");
    let mut branch = vec![leaf];
    branch.extend_from_slice(&path);
    let prover = MerkleProver::<StarkHash>::new(proof_options());
    let trace = prover.build_trace(value, &branch, index);
    prover.prove(trace).expect("prove membership")
}

/// Verify a membership proof against the public set root. Accepts iff the proof
/// witnesses some leaf preimage resolving to `root` — without learning which.
pub fn verify_membership(root: Hash, proof: Proof) -> Result<(), VerifierError> {
    let pub_inputs = PublicInputs { tree_root: root.to_elements() };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<MerkleAir, StarkHash, DefaultRandomCoin<StarkHash>, MerkleTree<StarkHash>>(
        proof,
        pub_inputs,
        &acceptable,
    )
}

// --- High-level API: the transmitted proof carries no witness ----------------

/// An anonymity set backed by the Rescue-Prime Merkle tree, hiding the winterfell
/// types so a consumer (e.g. the pool) never touches them.
pub struct MembershipSet {
    tree: MerkleTree<Rescue128>,
}

impl MembershipSet {
    /// Build the set from its leaves (each a Rescue digest — see [`leaf_of`]).
    pub fn new(leaves: Vec<Hash>) -> Self {
        Self { tree: build_tree(leaves) }
    }

    /// The public set root.
    pub fn root(&self) -> Hash {
        *self.tree.root()
    }

    /// Whether `leaf` really is the leaf at `index` of this set. Used by the
    /// in-the-clear relation checks; a proof never gets to look.
    pub fn contains(&self, leaf: Hash, index: usize) -> bool {
        match self.tree.prove(index) {
            Ok((l, _)) => l.to_bytes() == leaf.to_bytes(),
            Err(_) => false,
        }
    }

    /// Prove membership of the leaf whose preimage is `value` at `index`, and
    /// return the proof **as opaque bytes**. Unlike a witness-carrying proof, the
    /// secret `value` and the leaf `index` are not serialized into these bytes.
    pub fn prove(&self, value: [BaseElement; 2], index: usize) -> Vec<u8> {
        prove_membership(&self.tree, value, index).to_bytes()
    }

    /// Prove membership of the leaf whose preimage is `value` **and** that the
    /// per-round nullifier `Rescue(value, round)` comes from that same preimage —
    /// in one proof. Public inputs are `{root, nullifier, round}`; `value` and
    /// `index` stay private. See [`verify_bound`].
    pub fn prove_bound(
        &self,
        value: [BaseElement; 2],
        index: usize,
        round: BaseElement,
        action: [BaseElement; 2],
    ) -> Vec<u8> {
        prove_bound_membership(&self.tree, value, index, round, action).to_bytes()
    }
}

/// Prove membership *and* the per-round nullifier in a single STARK. The verifier
/// learns only `{root, nullifier, round}`; which member acted stays hidden.
pub fn prove_bound_membership(
    tree: &MerkleTree<Rescue128>,
    value: [BaseElement; 2],
    index: usize,
    round: BaseElement,
    action: [BaseElement; 2],
) -> Proof {
    let (leaf, path) = tree.prove(index).expect("valid index");
    let mut branch = vec![leaf];
    branch.extend_from_slice(&path);
    let prover = BoundMerkleProver::<StarkHash>::new(proof_options());
    let trace = prover.build_trace(value, &branch, index, round, action);
    prover.prove(trace).expect("prove bound membership")
}

/// Verify a bound proof: accepts iff the proof witnesses a secret that is both a
/// member under `root` and the preimage of `nullifier` for this `round`.
pub fn verify_bound(
    root: Hash,
    nullifier: Hash,
    round: BaseElement,
    action: [BaseElement; 2],
    proof_bytes: &[u8],
) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(proof) => proof,
        Err(_) => return false,
    };
    let pub_inputs = BoundPublicInputs {
        tree_root: root.to_elements(),
        nullifier: nullifier.to_elements(),
        round,
        action,
    };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<
        BoundMerkleAir,
        StarkHash,
        DefaultRandomCoin<StarkHash>,
        MerkleTree<StarkHash>,
    >(proof, pub_inputs, &acceptable)
    .is_ok()
}

/// The leaf a member commits: `Rescue(secret, action)`. Binding the action into
/// the leaf is what lets one proof witness *which intent* the member registered,
/// rather than only that they are in the set.
pub fn leaf_of(value: [BaseElement; 2], action: [BaseElement; 2]) -> Hash {
    Rescue128::digest(&[value[0], value[1], action[0], action[1]])
}

/// The per-round nullifier for a secret: `Rescue(v0, v1, round)`. This is the
/// value that binding-into-the-AIR (audit-critical #1c, see
/// `docs/1c-nullifier-binding-design.md`) must reproduce in-circuit and expose as
/// a public output, so that one proof witnesses membership *and* this nullifier
/// from the same secret. Provided and tested here so the AIR has a reference to
/// match.
pub fn nullifier(secret: [BaseElement; 2], round: BaseElement) -> Hash {
    Rescue128::digest(&[secret[0], secret[1], round])
}

// --- The ricorso: the set is reborn each cycle ------------------------------
//
// Finnegans Wake runs on Vico's cycle, and its fourth age is the *ricorso*, the
// return that begins it again. riverrun already borrows the book's circularity
// for the funding graph. This is the other half, and it closes a leak the repo
// had not named: a member's leaf is fixed forever, so per-round nullifiers unlink
// one execution from another while the leaf itself links the member across every
// round, and a set that only grows is a public record of who joined when.
//
// Under the ricorso the member holds a different leaf each cycle and proves the
// new one descends from some leaf under the previous root, without revealing
// which. History stops accumulating.
//
// Status: the relation is implemented and tested **in the clear** here, the way
// `riverrun-core::membership::check_relation` specifies the execution relation.
// The STARK that proves it without the witness is specified in
// `docs/RICORSO.md` and is not built. That is the same order 1c was done in, and
// the same honesty: a relation you can check is not a proof you can publish.

/// Domain tag separating the per-cycle secret from every other use of Rescue.
const DOM_CYCLE: BaseElement = BaseElement::new(0x0052_4943_4F52_534F);
/// Domain tag for the migration nullifier. It must differ from [`DOM_CYCLE`]:
/// sharing one would make publishing a migration nullifier hand out the next
/// cycle's secret, and with it the member's next leaf.
const DOM_MIGRATE: BaseElement = BaseElement::new(0x004D_4947_5241_5445);

/// The member's secret for cycle `c`: `Rescue(v0, v1, c, DOM_CYCLE)`.
///
/// Deriving per-cycle secrets from one master secret is what lets a member hold
/// an unlinkable leaf each cycle while still being able to prove, cycle after
/// cycle, that they are the same member.
pub fn cycle_secret(secret: [BaseElement; 2], cycle: BaseElement) -> Hash {
    Rescue128::digest(&[secret[0], secret[1], cycle, DOM_CYCLE])
}

/// The member's leaf in cycle `c`: `Rescue(cycle_secret(v, c), action)`.
pub fn cycle_leaf(
    secret: [BaseElement; 2],
    cycle: BaseElement,
    action: [BaseElement; 2],
) -> Hash {
    let s = cycle_secret(secret, cycle).to_elements();
    leaf_of(s, action)
}

/// Spent once per member per cycle, so one seat cannot become many at a rebirth.
pub fn migration_nullifier(secret: [BaseElement; 2], cycle: BaseElement) -> Hash {
    Rescue128::digest(&[secret[0], secret[1], cycle, DOM_MIGRATE])
}

/// Everything a migration publishes. The witness — the secret and the leaf index
/// — is not in here; it is what the STARK would hide.
#[derive(Clone, Debug)]
pub struct Migration {
    pub old_root: Hash,
    pub new_leaf: Hash,
    pub nullifier: Hash,
    pub old_cycle: BaseElement,
    pub new_cycle: BaseElement,
    pub action: [BaseElement; 2],
}

/// Evaluate the migration relation in the clear.
///
/// True iff, for this witness: the member's leaf for `old_cycle` sits under
/// `old_root`, the announced `new_leaf` is their leaf for `new_cycle`, and the
/// announced `nullifier` is their migration nullifier for `new_cycle` — all from
/// the same secret, which is what stops a member migrating under one identity
/// and spending another's nullifier.
///
/// This takes the witness as input, so it is emphatically **not** a proof
/// system. It is the specification the AIR has to enforce.
pub fn check_migration(
    m: &Migration,
    secret: [BaseElement; 2],
    index: usize,
    old_set: &MembershipSet,
) -> bool {
    if m.new_cycle == m.old_cycle {
        return false; // a rebirth has to move the cycle forward
    }
    if old_set.root().to_bytes() != m.old_root.to_bytes() {
        return false;
    }
    if cycle_leaf(secret, m.new_cycle, m.action).to_bytes() != m.new_leaf.to_bytes() {
        return false;
    }
    if migration_nullifier(secret, m.new_cycle).to_bytes() != m.nullifier.to_bytes() {
        return false;
    }
    // membership of the *old* leaf, checked against the set the root came from
    old_set.contains(cycle_leaf(secret, m.old_cycle, m.action), index)
}

// --- One round, one proof ---------------------------------------------------

/// Everything a settled round publishes: the set it was proven against, the
/// round and action it settles, and one nullifier per member.
#[derive(Clone, Debug)]
pub struct RoundClaim {
    pub root: Hash,
    pub round: BaseElement,
    pub action: [BaseElement; 2],
    pub nullifiers: Vec<Hash>,
}

/// Prove a whole synchronized round in one STARK: every `(index, secret)` in
/// `members` is a committed member of `set` acting on `action` in `round`.
///
/// This is the shape riverrun's thesis already has — k members doing the same
/// thing at the same time — so batching costs nothing conceptually and saves a
/// proof and a verification per member.
pub fn prove_round(
    set: &MembershipSet,
    members: &[(usize, [BaseElement; 2])],
    round: BaseElement,
    action: [BaseElement; 2],
) -> Vec<u8> {
    let witnesses: Vec<MemberWitness> = members
        .iter()
        .map(|(index, secret)| {
            let (leaf, path) = set.tree.prove(*index).expect("valid index");
            let mut branch = vec![leaf];
            branch.extend_from_slice(&path);
            MemberWitness { secret: *secret, index: *index, branch }
        })
        .collect();

    let prover =
        RoundProver::<StarkHash>::new(proof_options(), round, action, witnesses.len());
    let trace = prover.build_trace(&witnesses);
    prover.prove(trace).expect("prove round").to_bytes()
}

/// Verify a whole round against its public claim.
pub fn verify_round(claim: &RoundClaim, proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = RoundPublicInputs {
        tree_root: claim.root.to_elements(),
        round: claim.round,
        action: claim.action,
        nullifiers: claim.nullifiers.iter().map(|n| n.to_elements()).collect(),
    };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<RoundAir, StarkHash, DefaultRandomCoin<StarkHash>, MerkleTree<StarkHash>>(
        proof,
        pub_inputs,
        &acceptable,
    )
    .is_ok()
}

/// Verify an opaque membership-proof byte string against a public `root`.
pub fn verify_bytes(root: Hash, proof_bytes: &[u8]) -> bool {
    match Proof::from_bytes(proof_bytes) {
        Ok(proof) => verify_membership(root, proof).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::StarkField;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Build an 8-leaf set with `value`'s digest planted at `index`.
    fn set_with(value: [BaseElement; 2], index: usize) -> MerkleTree<Rescue128> {
        let mut leaves: Vec<Hash> = (0..8u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        leaves[index] = Rescue128::digest(&value);
        build_tree(leaves)
    }

    #[test]
    fn membership_proves_and_verifies() {
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index = 5;
        let tree = set_with(value, index);
        let root = *tree.root();
        let proof = prove_membership(&tree, value, index);
        assert!(verify_membership(root, proof).is_ok(), "valid member must verify");
    }

    #[test]
    fn proof_against_wrong_root_is_rejected() {
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let index = 3;
        let tree = set_with(value, index);
        let proof = prove_membership(&tree, value, index);
        // A different (swapped) root must not accept the proof.
        let real = tree.root().to_elements();
        let wrong = Hash::new(real[1], real[0]);
        assert!(verify_membership(wrong, proof).is_err(), "a wrong root must be rejected");
    }

    /// The start-tie, attacked directly.
    ///
    /// The public-input tests in `tests/bound_nullifier.rs` would pass even with no
    /// tie at all — they only vary what the verifier is told. This one builds the
    /// trace an attacker would want: hash secret A into the nullifier cycle, but
    /// carry member B into the Merkle path, so the proof would show membership of B
    /// under A's nullifier. That is the "act under someone else's nullifier" break,
    /// and only constraint (3) of the design doc stops it.
    #[test]
    fn a_trace_that_hashes_one_secret_and_carries_another_yields_no_accepted_proof() {
        let a = [BaseElement::new(42), BaseElement::new(43)];
        let b = [BaseElement::new(99), BaseElement::new(100)];
        let round = BaseElement::new(7);
        let b_index = 0;

        let mut leaves: Vec<Hash> = (0..4u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        let act = [BaseElement::new(0xAC01), BaseElement::new(0xAC02)];
        leaves[b_index] = leaf_of(b, act);
        leaves[3] = leaf_of(a, act);
        let tree = build_tree(leaves);
        let root = *tree.root();

        let (leaf, path) = tree.prove(b_index).expect("valid index");
        let mut branch = vec![leaf];
        branch.extend_from_slice(&path);

        let prover = BoundMerkleProver::<StarkHash>::new(proof_options());
        // hashed = A (whose nullifier the attacker wants), carried = B (the member)
        let forged = prover.build_trace_with_carry(a, b, &branch, b_index, round, act);

        // In a debug build the prover panics on an unsatisfied constraint; in a
        // release build it emits a proof that must not verify. Both are a rejection.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove(forged).map(|p| p.to_bytes())
        }));

        if let Ok(Ok(proof)) = attempt {
            assert!(
                !verify_bound(root, nullifier(a, round), round, act, &proof),
                "a forged trace must not yield a proof of B's membership under A's nullifier"
            );
        }
    }

    /// The action binding, attacked directly.
    ///
    /// Announcing a different action in the public inputs is not enough to test
    /// this: the action feeds the Fiat-Shamir transcript, so the proof fails for
    /// that reason alone even with no constraint at all (checked by deleting the
    /// constraint — those tests stayed green). The real attack is to hash the
    /// action you *did* commit into the leaf, so the Merkle path still resolves,
    /// while announcing the action you want to execute. Only the AIR pinning
    /// column 2 and 3 at the load row to the public action stops that.
    #[test]
    fn a_trace_whose_leaf_commits_one_action_cannot_announce_another() {
        let value = [BaseElement::new(42), BaseElement::new(43)];
        let round = BaseElement::new(7);
        let committed = [BaseElement::new(0xAC01), BaseElement::new(0xAC02)];
        let wanted = [BaseElement::new(0xBD01), BaseElement::new(0xBD02)];
        let index = 1;

        let mut leaves: Vec<Hash> = (0..4u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        leaves[index] = leaf_of(value, committed);
        let tree = build_tree(leaves);
        let root = *tree.root();

        let (leaf, path) = tree.prove(index).expect("valid index");
        let mut branch = vec![leaf];
        branch.extend_from_slice(&path);

        // the leaf hashes `committed` (so the path resolves), the proof announces `wanted`
        let prover = BoundMerkleProver::<StarkHash>::declaring_action(proof_options(), wanted);
        let trace = prover.build_trace(value, &branch, index, round, committed);

        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove(trace).map(|p| p.to_bytes())
        }));

        if let Ok(Ok(proof)) = attempt {
            assert!(
                !verify_bound(root, nullifier(value, round), round, wanted, &proof),
                "a member who committed one action must not be able to execute another"
            );
        }
    }

    #[test]
    fn nullifier_is_deterministic_and_round_dependent() {
        let v = [BaseElement::new(11), BaseElement::new(22)];
        let r1 = BaseElement::new(1);
        let r2 = BaseElement::new(2);
        // deterministic per (secret, round)
        assert_eq!(nullifier(v, r1).to_bytes(), nullifier(v, r1).to_bytes());
        // different round → different nullifier (cross-round unlinkability)
        assert_ne!(nullifier(v, r1).to_bytes(), nullifier(v, r2).to_bytes());
        // different secret → different nullifier
        let w = [BaseElement::new(33), BaseElement::new(22)];
        assert_ne!(nullifier(v, r1).to_bytes(), nullifier(w, r1).to_bytes());
        // and it is distinct from the leaf commitment of the same secret
        assert_ne!(nullifier(v, r1).to_bytes(), leaf_of(v, [r1, r2]).to_bytes());
    }

    #[test]
    fn transmitted_proof_does_not_carry_the_secret_verbatim() {
        // The whole point vs the reference proof: the opaque proof bytes must not
        // contain the secret preimage verbatim (the reference proof serialized
        // exactly that). This is a smoke test for "witness not on the wire", not
        // a formal zero-knowledge guarantee.
        let value = [BaseElement::new(0xDEAD_BEEF_1234), BaseElement::new(0x00C0_FFEE_5678)];
        let index = 2;
        let mut leaves: Vec<Hash> = (100..108u128)
            .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
            .collect();
        leaves[index] = Rescue128::digest(&value);
        let set = MembershipSet::new(leaves);
        let root = set.root();

        let proof = set.prove(value, index);
        assert!(verify_bytes(root, &proof), "opaque proof must verify against the root");

        // The 32 raw bytes of the secret preimage (two f128 elements, LE).
        let secret_bytes: Vec<u8> =
            value.iter().flat_map(|e| e.as_int().to_le_bytes()).collect();
        assert!(
            !contains(&proof, &secret_bytes),
            "the secret preimage must not appear verbatim in the transmitted proof"
        );
    }
}
