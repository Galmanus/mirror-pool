//! The **ricorso**: the anonymity set is reborn each cycle.
//!
//! Finnegans Wake is built on Vico's cycle — three ages and a *ricorso*, the
//! return that starts it over. riverrun already borrows the book's circularity
//! for the funding graph. This is the other half of the same idea, and it closes
//! a leak the repo had not named.
//!
//! A member's leaf is `Rescue(secret, action)` and it never changes. Per-round
//! nullifiers unlink one *execution* from another, but the leaf itself persists,
//! so anyone who ever learns it links that member across every round, forever,
//! and a set that only grows is itself a timeline of who joined when.
//!
//! Under the ricorso the member holds a fresh leaf each cycle,
//! `Rescue(Rescue(secret, cycle), action)`, and proves the new one descends from
//! *some* leaf under the previous root without revealing which. History stops
//! accumulating.

use riverrun_stark::{
    check_migration, cycle_leaf, cycle_secret, leaf_of, migration_nullifier, BaseElement, Hash,
    MembershipSet, Migration,
};

fn action() -> [BaseElement; 2] {
    [BaseElement::new(0xAC01), BaseElement::new(0xAC02)]
}

/// A 4-leaf set with `value`'s cycle-`c` leaf planted at `index`.
fn set_at_cycle(value: [BaseElement; 2], c: BaseElement, index: usize) -> MembershipSet {
    let mut leaves: Vec<Hash> = (0..4u128)
        .map(|i| Hash::new(BaseElement::new(2 * i + 1), BaseElement::new(2 * i + 2)))
        .collect();
    leaves[index] = cycle_leaf(value, c, action());
    MembershipSet::new(leaves)
}

#[test]
fn a_member_migrates_into_the_next_cycle() {
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let (c0, c1) = (BaseElement::new(0), BaseElement::new(1));
    let index = 2;
    let set = set_at_cycle(v, c0, index);

    let m = Migration {
        old_root: set.root(),
        new_leaf: cycle_leaf(v, c1, action()),
        nullifier: migration_nullifier(v, c1),
        old_cycle: c0,
        new_cycle: c1,
        action: action(),
    };

    assert!(
        check_migration(&m, v, index, &set),
        "a member of the previous cycle's set may carry a fresh leaf into the next"
    );
}

#[test]
fn the_cycle_secret_is_domain_separated_from_the_nullifier() {
    // Both are Rescue over (secret, cycle). If they shared a domain, publishing a
    // migration nullifier would hand out the next cycle's secret, and with it the
    // member's next leaf — the rebirth would be public.
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let c = BaseElement::new(3);
    assert_ne!(
        cycle_secret(v, c).to_bytes(),
        migration_nullifier(v, c).to_bytes(),
        "the cycle secret must not equal the migration nullifier"
    );
}

#[test]
fn the_new_leaf_is_unlinkable_to_the_old_one() {
    // The whole point: without the secret, nothing connects the two leaves.
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let old = cycle_leaf(v, BaseElement::new(0), action());
    let new = cycle_leaf(v, BaseElement::new(1), action());
    assert_ne!(old.to_bytes(), new.to_bytes());

    // and neither is the plain, cycle-free leaf
    assert_ne!(old.to_bytes(), leaf_of(v, action()).to_bytes());
}

#[test]
fn a_non_member_cannot_migrate_in() {
    // Set inflation through the back door: if migration did not check membership
    // under the old root, anyone could mint themselves a seat every cycle.
    let member = [BaseElement::new(42), BaseElement::new(43)];
    let outsider = [BaseElement::new(7), BaseElement::new(9)];
    let (c0, c1) = (BaseElement::new(0), BaseElement::new(1));
    let set = set_at_cycle(member, c0, 1);
    let root = set.root();

    let m = Migration {
        old_root: root,
        new_leaf: cycle_leaf(outsider, c1, action()),
        nullifier: migration_nullifier(outsider, c1),
        old_cycle: c0,
        new_cycle: c1,
        action: action(),
    };
    assert!(
        !check_migration(&m, outsider, 1, &set),
        "an outsider must not be able to migrate into the set"
    );
}

#[test]
fn a_migration_proof_does_not_verify_for_another_leaf() {
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let (c0, c1) = (BaseElement::new(0), BaseElement::new(1));
    let set = set_at_cycle(v, c0, 0);

    let real = cycle_leaf(v, c1, action()).to_elements();
    let forged = Hash::new(real[1], real[0]);
    let m = Migration {
        old_root: set.root(),
        new_leaf: forged,
        nullifier: migration_nullifier(v, c1),
        old_cycle: c0,
        new_cycle: c1,
        action: action(),
    };

    assert!(
        !check_migration(&m, v, 0, &set),
        "the relation must bind the new leaf the member announces"
    );
}

#[test]
fn one_member_cannot_migrate_into_two_seats() {
    // The migration nullifier is what stops a member turning one seat into many
    // at each rebirth: it is derived from the secret and the cycle, so a second
    // migration in the same cycle reuses it.
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let c1 = BaseElement::new(1);
    assert_eq!(
        migration_nullifier(v, c1).to_bytes(),
        migration_nullifier(v, c1).to_bytes(),
        "deterministic per (secret, cycle), so the pool can spend it"
    );
    assert_ne!(
        migration_nullifier(v, c1).to_bytes(),
        migration_nullifier(v, BaseElement::new(2)).to_bytes(),
        "a new cycle grants exactly one new migration"
    );
}

#[test]
fn a_migration_announcing_someone_elses_nullifier_is_rejected() {
    // Without this the nullifier is decoration: a member could migrate under
    // their own leaf while spending a nullifier that is not theirs, which both
    // burns another member's rebirth and leaves their own unspent — one seat
    // becomes two at the next cycle. Found by deleting the check and watching
    // every test stay green.
    let a = [BaseElement::new(42), BaseElement::new(43)];
    let b = [BaseElement::new(99), BaseElement::new(100)];
    let (c0, c1) = (BaseElement::new(0), BaseElement::new(1));
    let set = set_at_cycle(a, c0, 2);

    let m = Migration {
        old_root: set.root(),
        new_leaf: cycle_leaf(a, c1, action()),
        nullifier: migration_nullifier(b, c1), // B's, not A's
        old_cycle: c0,
        new_cycle: c1,
        action: action(),
    };

    assert!(!check_migration(&m, a, 2, &set), "the nullifier must come from the migrating secret");
}

#[test]
fn a_rebirth_has_to_move_the_cycle_forward() {
    // Re-migrating into the same cycle would mint a second leaf for one member
    // with a nullifier they have already spent.
    let v = [BaseElement::new(42), BaseElement::new(43)];
    let c = BaseElement::new(4);
    let set = set_at_cycle(v, c, 1);

    let m = Migration {
        old_root: set.root(),
        new_leaf: cycle_leaf(v, c, action()),
        nullifier: migration_nullifier(v, c),
        old_cycle: c,
        new_cycle: c,
        action: action(),
    };

    assert!(!check_migration(&m, v, 1, &set), "a cycle cannot be its own successor");
}
