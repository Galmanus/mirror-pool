# The ricorso — the anonymity set is reborn each cycle

Status: **relation implemented and tested in the clear; the STARK that proves it
is specified below and not built.** That is the same order 1c was done in, and
for the same reason: a subtly wrong AIR is false soundness, which is worse than
an honest gap. `crates/riverrun-stark` ships `cycle_secret`, `cycle_leaf`,
`migration_nullifier` and `check_migration`, with 8 tests, each of the relation's
four checks verified by deleting it and watching a test fail.

## The leak this closes

riverrun gives a member a per-round nullifier, so one execution cannot be linked
to another. Their **leaf does not change**. `Rescue(secret, action)` goes into
the tree at commit and stays there.

Two consequences the README did not previously name:

1. **Cross-epoch linkage.** Anyone who learns your leaf once — through a bug, a
   side channel, a subpoena, a careless client — links you across every round you
   ever acted in, past and future. Per-round nullifiers unlink executions from
   each other; nothing unlinks a member from their own history.
2. **The set is a timeline.** A set that only grows records who joined when.
   Join-order is a fingerprint, and it is public by construction.

Vico's cycle, which is the skeleton Finnegans Wake is built on, ends each turn
with the *ricorso* — the return that starts it over. riverrun already borrows the
book's circularity for the funding graph. The ricorso is the other half: the set
is reborn, and history stops accumulating.

## The construction

A master secret `v`, and a fresh secret per cycle:

```
cycle_secret(v, c)       = Rescue(v0, v1, c, DOM_CYCLE)
cycle_leaf(v, c, action) = Rescue(cycle_secret(v, c), action)
migration_nullifier(v, c) = Rescue(v0, v1, c, DOM_MIGRATE)
```

At each rebirth the member publishes `cycle_leaf(v, c_new, action)` and proves it
descends from *some* leaf under the previous root, spending
`migration_nullifier(v, c_new)` so one seat cannot become several.

`DOM_CYCLE` and `DOM_MIGRATE` must differ, and there is a test pinning it.
Sharing a domain would make publishing a migration nullifier hand out that
member's next cycle secret, and with it their next leaf — the rebirth would be
public and the whole thing pointless.

## The relation

Public: `{old_root, new_leaf, nullifier, old_cycle, new_cycle, action}`.
Private: `v`, the leaf index, the path.

1. `new_cycle ≠ old_cycle` — a cycle cannot be its own successor, or a member
   mints a second leaf against a nullifier they already spent.
2. `cycle_leaf(v, old_cycle, action)` is under `old_root`. Without this, anyone
   mints themselves a seat at every rebirth and the set inflates for free.
3. `new_leaf = cycle_leaf(v, new_cycle, action)` — binds the leaf being announced.
4. `nullifier = migration_nullifier(v, new_cycle)` — from the **same** secret, so
   a member cannot migrate under their own leaf while burning someone else's
   rebirth.

Check 4 is the one that was missing until a mutation exposed it: deleting it left
every test green.

## The AIR, and what it costs

Five hash cycles before the Merkle path, because three different values have to
flow through the trace:

| cycle | computes | notes |
|---|---|---|
| 0 | `migration_nullifier(v, c_new)` | public output, read at row 7 |
| 1 | `s_new = cycle_secret(v, c_new)` | needs `v` carried from row 0 |
| 2 | `new_leaf = Rescue(s_new, action)` | public output |
| 3 | `s_old = cycle_secret(v, c_old)` | needs `v` again |
| 4 | `old_leaf = Rescue(s_old, action)` | feeds the Merkle path |
| 5..d+4 | Merkle path | resolves to `old_root` |

That is `d + 5` cycles, and the trace length must be a power of two, so
`d + 5 ∈ {8, 16}` and the valid tree depths become `{3, 11}` — anonymity sets of
8 or 2048. The execution AIR requires `d + 2` to be a power of two, giving
`{4, 64, 16384}`. **The two do not intersect**, so shipping the migration STARK
also means padding the execution AIR with a no-op cycle to realign the widths.

That coupling is why this is specified rather than built four days before a
deadline, with the execution path green. It is a day of careful work on the most
delicate code in the repo, and the honest place to stop is here.

Carrying `v` across cycles 0 through 3 uses the same carry columns as the bound
AIR, with the same rule learned the hard way there: the carry must **not** be
constant across the whole trace, because a constant column has a constant
low-degree extension and puts the secret in every FRI opening — measured at 20
leaked proofs out of 20 before that was fixed.

## What it does not fix

The action stays in the leaf, so the anonymity set is still partitioned by which
action a member committed. Rebirth unlinks a member from their own past; it does
not merge members who committed different intents.

And the funding graph is untouched. A member whose seats across cycles are all
funded from the same wallet is linked by `pool-provenance`, not by the leaf —
which is the whole argument of [EFFECTIVE_K.md](EFFECTIVE_K.md), and the reason
the ricorso is necessary but not sufficient.
