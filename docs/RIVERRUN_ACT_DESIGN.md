# riverrun act: one secret, one call, one unlinkable action

**Status: design. Not implemented. No code until this is approved.**

This is the design for binding riverrun ID to the pool action end to end, so a fund,
market maker, or agent does a single call and gets an unlinkable, measured action,
instead of stitching together three separate tools (identity, commit, execute).

It is the highest financial-impact direction because it serves the actors with the
most value at risk from transparency (front-running, copy-trading, strategy leak),
and those actors need an integratable primitive, not an interactive menu.

## The insight: the crypto already exists

The hard part is done. `crates/riverrun-stark` already proves, in one object, that a
single secret satisfies all three bindings at once (`bound_air.rs`, audit item 1c,
tested):

- **membership**: the secret's commitment is a leaf under the published Merkle root,
- **nullifier**: a per-round tag derived from the *same* secret, so one action per
  member per round, no double-spend,
- **action**: the public action is bound into the leaf, so a member executes the
  intent they committed, not any intent.

What is missing is not cryptography. It is (a) a unified key derivation so identity
and membership come from one root, (b) a single orchestrated flow, and (c) the SDK a
fund integrates. That is what this document specifies.

## 1. One root, everything derived

The fund holds one master secret `s` (32 bytes, the riverrun ID root). Everything is
a domain-separated derivation of it, so there is nothing else to store:

```
identity in a context : id_ctx = H(s || "riverrun/id"     || context)
pool commitment (leaf) : C      = H(s || "riverrun/commit" || context || action)
nullifier (per round)  : n      = H(s || "riverrun/null"   || context || round)
```

The STARK proves: there exists `s` such that `C` is a leaf under the round's root,
`n` is derived from that same `s` and the public `round`, and the public `action`
matches the one welded into `C`. This is exactly `bound_air`, with the derivation
above pinned as the leaf preimage.

Property that matters to a fund: **one secret, held once, is identity and membership
and spend-authority.** No separate "create identity" then "commit" then "execute".
And it stays compartmentalized: the `context` domain separation means the fund's
identity in one venue is unlinkable to another, so one exposure does not cascade.

## 2. The single flow

The fund calls one function:

```
riverrun.act(context, action, recipient, amount) -> Receipt
```

Under the hood, deterministically:

1. **derive** `C` and `n` from `s`, `context`, `action`, and the current `round`.
2. **join**: submit `commit(C)` to the pool from a fresh, crowd-funded key, so even
   joining is unlinkable. The master secret never signs anything on-chain.
3. **wait for the crowd**: the round fills to `k_min` (see section 4).
4. **prove**: generate the bound STARK (membership + nullifier + action).
5. **settle**: a relayer submits `execute(action, n, round, proof)`. The vault pays
   `recipient` a fixed denomination. No member key signs the execution.
6. **receipt**: return the settlement signature *and the measured effective-k of the
   round*, so the fund knows the anonymity it actually got, not the advertised count.

The receipt is the point. A fund does not want a promise; it wants a number it can
log and audit. `act()` returns one.

## 3. Why this, and not the pieces we already have

Today the identity layer (`riverrun id`, offline pseudonyms) and the pool
(`commit` / `execute`) are separate, manual, and the STARK is not yet the live
settlement path (committee fallback). A fund cannot integrate three disconnected
tools into a trading system. `act()` is one secret, one call, one proof, one receipt.
That is the difference between a demo and a primitive.

## 4. Round mechanics: the real tension is latency versus crowd

A fund needs to act now; anonymity needs a crowd, which takes time to form. This is
the hard part, and it is honest to state it plainly.

- **Continuous rounds**: rounds open and close on a fixed cadence (every N seconds,
  or every `k` deposits). The action lands in the next round. Latency equals the
  round period. Faster rounds mean smaller crowds mean lower effective-k. The receipt
  reports the actual effective-k, so the fund chooses the tradeoff with eyes open.
- **The provenance coordinator** (already specified for riverrun): admits a member
  only when their funding-provenance class already holds `k_min` others, and defers
  the ones who would stand out. For a fund this means the coordinator refuses to
  settle an action that would be alone in its class, which is the failure mode below.
- **Denomination**: the payout is a fixed denomination within a pool, so the amount
  leaving reveals nothing about which member acted. A fund moving real inventory
  splits a large move into several fixed-denomination actions across rounds.
  Disanalogy with a coin mixer: there the denomination hides the amount; here the
  amounts are public by design, so the denomination hides only *which member*, not
  the total. We hide who, not how much.

## 5. Honest limits, named

- **Anonymity needs a crowd.** A fund acting in a fund-only or empty pool has
  effective-k near 1: everyone is a market maker, the set is homogeneous, and the
  ruler would show it. `act()` does not fix this; it measures it and the coordinator
  defers actions that would stand out. Real adoption needs retail and multiple funds
  sharing pools. This is why the audience is a spectrum, not just funds.
- **Latency.** Settlement waits for the round to fill. This suits position entry and
  exit where seconds to minutes is acceptable. It does not suit latency-critical HFT.
- **Trust model today.** Live settlement is committee-attested. The post-quantum
  on-chain STARK verification that removes the committee is the roadmap
  (`docs/M31_CIRCLE_STARK.md`), not shipped. `act()` works today on the committee
  path and inherits the on-chain verifier when it lands, with no interface change.
- **Aggregate leak.** N fixed-denomination actions to move a large position reveal
  the total as N times the denomination. We hide who moved each slice, not the sum.

## 6. What to build, phased (each phase its own gate)

- **Phase A** design (this document). **Done.**
- **Phase B** the unified derivation in `riverrun-core` (`riverrun_core::act`):
  `identity`, `commitment`, `nullifier` from one `s` with domain separation, plus
  tests that a wrong context or action yields a different leaf. **Done, 6 tests.**
- **Phase C** the `act()` orchestration and SDK (`riverrun-sdk`) that runs commit,
  round, prove, settle behind traits and returns a receipt with the measured
  effective-k, refusing to settle below the caller's floor. **Done, 5 tests.**
- **Phase D** the real devnet backend (committee path): `act()` running end to end
  on-chain. **Done and verified on devnet**: settlement
  `3XR8951sXTnHyNN9SrngfJWvVJ3XDJtf3gwPaBgmxsW4XYnKaPBSxLHHcbo2Ub5WJhQiyPnMvex2C7t2fHbejFJH`,
  and a second call with a floor of 104 above a crowd of 4 was refused on-chain,
  nothing settled (`programs/mirror-pool/examples/act_devnet.rs`). Still ahead here:
  a continuous-round coordinator and a per-pool configurable denomination sized for
  fund inventory, plus wiring the real effective-k (the ruler) into `await_round`
  instead of the optimistic devnet placeholder.
- **Phase E** a reference integration: a bot that enters and exits a position
  unlinkably, as the fund-facing proof that the primitive is real.

## 7. Falsifiable check

If, once Phase C exists, no high-value actor (fund, market maker, whale) will route a
single test action through `act()` within 90 days, the thesis that these are the
paying buyers is wrong, and the north star returns to retail. The design does not
assume adoption; it makes adoption measurable.
