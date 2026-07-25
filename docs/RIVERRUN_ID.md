# riverrun ID — a post-quantum anonymous-but-accountable identity layer for Solana

**Status: primitive built and tested; the on-chain layer is design / north-star.**
The full seven-power primitive it stands on (the rotatable piece + RLN) is built and
tested in `crates/riverrun-core/src/rotatable.rs` and `rln.rs` (44 tests), and the
rotation is proven in zero knowledge in `crates/riverrun-stark/tests/rotation.rs`.
What is *not* yet built — the in-circuit membership, the Solana verifier, a mainnet
deploy, an audit — is called out plainly in [§7](#7-honest-status). This is the
product north-star, not a shipped claim.

## 1. One line

**One secret. Unlimited unlinkable identities, one per context. One action per
context (sybil-resistant). Continuity provable in zero knowledge. Hash-based, so
post-quantum.** riverrun ID turns a single secret into a different, unlinkable
persona in every protocol on Solana, while still preventing one person from acting
twice where they should act once.

This is not a privacy *pool* (one use case). It is the identity *layer* many use
cases build on.

## 2. The seven powers (built and tested)

A user holds one `Secret`. A **context** — an **angle** `θ` — is any public label (a
dApp, DAO, airdrop, voting round, verifier). From that one secret, `Secret::piece()`
gives seven capabilities, each a tested relation in
`crates/riverrun-core/src/rotatable.rs` (and `rln.rs`), each provable in zero
knowledge over the same STARK:

| # | power | what the user can do | backed by (test) |
|---|---|---|---|
| 1 | **shape** `H(s‖θ)` | be a different, unlinkable identity in every context | `unlinkable_across_angles` |
| 2 | **fit** `H(s‖θ)` | act once per context — sybil-resistant | `binding_within_an_angle` + on-chain nullifier registry |
| 3 | **turn** `H(s‖θ‖θ+1)` | prove "I'm the same entity across cycles" in zero knowledge, revealing *which* to no one | `check_turn` + `tests/rotation.rs` (proven in ZK) |
| 4 | **link** | selectively reveal that two of your identities are one — to whom you choose, only for the contexts you pick | `check_link` |
| 5 | **grant** `H(s‖θ‖delegate)` | delegate one context to an agent — bound to that agent, scoped to that angle, never your master secret | `check_delegation` |
| 6 | **rln** (Shamir) | rate-limit yourself: N actions per context stay anonymous, the N+1-th lets anyone recover your secret and unmask you | `rln::*` |
| 7 | **credential** `H(s‖attr)` | carry an issuer's attribute (verified, over-18) and show it per context, without doxxing | `check_attribute` |

All are one collision-resistant hash (BLAKE3 in the spec crate; a Poseidon-family
hash in-circuit) plus, for RLN, Shamir sharing over a prime field. No elliptic
curves, no pairings, no trusted setup — post-quantum throughout. **44 tests green** in
`riverrun-core`.

## 3. The shape of it

You are **invisible by default** (1), **accountable where it matters** (2, 6),
**continuous when you choose** (3), **linkable only on your terms** (4), able to
**lend a single context to an agent** (5), and able to **prove facts about yourself
without a trail** (7). One secret, total control of your own exposure. Few systems
anywhere hold all seven at once; none does it post-quantum on Solana.

## 4. What it unlocks (the category, not one app)

- **Anonymous DAO voting** — one vote per member, no one learns who voted how.
- **Sybil-resistant airdrops** — one claim per person, unlinkable to their wallet.
- **Portable, unlinkable reputation** — prove "verified member / good actor" across
  protocols without a trail joining them.
- **Rate-limited anonymous actions (RLN-style)** — post or act under a per-context
  cap, with no identity attached.
- **Private-but-accountable participation** — any protocol that needs "anonymous,
  but one-per-person" gets it as a drop-in.

Each is a `θ`. The same secret, the same primitive, a different angle.

## 5. Architecture — the assembly

riverrun ID is an *assembly* of vetted parts, not new mathematics:

```
user secret ─┬─ shape(θ)  → published as a leaf in context θ's set
             ├─ fit(θ)    → revealed once to act in θ (nullifier registry rejects repeats)
             └─ turn(θ)   → proves continuity θ→θ+1 in zero knowledge

  membership + nullifier + turn, proven by:
     an M31 Circle-STARK over a Poseidon2 Merkle path        [to build — En-Cipher / Plonky3 as reference]
  verified by:
     a no_std Solana verifier (murkl / Stwo class), ~tens of k CU   [to build — the on-chain gap]
  measured by:
     the effective-k ruler — the real anonymity of each context's set   [exists, runs on mainnet]
```

The behavioral layer (which piece, unlinkable) and the measurement (effective-k)
are riverrun's own; the proof system and hash gadget come from the ecosystem
(Plonky3, En-Cipher's membership AIR, murkl/Stwo verifiers).

## 6. Honest positioning

This design is **not new in concept.** On Ethereum it is essentially **Semaphore**
(a secret identity + external/scoped nullifiers = unlinkable per-context identity +
sybil resistance), used by Worldcoin, RLN, and others. riverrun ID does **not**
claim to invent that.

What is genuinely uncommon is the **combination**: a **post-quantum (hash-only, no
curves)** identity layer, on **Solana** — which has no Semaphore-equivalent today —
with an **adversarial effective-k ruler** that measures how real each context's
anonymity actually is. The honest sentence:

> "Solana has no Semaphore. riverrun ID is a post-quantum, transparent one, with a
> ruler that tells you your real anonymity per context."

That is a defensible *infrastructure* position, not a claim of a new primitive.

## 7. Honest status

**Exists, tested:** the rotatable piece (`shape`/`fit`/`turn`), the turn relation
(`check_turn`), the turn proven in zero knowledge over the bound-membership STARK,
the effective-k ruler on mainnet, the on-chain nullifier registry + committee-gated
settlement, and an M31 verifier accepting riverrun's relation in a local VM (~160k
CU).

**Not yet built (the gap to "usable identity layer"):**
- **In-circuit Poseidon2 Merkle membership** (today the root is a public input; the
  hash foundation is done on Plonky3's vetted parameters, arithmetization is next).
- **A Solana on-chain verifier** for that proof (no_std verifier wrapped in an SBF
  program; murkl and Stwo show the class).
- **Formal zero-knowledge** (witness is kept off the wire but not formally proven ZK;
  En-Cipher and SmallWood are the reference lines, both with the formal-simulator
  question still open).
- **Mainnet deployment and an audit** before this guards real identities.

None of these is new mathematics. All are integration of vetted parts — which is
exactly what a disruptive *tool* on a new chain is made of.

## 8. Developer surface (sketch)

```rust
// one secret, minted once from the OS CSPRNG
let me = Secret::random();

// 1 + 2 — a different, unlinkable identity in each context; act once each
let dao_id  = me.piece().shape(dao_round);        // my identity in this DAO round
let vote    = me.piece().fit(dao_round);          // spend once — one vote
let drop_id = me.piece().shape(airdrop_epoch);    // unlinkable to dao_id
let claim   = me.piece().fit(airdrop_epoch);      // one claim per person

// 3 — prove I'm the same entity across cycles, revealing which to no one (ZK)
check_turn(&TurnStatement { prev_root, angle, turn_tag: me.piece().turn(angle) }, &wit);

// 4 — selectively link two of my identities, to a chosen verifier only
check_link(&LinkStatement { shape_a, angle_a, shape_b, angle_b }, &LinkWitness { secret: me });

// 5 — let an agent act as me in ONE context, bound to the agent, scoped to θ
let g = me.piece().grant(dao_round, &agent_pubkey);
check_delegation(&DelegationStatement { set_root, angle: dao_round, delegate: agent_pubkey, grant_tag: g }, &wit);

// 6 — rate-limit myself: N acts stay hidden, the N+1-th reveals my secret
let point = riverrun_core::rln::share(&me, dao_round, /*limit=*/ 3, x);

// 7 — carry & show an issuer's attribute, per context, without doxxing
check_attribute(&AttributeStatement { attr_root, attr, angle: dao_round, shape: dao_id }, &wit);
```

One secret, every context, no trail between them, one action each, delegable,
rate-limited, credential-bearing, quantum-safe. That is riverrun ID.
