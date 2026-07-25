# riverrun ID — a post-quantum anonymous-but-accountable identity layer for Solana

**Status: design / north-star.** The core primitive it stands on (the rotatable
piece) is built and tested in `crates/riverrun-core/src/rotatable.rs`, and its
rotation is proven in zero knowledge in `crates/riverrun-stark/tests/rotation.rs`.
What is *not* yet built is called out plainly in [§7](#7-honest-status). This is
the product north-star, not a shipped claim.

## 1. One line

**One secret. Unlimited unlinkable identities, one per context. One action per
context (sybil-resistant). Continuity provable in zero knowledge. Hash-based, so
post-quantum.** riverrun ID turns a single secret into a different, unlinkable
persona in every protocol on Solana, while still preventing one person from acting
twice where they should act once.

This is not a privacy *pool* (one use case). It is the identity *layer* many use
cases build on.

## 2. The primitive (this part exists)

A user holds one `Secret`. A **context** — call it an **angle** `θ` — is any public
label: a dApp, a DAO, an airdrop, a voting round, a verifier. The rotatable piece
(`Secret::piece`) derives, per angle:

- **shape** `H(secret ‖ θ)` — the user's identity *in that context* (a commitment
  leaf they publish).
- **fit** `H(secret ‖ θ)` — the spend-once nullifier for acting in that context.
- **turn** `H(secret ‖ θ ‖ θ+1)` — the migration witness, derivable only with the
  secret, that proves two contexts are the same piece.

All three are one collision-resistant hash (BLAKE3 in the spec crate, a
Poseidon-family hash in-circuit). No curves, no pairings, no trusted setup.

## 3. The three guarantees, and where each already lives

| Guarantee | What it means to a user | Backed by |
|---|---|---|
| **Unlinkable identities** | Your persona in DAO A and pool B cannot be tied together; cross-protocol clustering fails | `rotatable::unlinkable_across_angles` (test) |
| **Sybil-resistant, per context** | The fit is spent once per angle, so one secret = one action per context (one vote, one airdrop claim) | per-angle `fit` + on-chain nullifier registry (`programs/mirror-pool`) |
| **Provable continuity, hidden** | You can prove "I'm the same entity as in context A" without revealing which — reputation that doesn't dox | `rotatable::check_turn` (relation) + `tests/rotation.rs` (proven in ZK) |

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

// act, unlinkably, in any context
let dao_id     = me.piece().shape(dao_round);      // my identity in this DAO round
let vote_null  = me.piece().fit(dao_round);        // spend once — one vote

let airdrop_id = me.piece().shape(airdrop_epoch);  // unlinkable to dao_id
let claim_null = me.piece().fit(airdrop_epoch);    // one claim per person

// prove I am the same entity across contexts, without revealing which
let proof = prove_turn(prev_root, me, angle);      // ZK; reveals only {root, turn_tag, angle}
```

One secret, every context, no trail between them, one action each, quantum-safe.
That is riverrun ID.
