# riverrun on M31 — the Circle-STARK migration that puts verification on-chain

**Status: design, partially implemented.** This document specifies the migration
of riverrun's membership proof from the current Winterfell **f128 Rescue-Prime +
FRI** STARK (verified off-chain, gated on-chain by an M-of-N Ed25519 committee) to
a **Circle STARK over the Mersenne-31 field (M31)** whose proof is **verified
directly on-chain in a single Solana transaction (~31k CU)** — removing the
committee entirely.

> **Verified live (checked on-chain 2026-07-27).** A Circle-STARK verifier of the
> murkl class this migration targets is deployed and live on Solana devnet: program
> `StArKSLbAn43UCcujFMc5gKc8rY2BVfSbguMfyLTMtw` (272 KB, full verification, not demo
> mode), with a live pool holding real deposits. So a post-quantum Circle-STARK
> verifier already runs on a live cluster. That specific verifier is third-party
> code (`github.com/exidz/murkl`) whose repository ships an empty `LICENSE` file, so
> it is not redistributable and is not vendored anywhere in this repo; it is cited
> only as evidence of feasibility, the same way the rest of this document cites it.
>
> **`crates/riverrun-m31`, real and in-repo (2026-07-27).** riverrun now has its
> own Circle-STARK code, built without vendoring or copying any unlicensed source:
> it depends on the official Plonky3 crates (`p3-mersenne-31`, `p3-poseidon2`,
> `p3-poseidon2-air`, `p3-circle`, `p3-fri`, `p3-uni-stark`), published on
> crates.io under MIT OR Apache-2.0. It proves and verifies, end to end with a
> genuine Circle-STARK proof, knowledge of a Poseidon2-M31 permutation preimage
> (canonical Plonky3 round constants, not invented ones), which validates the whole
> pipeline the harder relation below needs.
>
> **§1a + §1c, real and in-repo (2026-07-28).** `crates/riverrun-m31/src/binding.rs`
> proves, as one Circle-STARK proof, that a leaf (`Poseidon2(secret ‖ action)`) and
> a nullifier (`Poseidon2(secret ‖ round)`) are bound to the same private secret:
> two Poseidon2 permutations packed into one row via Plonky3's
> `VectorizedPoseidon2Air`, with a same-row equality constraint over the shared
> secret cells. A dedicated soundness test attempts to prove a leaf and a
> nullifier built from two *different* secrets and confirms this panics at
> proving time, the trace is unsatisfiable, not merely that verification later
> rejects it. No vendored code (same Plonky3 crates as above).
>
> **§1b, real and in-repo (2026-07-28).** `crates/riverrun-m31/src/membership.rs`
> proves, as one Circle-STARK proof, that a leaf digest sits under a public
> Merkle root via a private `DEPTH`-step authentication path (`DEPTH = 4`, a
> provisional 16-leaf tree size, exactly CirclePcs's minimum committable row
> count, not a production size): a Poseidon2 compression folded per level, a
> private per-row bit choosing left/right order (constrained boolean), and a
> transition constraint tying each level's output to the next level's selected
> node, so the whole chain, not just one hop, is what verifies. A soundness
> test folds the wrong leaf through a genuine path and claims the original
> root; proving it panics, the forged trace is unsatisfiable. Composing
> `Poseidon2Air` with one extra private column needed `p3_uni_stark`'s
> `SubAirBuilder` (a column-windowed sub-builder, already exported, not
> vendored) so the inner AIR never sees riverrun's added `bit` column.
>
> **Composed, real and in-repo (2026-07-28).** `crates/riverrun-m31/src/relation.rs`
> proves and verifies the full relation end to end: `prove_full_relation` /
> `verify_full_relation` compose `binding.rs` and `membership.rs` via a shared
> public leaf value, checked outside either proof's algebraic constraints, the
> same composition an on-chain verifier would do (two proof checks plus one
> public-value equality). **Not one monolithic trace**: §1a+§1c and §1b stay
> two separately-verified proofs, not fused into a single AIR (that would need
> a row-type-selector AIR whose layout serves both a same-row two-block
> computation and a multi-row chained fold; real, larger, unstarted work). A
> regression test splices one member's real binding proof onto a *different*
> member's real membership proof, each individually valid alone, and confirms
> the composed check rejects it. 14 tests green. Still not built: any on-chain
> (SBF) verification of any of this. `cargo test --manifest-path
> crates/riverrun-m31/Cargo.toml`.

Why this is the decisive move: it is the one change that makes riverrun
simultaneously **(a) post-quantum, (b) transparent / no trusted setup, and (c)
verified on-chain with no trusted committee** — a position the pairing/Groth16
submissions cannot reach without abandoning their proof system, and one the current
f128 riverrun cannot reach because its proof is 12–16 KB and its verification is
3.77 M CU (k=4) — above Solana's 1.4 M per-transaction cap (measured in
`programs/stark-verifier/tests/cu.rs`).

Feasibility is not speculative: `murkl` ships **the first Circle-STARK verifier as a
general-purpose CPI target on Solana** — M31/QM31, keccak256, ~8.7 KB proof, **~31k
CU**, 128-bit post-quantum, deployed. This migration targets that class of verifier.

---

## 0. Field and hash choices

| Role | f128 (current) | M31 (target) | Why |
|---|---|---|---|
| Base field | `p = 2^128 − 45·2^40 + 1` | **M31: `p = 2^31 − 1`** | native 32-bit arithmetic; FFT-friendly (`p+1 = 2^31`); the field Circle STARKs are built for |
| Proof field | — | **QM31** (degree-4 ext of M31) | soundness sampling from the extension |
| In-circuit hash | Rescue-Prime | **Poseidon2 over M31** | arithmetization-oriented; the standard AO hash for M31 (Stwo, En-Cipher) |
| Commitment / Fiat-Shamir hash | BLAKE3 | **keccak256** | cheap on Solana via the `keccak` syscall; the hash murkl's on-chain verifier uses |

Post-quantum posture is unchanged: everything is hash-based (Poseidon2 + keccak),
no elliptic curves, no pairings, no trusted setup. Grinding + queries are set for
**128-bit conjectured security** (blowup 8, ≥43 queries or the Circle-STARK
equivalent, plus grinding), not the old ~84-bit demo set.

---

## 1. The AIR — one proof, four bound facts

Public inputs (what the verifier writes out, what the chain sees):

```
{ root, nullifier, round, action }
```

Private witness (never leaves the prover):

```
{ secret : [M31; k_s],           // the member's secret preimage
  leaf_index,                    // position in the set (Merkle authentication)
  merkle_path : [[M31; k_h]; D], // sibling digests up to the root
  cycle_prev  (ricorso only) }   // previous-cycle secret + migration path
```

The AIR arithmetizes exactly the relation already specified in the clear in
`crates/riverrun-core/src/membership.rs` (`check_relation`) and bound in one STARK
in `riverrun-stark`'s `bound_air` — restated over M31. Its trace proves, in one
proof, **four facts**:

### 1a. Commitment / leaf formation
```
leaf = Poseidon2( secret ‖ action )
```
A Poseidon2 permutation gadget occupies a fixed block of rows; the input cells are
`secret` and the two `action` limbs (public), the output cell is `leaf`. The
action limbs are **public inputs**, so the same proof that proves membership also
pins *which action* the leaf commits to — this is the **action binding** (1c).

### 1b. Membership under the root
A Poseidon2 Merkle-path verifier: starting from `leaf`, fold `D` levels
```
node_{i+1} = Poseidon2( ordered(node_i, sibling_i, bit_i) )
```
where `bit_i` is the `i`-th bit of `leaf_index` (selecting left/right), and assert
`node_D == root` (public input) via a boundary constraint. Each level is one
Poseidon2 block; the trace length is `(D + gadget_blocks) · rows_per_block`, padded
to a power of two for the circle-FFT.

### 1c. Nullifier binding
```
nullifier = Poseidon2( secret ‖ round )
```
A second Poseidon2 block over the **same** `secret` cells and the public `round`,
output asserted equal to the `nullifier` public input. Sharing the `secret` cells
with 1a is the binding: a prover cannot present member A's membership with member
B's nullifier, because both are constrained to read the one `secret` the trace
commits to. This is the constraint whose deletion must break a test
(`bound_nullifier` today) — carried over verbatim in intent.

### 1d. Ricorso (cycle migration) — optional second mode
For the round-over-round unlinkability the PR describes, a second AIR variant adds:
```
cycle_leaf = Poseidon2( cycle_secret(secret, c) ‖ action )
migration_nullifier = Poseidon2( secret ‖ "migrate" ‖ c )
```
proving the current-cycle leaf descends from *some* leaf under the **previous**
root while spending a migration nullifier (so one seat cannot fan into several
across cycles). This is the `docs/RICORSO.md` relation, arithmetized over M31; it
ships after the base membership AIR verifies on-chain.

**Constraint degrees.** Poseidon2's S-box is `x^5` over M31 (α=5), so transition
constraints are degree ≤ 5 within the permutation rounds, well inside a low blowup.
This is the concrete reason M31 + Poseidon2 is cheap where f128 + Rescue was not:
smaller field elements (4 bytes vs 16), a cheaper permutation, and a proof the
on-chain verifier reads in one transaction.

---

## 2. Proof + public-input wire format (murkl-compatible buffer)

The prover (off-chain, Stwo/Circle-STARK) emits a proof blob; the on-chain verifier
consumes it, runs the real verification (constraint checks, FRI folding, Merkle
paths, Fiat-Shamir over keccak), and on success **writes the verified public inputs
into a buffer account** that the riverrun pool program reads. The layout mirrors
murkl's integration contract so riverrun can target that verifier class directly.

### Verifier buffer account (read by the pool program)
```
offset  size  field
0       32    verifier discriminator / vk hash (which AIR was verified)
32       8    proof session id / nonce
40       1    FINALIZED flag  (1 == proof verified; the only byte that authorizes)
41      32    public input: root        (the membership root proven against)
73      32    public input: nullifier   (the revealed, spent-once nullifier)
105     16    public input: round       (u128 LE; only low 8 bytes used today)
121     32    public input: action      (the action hash the leaf commits to)
153     …     reserved / verifier bookkeeping
```

Design rules the pool program enforces when it reads this buffer:

1. **Owner check.** The buffer account MUST be owned by the configured
   `STARK_VERIFIER_ID` — a buffer the pool program itself cannot forge, only the
   verifier program can write the FINALIZED byte.
2. **FINALIZED == 1.** The single byte that means "the Circle-STARK proof for these
   public inputs verified." Anything else → reject.
3. **Public inputs must equal the settled tuple.** `root`, `nullifier`, `round`,
   `action` in the buffer must byte-equal the `execute` arguments, and `root` must
   equal the pool's published `membership_root` for the round. This binds the
   verified proof to *this* settlement — a stale or foreign proof buffer cannot be
   replayed.
4. **Freshness.** The session id / nonce plus the nullifier-PDA anti-replay
   (unchanged) prevent a finalized buffer from settling twice.

Everything the buffer carries is a hash or a field element — the on-chain state
stays post-quantum, exactly as the committee path already was.

---

## 3. On-chain integration — replacing the committee with the buffer

The current `execute` calls `verify_quorum(...)` (M-of-N Ed25519 attestations via
the instructions sysvar). The migration adds a **committee-free** settlement path,
`execute_verified`, that swaps *only* that gate:

```
execute (today)                         execute_verified (STARK path)
──────────────                          ─────────────────────────────
round / k_min / root checks     same →  round / k_min / root checks
verify_quorum(Ed25519 M-of-N)      →    verify_stark_buffer(verifier_buffer):
                                          - owner == STARK_VERIFIER_ID
                                          - buffer.FINALIZED == 1
                                          - buffer.{root,nullifier,round,action}
                                            == settled tuple, root == published
nullifier PDA init (anti-replay)  same → nullifier PDA init (anti-replay)
payout from vault                 same → payout from vault
```

No committee, no `verifiers`/`threshold`, no trusted M-of-N: settlement now
requires a **real post-quantum proof verified on-chain**. The committee path is
kept as a labelled legacy fallback until the Circle-STARK verifier is deployed to
mainnet, then removed.

**What builds where (the machine split).** `execute_verified` and its buffer parser
are pure SBF/Anchor and build + test here (against a mock finalized buffer). The
heavy half — the Stwo/Circle-STARK prover for the M31 AIR of §1, and the on-chain
Circle-STARK verifier program that writes the buffer — is the multi-session build
that needs a machine with real RAM/disk headroom; this laptop (3.9 GB free disk,
~0.7 GB free RAM) OOMs on the Winterfell toolchain, let alone Stwo.

---

## 4. Migration phases

1. **[this session] On-chain seam.** `execute_verified` + buffer parser + tests
   against a mock verifier buffer. Kills the committee *in the program structure*;
   ready to point at a real verifier.
2. **M31 AIR.** Implement §1's AIR over M31/Poseidon2; prove membership + nullifier
   + action binding; native tests. **In progress**: `crates/riverrun-m31` proves and
   verifies a Poseidon2-M31 permutation preimage today, on the official, licensed
   Plonky3 stack (`p3-circle` + `p3-fri` + `p3-poseidon2-air`). Still ahead: chaining
   permutation rows into a Merkle authentication path with index-bit routing
   (mirroring `riverrun-stark`'s `bound_air.rs`, adapted to Plonky3's AIR trait),
   then the nullifier and action binding on top.
3. **On-chain Circle-STARK verifier.** Deploy an M31 verifier that writes the §2
   buffer. `murkl`'s verifier is cited as feasibility evidence only, not a source
   to fork: its repository ships no license, so nothing from it is redistributable.
   The verifier here must be riverrun's own, built on the same licensed Plonky3
   primitives `riverrun-m31` already depends on. Wire `STARK_VERIFIER_ID`.
4. **Ricorso AIR (§1d).**
5. **Mainnet.** Deploy pool + verifier; settle a real action whose membership proof
   is verified on-chain, no committee. This is the headline: *the only submission
   that is post-quantum, trustless-setup, and on-chain-verified.*

---

## 5. Honest limits of this document

- The AIR here is a **specification**, not yet a proved-sound arithmetization; the
  Poseidon2-over-M31 round counts must be set from published security bounds before
  any "audited" claim (same discipline as the f128 AIR).
- **Formal zero-knowledge** is a separate axis: a plain Circle STARK (Stwo, murkl)
  is *not* witness-hiding by default. On-chain that is moot — only the nullifier is
  persisted, and it is a PRF output — but the off-chain proof's formal ZK needs the
  ethSTARK-style masking (eprint 2024/1037), independent of this migration.
- Reusing murkl's deployed verifier verbatim requires riverrun's AIR/public-input
  layout to match what that verifier was compiled for; if it is specialized to
  murkl's own claim AIR, riverrun ships its own M31 verifier for the §1 relation.
