# The repeated-use bound: measuring how a persistent identity erodes

_The ruler measures the anonymity of a **single** action. riverrun ID's value is a
**persistent** identity used **repeatedly**. This document defines the metric for that
gap — the effective-k of a persistent identity across its uses — computes it, and shows
that the metric fires exactly the defense riverrun already has. It is the honest number
for what riverrun ID is, and it turns Danezis's warning (single-shot entropy is "very
poor" at repeated use) into a construction. Paper-track; the computation is concrete
enough to build._

## 1. The gap, precisely

A user holds one secret `s` and acts in contexts θ₁,…,θₙ through pseudonyms
`Pᵢ = shape(s, θᵢ)`. Cryptographically the `Pᵢ` are mutually unlinkable, and — being
hashes — **everlastingly** so (§3 of [`RIVERRUN_ID_THEORY.md`](RIVERRUN_ID_THEORY.md)):
no adversary, quantum or otherwise, links `P₁` to `P₂` through the pseudonyms.

So where is the leak? Not in the pseudonyms. In the **side channel the ruler already
measures**: funding provenance. A user's funding origin is a *persistent physical
attribute* — it is the same in every context, no matter how unlinkable the pseudonyms
are. The adversary does not need to break `shape`; it links a user's actions across
contexts by the **origin**, which recurs, and then intersects.

> Cryptographic unlinkability hides the pseudonym. It does **not** hide a persistent
> quasi-identifier that rides underneath every use. Provenance is exactly such a
> quasi-identifier, and the funding graph is public.

This is the classic **intersection / statistical-disclosure attack** from the mix
literature, arriving at riverrun ID through the one channel the ruler was built to see.

## 2. The metric

Let `U` be the population (a pool's members). In context `i` the adversary observes a
feature of the actor, `Xᵢ = φᵢ(u)` — at minimum the provenance class, optionally a
per-context behavioral feature (timing bucket, size bucket). Define the candidate set
after context `i`:

```
Sᵢ = S_{i-1} ∩ { v ∈ U : v consistent with the observation Xᵢ },   S₀ = U
```

The **repeated-use effective-k** is the effective size of the surviving candidate set:

```
k_eff⁽ⁿ⁾ = 2^{ H(posterior over Sₙ) }      ( = |Sₙ| when the posterior is uniform )
```

Two facts make this the right number:

- **It is monotone non-increasing.** `k_eff⁽ⁿ⁾ ≤ k_eff⁽ⁿ⁻¹⁾ ≤ … ≤ k_eff⁽¹⁾`. More uses
  never help. The single-shot ruler reports `k_eff⁽¹⁾`; the honest number for a
  persistent identity is `k_eff⁽ⁿ⁾`, which the single-shot number **over-states**.
- **It reduces to the current ruler at n = 1.** `k_eff⁽¹⁾` is exactly Serjantov–Danezis
  conditioned on provenance — the number riverrun already measures. This is a strict
  generalization, not a replacement.

## 3. The composable bound (the differential-privacy budget)

Per-context privacy loss is the entropy the observation removes:

```
εᵢ = H(u | X_{<i}) − H(u | X_{≤i})  ≥ 0        (bits leaked by context i)
```

By the telescoping sum, the cumulative leak after `n` uses is

```
Σᵢ εᵢ = H(u | ∅) − H(u | X_{1..n}) = log₂|U| − log₂ k_eff⁽ⁿ⁾
⇒  k_eff⁽ⁿ⁾ = |U| · 2^{ −Σᵢ εᵢ }
```

A persistent identity's anonymity **decays exponentially in its accumulated per-use
leak.** This is the differential-privacy view Danezis proposed, made concrete for
riverrun: each use spends a privacy quantum `εᵢ`; the identity has a budget; when the
budget is spent the identity is effectively named.

Set an anonymity floor `k_min`. The identity is safe to keep using under one secret
while

```
Σᵢ εᵢ ≤ log₂( |U| / k_min )      — the budget
```

and the moment the cumulative leak crosses it, `k_eff⁽ⁿ⁾ < k_min`: the identity is spent.

## 4. The closure — the metric fires `turn`

Here is why this is riverrun's, not a generic disclosure-attack note. **When the budget
is spent, the defense is already a power.** `turn` rotates the secret to a fresh
lineage `sₖ₊₁`, whose pseudonyms have a fresh, un-intersected candidate set — it *resets
the accumulated crypto-linkage to zero.* So the repeated-use metric is not just a
warning; it is the **trigger** for rotation:

> Act under one secret until your measured `k_eff⁽ⁿ⁾` reaches the floor; then `turn`.
> The ricorso, given a quantitative firing condition.

This is the same move riverrun makes everywhere — **measure, then defend** — now closing
on identity: an anonymous identity that *measures its own erosion and rotates itself
before it is named.*

## 5. The honest limit that makes it real

`turn` resets the **crypto** lineage. It does **not** reset the **physical
quasi-identifier.** If you rotate `s` but keep funding from the same origin, the
origin-based intersection survives the rotation — the adversary re-links the new
lineage by the same recurring origin. So rotation alone is *necessary but not
sufficient*. The two defenses compose:

- `turn` — reset the pseudonym lineage (defeats pseudonym accumulation), **and**
- re-provenance — fund the next lineage from a *common* origin so the persistent
  quasi-identifier stops being rare (defeats the origin-linkage). This is exactly what
  `preflight` already advises for a single action, now extended across the identity's
  life.

Stating this is the difference between a metric that flatters and one that holds:
rotating your secret while keeping a rare funding origin buys far less than it appears.

Other honest edges, consistent with the ruler's existing floor semantics:

- `k_eff⁽ⁿ⁾` is a **floor** under a stated observation model `{φᵢ}`. A richer adversary
  (more persistent features: device, behavioral timing) sees additional channels; these
  are *additive in ε*, so the framework absorbs them, but they must be enumerated — an
  unlisted channel is unmeasured leak.
- Basic composition (`Σεᵢ`) is a worst-case bound. Correlated features can erode faster
  than independent ones in the tail; advanced composition gives a tighter typical-case
  `√(2n ln(1/δ))·ε` but assumes near-independence riverrun should not assume silently.
- The metric measures **erosion given participation**; it does not by itself hide *that*
  an identity participated. Hiding participation is the pool's job (the actor↔action
  unlink), which composes with this.

## 6. Worked example — erosion in three uses

Pool of `|U| = 30`. Floor `k_min = 4`, so the budget is `log₂(30/4) ≈ 2.9` bits.

| use | what the adversary learns | candidate set | `k_eff⁽ⁿ⁾` | `εᵢ` (bits) | Σε |
|---|---|---|---:|---:|---:|
| 1 | origin A (persistent) | 6 of 30 | **6.0** | 2.32 | 2.32 |
| 2 | + timing bucket (same origin) | 3 of 6 | **3.0** | 1.00 | 3.32 |
| 3 | + size bucket | 1 of 3 | **1.0** | 1.58 | 4.90 |

Each single-shot check looks survivable (6, then 3). The persistent identity is
**named after the third use** — and the budget was already blown at use 2
(`Σε = 3.32 > 2.9`, `k_eff = 3 < 4`). riverrun ID's correct behavior: after use 1,
`k_eff⁽¹⁾ = 6 ≥ 4`, act. Before use 2 would drop it under the floor, **`turn` to a fresh
secret and re-fund from a common origin** — resetting both the lineage and the
quasi-identifier — rather than spending the third use into de-anonymization.

The single-shot ruler would have said "6, fine." The repeated-use ruler says "you have
one safe use left under this secret, then rotate." That difference is the contribution.

## 7. Making it computable

The ruler already builds per-context provenance classes; the repeated-use metric is the
running **intersection** of a user's candidate sets across their contexts, plus the
entropy of the survivor. A concrete `riverrun-eval` surface:

```rust
/// Feed the sequence of a persistent identity's uses (context + observed classes);
/// get the erosion curve and the rotation trigger.
pub struct Use { pub context: u64, pub observed: Vec<ClassId> }

pub struct Erosion {
    pub k_eff: Vec<f64>,     // k_eff^(1..n): the identity's anonymity after each use
    pub spent_bits: Vec<f64>,// cumulative Σε after each use
    pub rotate_before: Option<usize>, // first use that would breach k_min → turn here
}

pub fn repeated_use_effective_k(population: &Population, uses: &[Use], k_min: f64) -> Erosion;
```

It is deterministic, offline, and reuses the existing class-partition code — the same
discipline as `exhibit`: measured on riverrun's own constructions before it is claimed.

## 8. What this is, in one line

> **An anonymous identity that measures its own erosion under repeated use and rotates
> itself before it is named** — effective-k extended from one action to a persistent
> identity via the intersection attack on the provenance channel, with a
> differential-privacy budget that fires `turn`. The open metric riverrun ID needed,
> built from the ruler it already has.

## References

Adds, to those in [`RIVERRUN_ID_THEORY.md`](RIVERRUN_ID_THEORY.md):

- G. Danezis. *Statistical Disclosure Attacks: Traffic Confirmation in Open
  Environments.* SEC 2003. (the intersection attack over a persistent pseudonym)
- D. Kesdogan, D. Agrawal, D. Pham, D. Rautenbach. *Fundamental Limits on the Anonymity
  Provided by the MIX Technique.* IEEE S&P 2006. (the hitting-set / disclosure limit)
- C. Dwork, A. Roth. *The Algorithmic Foundations of Differential Privacy.* (basic and
  advanced composition, the ε-budget)
- G. Danezis. *Measuring anonymity: a few thoughts and a differentially private bound.*
  (the repeated-use critique this document answers)
