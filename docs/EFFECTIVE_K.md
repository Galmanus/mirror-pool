# Your k is not your k

*A measurement of what a live Solana anonymity set is actually worth, and the
ruler that produced it.*

Every anonymity pool in this space reports the same number: `1/k`. There are k
members, so an observer has a one-in-k chance of attributing an action. It is the
number in every README, including this one.

That number counts **members**. It says nothing about where those members' money
came from — and on a public ledger, where the money came from is public.

If an adversary can sort the set into classes by funding provenance, then
learning which class the actor belongs to leaves only that class to guess within.
The advertised k is an upper bound that nobody had measured.

## The result

Run against a live Tornado-style SOL privacy pool on Solana mainnet
(program `9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD`), sampling 30 real
depositors:

| | |
|---|---|
| depositors sampled | 30 |
| reach an attributable origin | **11 / 30 (37%)** |
| mean depth to that origin | **1.18 hops** |
| provenance classes | 12 |
| largest class | 19 / 30 (63%) |
| residual anonymity | 2.69 bits |
| **advertised k** | **30** |
| **effective k** | **6.5** |
| **worst case** | **1** |

A set advertising 30 delivers 6.5. And the worst case is not a rounding error:
at least one depositor sits alone in their provenance class. For that person the
pool provides no anonymity at all against an adversary who reads the funding
graph — while the pool's own dashboard would report their anonymity as 1-in-30.

Reproduce it:

```bash
cargo run --features onchain --bin pool-provenance -- <POOL_PROGRAM_ID> 30
```

## What that number does not know, and the gate that now refuses it

The 6.5 above is a point estimate from one sample with two uncertainties stripped
off it. Both are now computed, and the run is re-measured offline against its own
committed histogram by `riverrun runs` (no RPC, fixed seed):

```
effective-k, unresolved merged (as published) : 6.45
effective-k, unresolved split (adversarial)   : 1.00
bracket                                       : 1.00 … 6.45 members
95% resampling range of the merged reading    : 4.90 … 13.31
                                                (bias +1.79, 10,000 replicates,
                                                 seed 0x726976657272756e)
gate : REFUSED — 11 of 30 members (37%) reached an origin, under the 50% floor
```

**The bracket.** 19 of the 30 depositors reached no attributable origin within
the trace bound (depth 3, 14 nodes, SOL transfers only). They were reported as
one shared "rootless" class. That is a *reading*, not a measurement: merging them
is the most favourable interpretation available, and it is the one that produced
6.5. Split them into singletons — the adversarial reading, equally consistent
with what was observed — and the same run reads as **1.0**. The truth is
somewhere in 1.0…6.5, and most of the published number is the part we did not
resolve. `riverrun_trace::uncertainty::Bracket` computes both ends exactly.

**The sampling range.** Resampling the 30 members with replacement and
recomputing effective-k puts the estimator in 4.9…13.3. It is a bootstrap
percentile range, **not** a confidence interval, and it does not contain the
point at its centre: the population is one crowd plus eleven singletons, and
resampling drops a singleton class about 37% of the time, which raises the
estimate. The `+1.79` bias is that tail, reported next to the range instead of
hidden inside it. A second bias runs the same way and is *not* corrected here:
plug-in entropy from counts understates `H(C)` at small `n`, and by
`H(X|C) = log2 K − H(C)` that overstates effective-k. Every effective-k in this
repository is plausibly optimistic.

**The gate.** `Bracket::gate` refuses to publish a single effective-k when fewer
than half the members resolved, or fewer than 8 did, or more than 1% were lost to
our own RPC. This run fails the first: 37% resolved. The refusal is enforced in
code and tested (`the_published_run_does_not_pass_this_crate_s_own_gate`), not
printed as a caveat someone can drop when quoting the figure. **6.5 is the
ceiling of a bracket, not a result.** The honest statement of this measurement is
*"a live pool advertising 30 delivers between 1.0 and 6.5, and this sample cannot
narrow it further"*.

`riverrun audit` now emits the census, the bracket, the range and the gate
verdict on every live run, in text and in `--json`.

**What is still missing, named rather than implied.** The per-member evidence of
this run — the sampled depositor addresses, the funding edges walked, the hubs
reached — was never written to disk. Only the class histogram is committed, so a
third party can recompute the arithmetic (`riverrun runs`) but cannot re-check
the tracing without re-running against a live RPC and drawing a different sample.
The neighbouring measurement in this bounty (`solanabr/mirror-pool` PR #5) commits
its raw per-member chains and is offline-checkable in a way this run is not.

## What this is not

**Not a vulnerability in that pool.** No deposit-pool design can control where
its users' money came from. The funding graph is outside the protocol's trust
boundary entirely — which is exactly why it goes unmeasured, and exactly why it
keeps working as an attack. This measurement applies to every construction in
this class, riverrun included, and the section below applies it to riverrun.

**Not a claim about any individual.** The tool reports aggregates. No depositor
is named in its output, and none is named here.

**Not an upper bound.** It is a floor. Public RPC, SOL transfers only, depth 3,
at most 14 addresses per target, and hub labels from an activity heuristic rather
than a maintained tag database (Arkham, Chainalysis). A funded analyst measures
more, never less. n = 30 from recent activity is a sample, not a census.

**Conditional on an assumption, stated rather than buried.** Provenance classes
shrink the adversary's search space only for an adversary who can also observe
the provenance class of the *acting* identity. A fresh withdrawal wallet has to
be funded from somewhere, which is what makes that assumption cheap — but it is
an assumption.

## Where this sits in the literature

Two things here are borrowed, and saying so is the point: the metric is standard,
and the research programme is established. What is new is the channel and the
chain.

**The metric is Serjantov & Danezis (2002).** "Towards an Information Theoretic
Metric for Anonymity" (PET 2002, that year's Award for Outstanding Paper in
Privacy Enhancing Technologies) defines the *effective anonymity set size* as the
entropy of the probability distribution linking subjects to the observed event,
rather than the raw count of subjects. `effective_k` is exactly that, conditioned
on the adversary observing the actor's provenance class: the adversary sees class
`c` with probability `n_c/n` and is left with a uniform posterior over its `n_c`
members, so the conditional entropy is `Σ_c (n_c/n)·log2(n_c)` — the formula
above — and `2^H` is the group size the member is actually hidden in.

Díaz et al. proposed normalising that entropy by the maximum the system could
provide. We deliberately do not, following Danezis's objection that the
normalised form measures fulfilled potential rather than anonymity: a set of one
scores a perfect 1.0 while providing none.

**The programme is established — on Ethereum.** Measuring the gap between a
mixer's advertised anonymity set and its true one is a research line with real
results:

- **Tutela** (Stanford, arXiv 2201.06811) reports the true size of each Tornado
  Cash pool by excluding compromised deposits.
- **Béres et al.**, *Blockchain is Watching You*, profiles Ethereum users by
  quasi-identifiers and applies them to Tornado Cash.
- A **cross-chain study** (arXiv 2510.09433, October 2025) links **5.1–12.6%** of
  Tornado withdrawals to their deposits via address reuse and transactional
  linkage, and a further **15–22 percentage points** with a FIFO temporal-matching
  heuristic — over $2.3B of withdrawals connected to identifiable deposits.
- **Du et al.** (IEEE TIFS, 2024) correlate mixing addresses with graph neural
  networks.

That literature is also a sanity check on the number above. Our 37% is the same
order of magnitude as the 20–35% those heuristics reach on Tornado. A result of
95% would have been a reason to distrust the tool rather than the pool.

**What is not in it.** Every heuristic in that body of work is *behavioural* —
address reuse, deposit/withdrawal timing, FIFO ordering, wallet fingerprints —
and none of it has been run on Solana. The programme exists; it stopped at
Ethereum, and it stopped at behaviour.

**Credit where it is due, including to a competitor.** Within this bounty, the
funding-graph channel is not unmeasured. [`supersonic-tx` PR
#4](https://github.com/solanabr/supersonic-tx/pull/4) (@gustavo-f0ntz) measures
funding provenance on real mainnet data as a residual **adversary advantage** of
**+0.27…+0.51** for durable P2P payees, alongside the finding that **63.4% of
real mainnet transfer destinations already have on-chain history** (n=1181), and
leaves it honestly open. That work reached the same channel from the decoy side.

The two measurements are complementary rather than competing, and it is worth
being precise about the difference. Theirs asks: *how much better than chance can
an adversary pick the real leg out of a decoy bundle, given provenance?* — an
advantage, measured against deployed selection code. This one asks: *what is the
whole depositor population of a live anonymity pool actually worth, in members,
once provenance partitions it?* — an effective set size, measured against a
deployed pool. Different object, different metric, same channel, and neither
subsumes the other.

**And inside `mirror-pool` too.** [PR
#5](https://github.com/solanabr/mirror-pool/pull/5) (@thiagorochatr) measures the
same channel against a live mainnet mixer and reports `ρ = 0.0955` with an
unresolved bracket of `0.0350…0.1136` and a 95% sampling interval of
`0.0848…0.1790`, 54 of 83 members resolved, with six of its eight collection runs
published as unpublishable. The statistical apparatus in the section above —
bracket, bootstrap range, refusal gate — is the answer to that work, and the
prior claim on this line that no other submission measured this channel was
wrong.

The objects differ, which matters when comparing the two numbers. Theirs is
`ρ = 2^{−H(C)}`, the *fraction* of nominal k that survives, chosen because it is
independent of `k` and therefore comparable across pools of different sizes.
Ours is `effective_k = 2^{H(X|C)}`, a member count, which is not: an effective-k
of 6.5 at n=30 and one at n=83 are not the same statement, and this repository
does not compare them. The two are related by the chain rule
`H(C) + H(X|C) = log2 K`, so on one sample they carry the same information — but
only on one sample.

## The ruler

Residual anonymity is the class size, averaged over which class the actor came
from:

```
H_residual = Σ_c (n_c / n) · log2(n_c)        effective k = 2^H_residual
```

One class holding everyone returns `log2(n)`: nothing was partitioned, the set is
worth its advertised size. All-singleton classes return 0 bits — an effective k
of 1, every member individually identified.

The direction is the whole thing, and the first version of this had it backwards.
It is tempting to measure how *concentrated* the classes are — min-entropy over
the class distribution — but that reports a catastrophic effective k precisely
when the measurement found nothing to partition on. A single class of 7 came out
as "effective k = 1" when the honest reading is "effective k = 7, we found no
roots". Four unit tests in `riverrun-trace` now pin the direction, and one of
them caught the arithmetic a second time.

Implementation: `riverrun_trace::effective_k`, used unchanged by both the live
scan and the synthetic exhibit, so the two are comparable.

## The same ruler, applied to riverrun

Measuring other people's pools and not your own is marketing. `cargo run --bin
provenance-tracer` runs the metric over the three constructions this repo ships,
with the same 2000 members in each:

| construction | root-hit | attrib. (bits) | in-cycle | **effective k** |
|---|---|---|---|---|
| rooted decoy (the field) | 100.0% | 0.00 | 0.0% | **500** |
| cyclic, ambiguous root | 100.0% | 2.90 | 100.0% | **2000** |
| cyclic, rootless | 0.0% | 0.00 | 100.0% | **2000** |

The same 2000 members are worth 500 under the construction the field ships, and
2000 under circularity. That is the Finnegans Wake idea — a funding cycle with no
origin to name — stated as a number instead of a metaphor.

Honest caveat, the same one the exhibit prints: "rootless" holds only while the
pool's funding sources are themselves unattributable. One known CEX entry
degrades it to "ambiguous", which is still a large win and a smaller, measured
one.

## Why this belongs in this bounty

The brief asks for tooling that makes on-chain behaviour "far harder to read for
automated chain analysis", and for noise that "actually defeats modern
clustering, not naive randomness". You cannot claim to defeat an analyst you
never ran, and you cannot report progress on a number nobody measures.

`pool-provenance` is runnable today, against mainnet, by anyone, on any pool
program — including the other two repos in this bounty when they ship theirs. It
does not depend on riverrun's cryptography. Whatever construction wins here, the
funding graph is the channel it will be judged on next, and this is the
instrument that reads it.
