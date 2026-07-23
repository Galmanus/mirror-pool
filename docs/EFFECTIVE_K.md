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
