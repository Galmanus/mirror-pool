# Pre-flight: know your anonymity before you act

*The measurement flipped from auditing pools to protecting users — the same core,
ten times the reach.*

## The leverage

`pool-provenance` audits a pool after the fact. Its audience is auditors and
researchers, and its finding — a live pool advertising k=30 delivers an effective
6.5 — is true but passive: it tells you a pool is weak, not what *you* should do.

`preflight` is the same core turned around. Before you deposit into **any** pool
on Solana, it traces your own funding graph, samples the pool's current
depositors, and tells you the anonymity *you personally* would get there — because
the advertised number is the pool's, not yours.

The reach is the point. Auditing pools reaches the people who audit pools.
Protecting a user at the moment they act reaches every user of every privacy
protocol on Solana — Umbra, Privacy Cash, the two other repos in this bounty when
they ship, any app on Arcium. It is protocol-agnostic by construction: it reads
public chain data, never the pool's internals, so it works against a program it
has never seen.

This is what the brief asks for in as many words: *tools people will genuinely
run in the wild* that make on-chain behaviour *far harder to read for automated
chain analysis*. You cannot defend what you cannot see, and until now no one on
Solana could see this from the user's side.

## What it does

```
preflight <YOUR_WALLET> [POOL_PROGRAM_ID] [SAMPLE]
```

Against a real wallet and the live Privacy Cash pool:

```
your provenance class : rootless (no attributable origin found within the bound)
depositors sampled    : 8
advertised anonymity  : 1 in 9
pool effective k (now): 3.8
YOUR crowd in this pool : 7 of 9 share your provenance class
VERDICT               : OK (within the trace bound)
```

Three verdicts, each with an action:

- **EXPOSED** — you'd be alone in your provenance class. The pool's size is
  irrelevant to you; an adversary reading the funding graph attributes your action
  immediately. *Fund a fresh wallet from a source other depositors also use, or
  wait for a same-origin crowd.* Anonymity is a crowd of people who look like you,
  not a large crowd.
- **WEAK** — a small minority shares your class; your real anonymity is far below
  the headline.
- **OK** — a healthy fraction shares your class, so the crowd is genuinely yours.

## The honesty that makes it safe to run

A tool that says "you're anonymous" and is wrong is worse than no tool. So the
bound is stated in the output and enforced in the logic:

- The trace is bounded (public RPC, SOL flows only, depth 3, capped fan-out), so a
  clean result is a **floor**. A deeper trace or a maintained tag database can
  only *shrink* your class, never grow it. "OK" means "no cheap attribution
  found", never "anonymous".
- The verdict is conditional on the same assumption the whole `effective_k`
  argument is: an adversary who can observe the provenance class of the acting
  identity. A fresh withdrawal wallet has to be funded from somewhere, which is
  what makes that assumption cheap — but it is stated, not buried.
- No wallet other than the one you pass is named in the output, and the pool's
  depositors are shown only as class fingerprints.

## How it composes

The assessment core is a pure function, `riverrun_trace::preflight`, tested
offline, that takes your provenance class and the pool's depositor classes and
returns your personal crowd, the pool's effective k, and a verdict. The mainnet
binary is a thin shell over it plus `provenance_class`, the bounded backward
trace shared with `pool-provenance`. Any Solana privacy protocol could embed the
core to show users their real anonymity at deposit time instead of the advertised
number — which is the public good this points at, and the reason it belongs in an
open, MIT repo rather than one submission's private feature.
