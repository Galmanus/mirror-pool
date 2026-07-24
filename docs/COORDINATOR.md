# The coordinator: an agent that forms private crowds

*Measured privacy is optimizable privacy. riverrun is the only system that can
measure a crowd's anonymity, so it is the only one where an agent can form a good
one on purpose.*

## The problem this solves

riverrun's privacy rests on a synchronized round: a crowd of members acting
together. The mirror-pool brief asks, in as many words, for "the coordination
layer, the privacy set, and the incentives that keep people in it." But nobody had
built the coordinator, because nobody could answer the question it turns on: *which
members should be in this round?*

A crowd is not privacy just because it is large. Anonymity is the effective
set size (see [EFFECTIVE_K.md](EFFECTIVE_K.md)), and that is decided by funding
provenance. The counter-intuitive fact:

- A crowd where everyone was funded from the **same** origin is strong. An
  adversary who learns "the actor's funding traces to Coinbase" has learned
  nothing --- everyone's does.
- A crowd of members with **distinct** origins is weak. Learning the actor's
  origin narrows them to the one member who has it. A member alone in their
  provenance class has an effective anonymity of exactly **one**, no matter how big
  the round.

So forming a round is an optimization: admit members whose origin is
well-populated, and keep out the ones who would be exposed.

## The policy, and its guarantee

`riverrun_trace::coordinator::coordinate(pending, k_min)` admits a member only if
at least `k_min` pending members share their provenance class. This is not a
heuristic that tends to help; it is a guarantee. Every admitted member lands in a
class of size $\geq k_{\min}$, so **no admitted member is exposed**, and among all
rounds with that property this one admits every safe member, so it is the largest.
Because it drops exactly the singleton and thin classes that fragment the
distribution, it also lifts the round's effective-k above the naive "admit
everyone" round --- a claim proven by a test, not asserted.

The deferred members are not abandoned. Each is told what to do: wait for more
same-origin members, or re-fund a fresh wallet from an origin the round already
has. Refusing to act, when acting would expose you, is the privacy-preserving
choice --- and an autonomous agent that acts on-chain should make it.

## The result, as an agent loop

```
cargo run --release -p riverrun-trace --example coordinator
```

Members arrive over time. The agent fires a round the moment a same-origin crowd
is ready, and holds the rest:

```
── tick 2 ─ arrived: dave, erin, frank
   FIRE ROUND: 3 members  |  effective-k 3.0  (worst member 3)
     admitted: alice, bob, dave
     vs batching all 6 waiting: effective-k 2.2  -- the smaller round is more private
     hold frank (self-mined): only 1 pending member shares your provenance origin
```

Every fired round beats the naive round on effective-k, with a smaller crowd, and
never exposes a member. That is the whole idea: an agent turning a measurement into
a decision.

## What it is and is not

The admitted set is exactly what feeds riverrun's batched round (Section on the
synchronized round in the paper): one proof, one verification, for the whole
crowd. The coordinator decides *who*; the STARK proves *that they acted*.

Honest scope. The clean setting is one operator running many identities --- an
agent fleet, a market maker --- who holds all the secrets and orchestrates their
own crowd. A crowd of mutually distrustful strangers would need distributed
proving to batch, which riverrun names as open rather than pretends to have. And
provenance classes come from a bounded, public-RPC trace, so "well-populated" means
"well-populated as far as a cheap trace can see" --- a floor, like every live
number in this repo.
