# A structural study of *Finnegans Wake*, chapter by chapter, for riverrun

*What the whole book actually contains, and which of its structures map to real
cryptographic constructions rather than decoration.*

Method, stated honestly. This is a study of the primary text — Joyce's actual
words, read from the full text at finwake.com and from the book's real content
across all four Books — not a plot summary. Finnegans Wake has no plot to
summarize; it has **structures**, and structures are what a privacy system can
borrow. For each chapter below: the device Joyce actually built, and a verdict —
**STRUCTURE** (could become code, and how) or **RESONANCE** (a true echo, but
decoration if forced into architecture). The bar is deliberately harsh, because a
literary flourish with no code behind it is exactly the kind of thing a serious
reader discounts the rest of a submission for.

The book is built on Giambattista Vico's four ages, so it has four Books. We go in
order.

---

## Book I — birth / the fall (chapters 1–8)

**I.1 — the fall.** The book opens mid-sentence (`riverrun, past Eve and Adam's`)
and the first event is *the fall*, marked by a hundred-letter thunderword:
`bababadalgharaghtakammin­arronnkonn­bronntonner­ronntuonn­thunn­trovarrhou­nawnskawn­toohoohoorden­enthurnuk`. The fall "is retaled early in bed and later on
life down through all christian minstrelsy" — **the same event retold across
time, mutating with each telling.**
→ *STRUCTURE (weak).* The ten thunderwords mark forced transitions between ages;
they map to **epoch/cycle-transition commitments** — the boundary markers of the
ricorso. Usable to name the cycle-advance event, but not load-bearing on its own.

**I.2 — the naming and the crime.** HCE is given his name and accused of an
unspecified indecency in Phoenix Park, witnessed ambiguously. The accusation
spreads as gossip and hardens into "The Ballad of Persse O'Reilly" — **an
attribution that travels through a chain of retellers, each hop lossy and
distorting, until the "evidence" is hearsay that grew in transit.**
→ *STRUCTURE (moderate).* This is the funding-graph attack seen from the
defender's side. Attribution is a chain of inferences; each hop loses fidelity.
It is exactly why the tracer's backward walk is **depth-bounded and reports
attribution *entropy*** — the further from the act, the more the attribution is
rumor. The Ballad is the adversary; the entropy is our measure of how garbled the
rumor is. (Already implemented: `attribution_entropy_bits`.)

**I.3–I.4 — the trial, and the Four as judges.** HCE is tried. The **Four Old Men
(Mamalujo** — Matthew, Mark, Luke, John, based on the Four Masters who compiled
the *Annals of Ireland*) serve as **judges**. They are senile and give four
**contradictory** accounts; no single one is authoritative, and the verdict, such
as it is, emerges only from their aggregate.
→ **STRUCTURE (strong, buildable).** See *The load-bearing find* below.

**I.5 — the mamafesta (ALP's letter).** A letter defending HCE, dug from a midden
heap by a hen, is examined. It has **no definitive text**: its authorship is
disputed, its meaning endlessly re-interpreted, a tea-stain on it read as
evidence. "Every letter is a godsend."
→ *STRUCTURE (moderate).* A message whose **authorship is undecidable and
deniable**. Maps to a *deniable-execution* construction: an action whose author,
even to themselves under coercion, is not provable — plausible deniability as a
property, not a hope. Related to the equivocation/polysemy insight; a real
direction, not yet built.

**I.6 — the twelve questions; Shem and Shaun.** A quiz of twelve questions
introduces the cast. The twin brothers **Shem the Penman** (the forger, the
artist, the outcast) and **Shaun the Post** (the deliverer, the respectable one)
are opposites who **exchange roles** through the book.
→ *RESONANCE.* Shem/Shaun swap = exchangeability of two parties, which our
ambiguous-origin construction already generalizes to many. No new code.

**I.7 — Shem the Penman.** Shem writes "over every square inch of the only foolscap
available, his own body" — a self-written, self-authenticating text.
→ *RESONANCE.* The prover is the code writing its own proof; nice framing for the
no-trusted-setup property, decoration only.

**I.8 — Anna Livia Plurabelle.** The famous river chapter: two washerwomen gossip
across the Liffey while washing HCE's dirty laundry, and the prose is woven from
**roughly eight hundred river-names** from around the world. As night falls they
turn to stone and tree. **Every identity in the world is dissolved into the flow
of one river.**
→ *RESONANCE (beautiful, not code).* This *is* the mixer, as literature: the
anonymity set as a river of names, laundry washed until the dirt is everyone's.
The strongest image in the book for what riverrun does, and worth one sentence in
the paper — but it is a picture of the existing k-anonymity, not a new mechanism.

---

## Book II — marriage / maturity (chapters 9–12)

**II.1 — the Mime (the children's games).** The children play a guessing game:
Shem (as "Glugg") must guess the colour the girls represent, and **fails** — the
answer is heliotrope, hidden in riddling clues he cannot decode.
→ *RESONANCE.* A commitment the guesser cannot open without the secret. It is the
hiding property, dramatized; no new construction.

**II.2 — the Night Lessons (the most structurally unique chapter).** The page is
split into **three simultaneous channels**: the central text (the lesson), **left
and right marginal glosses** (by Shem and Shaun, who **swap sides at the chapter's
midpoint**), and **footnotes** (by their sister Issy). The margins comment on,
mock, and subvert the center; the three voices do not agree.
→ **STRUCTURE (strong).** This is the deepest textual architecture in the book,
and it reinforces the load-bearing find: **one object, several independent
annotators who need not agree.** A single verifier is the center speaking alone;
the Wake's own page refuses that. It argues specifically for **threshold**
attestation (M-of-N) over unanimity, because the annotators are designed to
disagree — truth is the agreement of *enough* of them, not all.

**II.3 — the tavern (the Norwegian Captain; the radio).** HCE's fall is retold yet
again, now broadcast through a **radio and television** in the pub — the story
laundered through a medium, mutating as it passes.
→ *RESONANCE.* Cover-traffic / retelling as noise; this is `account-cooker`
territory (a different repo), not ours.

**II.4 — Mamalujo watch Tristan and Isolde.** The Four Old Men, now as **four
senile observers**, spy on the young lovers and offer "four intertwining
commentaries... always repeating themselves," each tied to a **province and a
compass direction** (Matthew/Ulster/North, Mark/Munster/South, Luke/Leinster/East,
John/Connaught/West).
→ **STRUCTURE (strong, buildable).** The Four again, now explicitly as **four
independent observers positioned at four corners**, each seeing the same event
from a different side. This is a distributed-observer set: no single vantage is
complete, and the record is the composite. Directly the threshold-verifier design.

---

## Book III — the return / decline (chapters 13–16)

**III.1–III.3 — Shaun's four watches.** Shaun, carrying the letter, is questioned
and **floats backward down the Liffey in a barrel** — the deliverer moving in
reverse, the message in transit and degrading.
→ *RESONANCE.* Backward motion along the river = the tracer's backward walk;
already the adversary we implement.

**III.4 — the inquisition of Yawn.** The **Four Old Men interrogate Yawn** (a form
of Shaun) lying on a hill, digging for the truth of HCE. They question from four
sides; voices speak *through* the sleeping figure; the truth they extract is
partial, contradictory, and never final.
→ **STRUCTURE (strong, buildable).** The Four as **inquisitors/verifiers** who
extract an attestation that no single one of them could produce or vouch for
alone. The clearest statement in the book that verification is a **quorum**, not a
witness.

---

## Book IV — the ricorso / dawn (chapter 17)

**IV.1 — the dawn, and ALP's final monologue.** Day breaks; the cycle turns. Anna
Livia, the river, speaks her final monologue as she flows to the sea to be reborn
as rain, and the book's last words — "A way a lone a last a loved a long the" —
break off and **flow back into the first word, `riverrun`.** The end is the
beginning.
→ **STRUCTURE (implemented).** The ricorso: the set reborn each cycle
(`cycle_secret`, `cycle_leaf`, `migration_nullifier`, `check_migration`). The
river returning as rain is the funding cycle with no origin. Both already in code.

---

## The load-bearing find: the Four → threshold verifiers

Across the whole book, one structure recurs at every level and is unmistakably a
**verification** structure: the **Four**. They are judges (I.4), observers from
four sides (II.4), and inquisitors (III.4). They are senile and **contradict each
other**; the Wake never lets a single one of them be authoritative. Truth, when it
appears at all, is what enough of the Four agree on. The II.2 page enacts the same
thing typographically — a center flanked by independent, disagreeing margins.

riverrun's deployed program had exactly the weakness the Four are the answer to.
`execute` trusted **one** named verifier's signature, and a dishonest verifier
could attest to a proof that does not exist. **This is now built.** The single
verifier was replaced with **M-of-N threshold attestation**: the pool names a
committee of N verifier keys and a threshold M, and `execute` requires Ed25519
signatures from at least M **distinct** committee members over the same tuple,
none authoritative alone. A false attestation now requires **M colluding
verifiers**, not one. It is covered by five on-chain tests (a 2-of-3 quorum
settles; one vote is below threshold; a member signing twice counts once; an
outsider's signature does not count; more than a quorum settles), and the
program's `verify_quorum` carries the III.4 epigraph "Impassable tissue of
improbable liyers."

This is the one insight from studying the whole book that made it from the page
into the on-chain program — grounded in the book's most recurrent structure,
buildable, and a fix to a gap the system admitted.

Everything else above is either already implemented or honestly marked as
resonance. The Four are the one that crossed from reading into code.
