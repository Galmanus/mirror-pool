# riverrun ID, situated in the anonymity literature

_A study of where riverrun ID sits in the science of anonymity — what it is in the
field's own vocabulary, one claim the literature makes stronger than we did, one
weakness the literature exposes that we had not stated, and the frontier that follows.
Every external claim is cited; where riverrun is behind the state of the art, the
citation says so._

## 1. What riverrun ID is, in the field's vocabulary

riverrun ID is not one primitive. It sits at the intersection of three separate
research lineages, and naming them precisely is the first useful thing a study can do.

1. **Hash-based, quantum-safe anonymous credentials.** A single secret, a public
   commitment, and per-context nullifiers derived by hashing. This is exactly the
   construction Kazmi & Minwalla call the *first secret-free and quantum-safe anonymous
   credential* — a Merkle tree of commitments plus a quantum-safe zero-knowledge
   argument of membership, security resting on a hash rather than a signature or a
   trusted issuer secret (Bank of Canada SWP 2023-50). The same shape appears, hash for
   hash, in the 2026 line of *issuer-untraceable* credentials: commit `C = H(s‖r)`, and
   at presentation derive a scoped nullifier `N = H(s‖ctx)` in zero knowledge, "adding
   zero new cryptographic assumptions" (lukasjhan, 2026). riverrun ID's `shape` and
   `fit` are precisely this.

2. **Accountable / conditional anonymity.** Anonymity that can be revoked or that
   self-reveals under a well-defined condition. Lysyanskaya's survey frames the whole
   agenda — *"there is no contradiction between anonymity and accountability"* — and
   catalogues the tools: conditional anonymity (double-spending e-cash: de-anonymize on
   a defined misbehavior), revocable anonymity (group signatures with an opener),
   controlled linkability, and privacy-preserving blueprints (NIST STPPA4, 2022).
   riverrun ID's `fit` (act once), `rln` (act N+1 times → unmask), and `link` (reveal
   two identities are one, on your terms) are the non-custodial members of this family.

3. **The measurement of anonymity itself.** Serjantov & Danezis (PET 2002) showed that
   set *size* is the wrong number; the honest quantity is the *entropy* of the
   adversary's belief — the effective anonymity-set size. riverrun's `effective-k` ruler
   is a direct implementation, and the only one of the three lineages riverrun did not
   inherit but had to build for its own use.

The one-sentence situation: **riverrun ID is a secret-free, quantum-safe anonymous
credential system in which one secret is the credential, every capability is a
domain-separated hash relation, and the quality of the anonymity set is itself
measured.**

## 2. The seven powers, mapped to their formal primitive

| power | formal primitive | strongest published form | riverrun's variant / gap |
|---|---|---|---|
| **shape** | scope-exclusive pseudonym | BBS per-verifier pseudonyms (IETF `draft-irtf-cfrg-bbs-per-verifier-linkability`); hash nullifier creds (lukasjhan 2026) | hash-based, so quantum-safe unlinkable — see §3 |
| **fit** | one-show / double-spend tag | conditional anonymity, e-cash (Lysyanskaya 2022) | per-context nullifier; on-chain registry enforces once |
| **turn** | cross-epoch linkability the holder controls | controlled linkability in group sigs w/ privacy-friendly openings (ARES 2019) | proven in ZK over the STARK |
| **link** | member-side controlled (un)linking | group sigs w/ privacy-friendly openings — *"make two signatures linkable or unlinkable in a controlled way,"* making full openings irrelevant (ARES 2019) | hash relation; no opener at all |
| **grant** | delegatable anonymous credential | DAC from equivalence-class sigs, with bounded levels + unshowable attributes (ePrint 2022/680) | single-level scoped grant — **weaker than DAC**; see §5 |
| **rln** | rate-limited / d-strikes-out revocation | RLN (Logos); BLAC — revoke repeat offenders *without a TTP*, d-strikes-out (CCS) | Shamir self-reveal; **no TTP**, which is the strong position |
| **credential** | anonymous credential w/ selective disclosure | BBS+ selective disclosure + privacy-preserving revocation + device binding (ePrint 2025/824) | hash attribute; **no revocation** yet — see §5 |

Two things stand out from the table. First, every power has a named, studied home —
riverrun ID invents no new primitive, which is the honest claim we already make.
Second, riverrun's versions are consistently the **non-custodial, hash-based** members
of each family: no opener for `link`, no TTP for `rln`, no issuer secret for
`credential`. That is a real design signature, not an accident.

## 3. The claim the literature makes *stronger* than we did

We have positioned riverrun ID as "Solana's missing Semaphore, post-quantum." The
anonymity-credential literature lets us say something sharper and more defensible.

The pseudonym schemes actually being standardized and deployed — BBS per-verifier
pseudonyms — are unlinkable only **computationally**, under the discrete-log
assumption. The field states the consequence plainly:

> "The unlinkability property relies on the discrete logarithm assumption. That is,
> adding such pseudonyms reduces perfect privacy of BBS-based ZKPs to *computational*
> privacy, which can be **retroactively broken when efficient quantum computers become
> available**. Thus, the simple construction should only be used when *everlasting
> privacy* is not required." — *A Brief Note on Cryptographic Pseudonyms*, arXiv
> 2510.05419 (Oct 2025)

This is the harvest-now-decrypt-later argument (see the Mosca inequality in the README
and whitepaper §2.1) arriving from *inside* the anonymous-credential world, not from
blockchain. The mainstream anonymous-identity pseudonym is HNDL-breakable; the field
knows it, and calls the fix *everlasting privacy* — pseudonyms whose unlinkability a
quantum adversary cannot retroactively undo. Those constructions "exist as well, but
incur higher costs."

**riverrun ID's `shape`/`fit` are on the everlasting side by construction:** they are
hashes, with no discrete-log to break. So the precise, literature-grounded claim is not
merely "post-quantum" — it is:

> riverrun ID provides **everlasting per-context unlinkability**: the link between a
> user's identities in two contexts cannot be recovered even by a future quantum
> adversary holding today's transcript — a property the deployed BBS-pseudonym standard
> does *not* have, and which its own literature flags as the open requirement.

That is a stronger, defensible statement than "a post-quantum Semaphore," and it is the
one to lead with.

## 4. The weakness the literature exposes — and we had not stated

This is the more important half of the study, because it is a limit of riverrun's own
ruler, aimed at riverrun's own core value.

The effective-k metric is single-shot: it scores the anonymity of *one* action. Danezis
— co-author of the very metric riverrun implements — later warned that this is exactly
where entropy metrics are weakest:

> "A simple composition theorem was also provided to combine primitive anonymity
> building blocks — *as long as all actors or actions were distinct. This proves to be a
> very serious limitation.* … it is imperative for a measure to provide good intuitions
> about the security of **repeated uses** of the channel. The entropy measures are very
> poor at this." — Danezis, *Measuring anonymity: a few thoughts and a differentially
> private bound*

Now read that against riverrun ID's whole point. Its value is a *persistent* identity
used *repeatedly*: `shape` across many contexts, `turn` across many cycles, `fit`
action after action. Those uses are correlated by construction — they descend from one
secret — which is exactly the "actions not distinct / repeated use" case where
single-shot effective-k **systematically understates the leak.** A user can pass the
ruler's per-action check every time and still be de-anonymized by the *join* of their
uses across contexts, a leak the current metric does not see.

This is not a bug in the ruler; it is the honest boundary of the metric the ruler
implements, and it lands squarely on riverrun ID rather than on the pool. Stating it is
the mature move. The field's own proposed answer is a **differential-privacy-style bound
over repeated use** (Danezis, same note) — a per-identity privacy budget that composes
across a user's actions, rather than an entropy computed fresh each time. That is the
metric riverrun ID actually needs, and it connects directly to the "LWE-hard cover /
provable-privacy" roadmap item already in the README: measured → *provable* over
repeated use.

## 5. The frontier — what the study says to build next

Ordered by how cleanly each fits riverrun's hash-only, non-custodial grain.

- **A repeated-use privacy bound for the ruler (the most important).** Replace, or
  augment, single-shot effective-k with a differential-privacy budget per identity that
  composes across contexts and cycles, so the ruler measures the leak of a *persistent*
  identity, not just a single act. This is the honest metric for what riverrun ID is.
  It is a paper-track result before it is code.

- **Privacy-preserving revocation (a real missing power).** riverrun ID today cannot
  revoke a credential. The hash-friendly mechanism already exists: the authority signs
  the *gaps* between adjacent revoked IDs, and the holder proves "my ID lies in a gap"
  in zero knowledge — constant-size, revealing neither the ID nor which gap (lukasjhan
  2026, extending longfellow). This is a clean candidate for an eighth power and needs
  no new assumption.

- **Multi-level bounded delegation.** riverrun's `grant` is single-level. Delegatable
  anonymous credentials give bounded delegation depth and per-level unshowable
  attributes (ePrint 2022/680) — the richer version `grant` should grow toward.

- **Issuer-hiding credentials.** Hide *which* issuer attested an attribute, not just the
  attribute holder. The first plausibly quantum-safe construction is lattice-based
  (ACM 2026); a hash-based analogue is open, and would fit riverrun's `credential`.

## 6. Honest placement against the post-quantum frontier

The competitive PQ anonymous-credential frontier is **lattice-based**: traceable
anonymous credentials from module lattices, ~54–79 KB per credential proof (IACR CiC
2/4, Jan 2026; ePrint 2024/131). Hash-based PQ accountable anonymity also exists —
SPHINCS+ group signatures scaling to 2^60 users with constant-size signatures (DGSP,
ePrint 2025/760). riverrun sits on the **hash / transparent** branch: it trades proof
size (kilobytes, via the STARK) for no structured-lattice assumption and no trusted
setup. That is the same trade the whitepaper makes for the pool, applied to identity —
conservative assumptions and transparency, paid for in bytes.

The honest one-line placement:

> riverrun ID is the **secret-free, hash-based, everlasting-unlinkable** point in the
> anonymous-credential design space — weaker than lattice schemes on proof size, unique
> in pairing everlasting per-context unlinkability with a ruler that measures the
> anonymity set's real quality — whose open problem is a repeated-use privacy bound, not
> a new primitive.

## References

- A. Serjantov, G. Danezis. *Towards an Information Theoretic Metric for Anonymity.*
  PET 2002. <https://bib.mixnetworks.org/pdf/serjantov2002towards.pdf>
- G. Danezis. *Measuring anonymity: a few thoughts and a differentially private bound.*
  <http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/Danezis-MeasuringThoughts.pdf>
- R. A. Kazmi, C. Minwalla. *Anonymous Credentials: Secret-Free and Quantum-Safe.*
  Bank of Canada SWP 2023-50.
  <https://www.banqueducanada.ca/wp-content/uploads/2023/09/swp2023-50.pdf>
- *A Brief Note on Cryptographic Pseudonyms for Anonymous Credentials.* arXiv 2510.05419
  (2025). <https://arxiv.org/html/2510.05419v1>
- lukasjhan. *Anonymous credentials the issuer can't trace — no format change, no
  trusted setup.* (2026)
  <https://blog.lukasjhan.com/anonymous-credentials-the-issuer-can-t-trace-no-format-change-no-trusted-setup>
- A. Lysyanskaya. *Anonymous Credentials* (50-year agenda). NIST STPPA4, 2022.
  <https://csrc.nist.gov/csrc/media/Presentations/2022/stppa4-anonym-cred/images-media/20221121-stppa4-anna-lysyanskaya--anonymous-credentials.pdf>
- IETF CFRG. *BBS per Verifier Linkability.*
  <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability>
- P. Tsang, M. H. Au, A. Kapadia, S. Smith. *BLAC: Revoking Repeatedly Misbehaving
  Anonymous Users without Relying on TTPs.* ACM CCS.
  <https://dl.acm.org/doi/10.1145/1880022.1880033>
- *Practical Group-Signatures with Privacy-Friendly Openings.* ARES 2019.
  <https://dl.acm.org/doi/10.1145/3339252.3339256>
- *Practical Delegatable Anonymous Credentials From Equivalence Class Signatures.*
  ePrint 2022/680. <https://eprint.iacr.org/2022/680.pdf>
- Rate-Limiting Nullifier (RLN). Logos Research. <https://research.logos.co/rln>
- M. Chathurangi et al. *Post-Quantum Traceable Anonymous Credentials from Lattices.*
  IACR CiC 2/4 (2026). <https://cic.iacr.org/p/2/4/12>
- M. Fadavi. *DGSP: Fully Dynamic Group Signatures using SPHINCS+.* ePrint 2025/760.
  <https://eprint.iacr.org/2025/760>
- *A Specification of an Anonymous Credential System Using BBS+ … Privacy-Preserving
  Revocation and Device Binding.* ePrint 2025/824. <https://eprint.iacr.org/2025/824.pdf>
