# Honest answers to the hardest questions

We would rather name the sharp edges of this submission than have a reviewer find
them. Here are the questions a technical panel should ask, and the honest answers.

## "The Groth16 submissions verify their proof on-chain with no committee. You use a committee. Isn't that a weaker trust model?"

Yes, on that one axis, today. A curve-based submission verifies its membership proof
on-chain trustlessly; riverrun's live settlement is attested by an M-of-N committee,
because the transparent proof is larger than Solana's per-transaction compute budget.
That is the single axis where a curve-based submission still leads, and it is
riverrun's named next milestone: a Circle STARK over the Mersenne-31 field, verified
on-chain in one transaction, which we have proven end to end in the Solana VM and
whose remaining work (the in-circuit Poseidon2 Merkle arithmetization) is specified in
`docs/M31_CIRCLE_STARK.md`.

Two things keep this honest rather than fatal. First, even on the committee path,
riverrun settles full rounds and an 18-action batch live on devnet, with the floor and
anti-replay enforced on-chain. Second, the trade the curve submissions make to get
trustless on-chain verification is exactly the one riverrun refuses: their
unlinkability is broken retroactively by a quantum computer, and it rests on a
trusted-setup ceremony whose leaked secret forges proofs. On a permanent ledger, that
is a privacy guarantee with an expiry date and a secret you must trust. riverrun's has
neither. We are one on-chain-verification milestone from leading on every axis; they
cannot become post-quantum or ceremony-free without abandoning their proof system.

## "Is the 18-action batch real, or a benchmark?"

Real, on devnet, in one atomic transaction:
[`3SageKBif…`](https://explorer.solana.com/tx/3SageKBifChN4t1iBnUX13riYDF1zN9UmGqp8cnfi4Pf3tzJJEnsWpiHVG9BJhdVRS4f9QvYTh5s6QAkTgSKQfCQ?cluster=devnet).
18 recipients paid, one relayer signature, one committee attestation, no member key.
18 fits and 19 overflows Solana's 1232-byte transaction limit; that is past the 17 a
leading curve submission fits. Reproduce it with
`cargo run --manifest-path programs/mirror-pool/Cargo.toml --example batch_alt_devnet 18`.

## "Your effective-k of 6.5 is from mainnet, but your pool runs on devnet. Are you mixing claims?"

They are deliberately separate, and labeled. The **ruler** runs on live mainnet pools
(that is where the advertised-30, effective-6.5 measurement comes from, and it scores
any pool, including the other submissions). The **pool** and the batch run on devnet.
On devnet the members are synthetically funded, so we do not report a devnet
effective-k as if it were real anonymity; the value there is the mechanism, the floor,
and the settlement, all checkable. The one number we stand behind as a measurement is
the mainnet one.

## "Why not just ship the M31 verifier now and win outright?"

Because doing it right is days of careful cryptography (the in-circuit AIR), and the
compact M31 verifier that hits ~160k CU is third-party, unlicensed code we will not
vendor into this submission. Shipping a half-finished in-circuit proof would be broken
mathematics presented as a feature, which is the opposite of what this project stands
for. We would rather ship what is real and name what is next than fake the finish.

## "PR#1's confidential-value layer and Groth16 membership proof look more complete. Why should a panel weigh riverrun over it?"

We read it closely rather than assert against it. It is genuinely strong
engineering: a live devnet program, a real ceremony toolkit, a rigorously
measured effective-k table with an honestly corrected methodology, and an
on-chain Groth16 membership proof that settles with no participant signature,
the exact axis named above where riverrun still trails. Two facts from their
own repository matter for a panel weighing trust, not capability:

1. **A self-disclosed, currently unfixed fund-draining bug.** Their own test,
   `settle_zk_escrow_is_a_pool_wide_pot_any_leaf_can_spend`
   (`programs/mirror-pool/tests/integration.rs:1335` on
   `marcelofeitoza/mirror-pool@feat/mirror-pool-v1`), proves that a
   participant who deposits nothing (a fee-only crowd commit) can drain a
   *different* depositor's real escrowed SOL, because no on-chain check ties a
   settled amount to the leaf that funded it. They document it honestly
   ("a v1 pool must not hold value it cannot afford to lose") rather than hide
   it, which is to their credit, but it is live on their deployed devnet
   program and unfixed in that branch.
2. **The ceremony's deployed keys are admittedly insecure.** `docs/CEREMONY.md`
   in that repo states plainly that the verifying keys currently committed and
   deployed come from an "insecure dev setup," not a real multi-party run. The
   ceremony *tooling* is real and tested; the *keys actually protecting live
   value* are not, today.

riverrun cannot have the first bug by construction, not by a fix applied in
response to finding it: the pool holds no shared escrow at all. `execute_batch`
pays each round's recipients directly from the relayer's transaction; there is
no pot for one leaf's proof to drain another leaf's deposit from (verify it
yourself: `grep -rn escrow programs/mirror-pool/src/` on this repo returns
nothing). riverrun cannot have the second either, because it has no ceremony
and no ceremony keys to be insecure, by the same no-trusted-setup argument
already made above. Neither is a race we are ahead in by luck; both are
structural consequences of being hash-based and committee-attested rather than
holding value against a proof of a leaf someone else may have funded.

This does not close riverrun's own named gap (the single-transaction,
no-committee on-chain proof, still the M31 verifier's job, still not shipped).
It is not offered as a substitute for that. It is offered as the honest answer
to "which of these is safer to trust with real value today," which is a
different question than "which is cryptographically further along," and on
that question the answer is concrete, cited, and checkable in both
repositories, not asserted.

## "What stops a relayer from stealing or redirecting a payout in the batch?"

The committee's attestation is over a digest that binds the pool, root, round, the
shared action, and every nullifier and recipient. A relayer that adds, drops, or
redirects any of them produces a different digest, which no committee member signed, so
the quorum check fails and nothing settles. This is covered by an on-chain test
(`a_relayer_cannot_redirect_a_batch_payout`).
