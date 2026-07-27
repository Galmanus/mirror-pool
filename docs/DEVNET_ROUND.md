# A full multi-member round, live on devnet

This is not a proof of concept in a test harness. It is a complete `k = 8` round
run against the deployed program on Solana devnet, with every signature below
checkable in an explorer (append `?cluster=devnet`). Eight distinct members each
committed an intent, signing only their own commit. A single relayer then settled
all eight actions, signing every one of them alone, with eight distinct
nullifiers. The pool's anonymity floor (`k_min = 8`) was enforced by the program:
an execution attempted before the crowd was complete was refused on-chain, and a
reused nullifier was rejected on-chain.

Reproduce it:

```
cargo run --manifest-path programs/mirror-pool/Cargo.toml --example devnet_round 8
```

## What an observer of the permanent record sees

Eight members joined and eight identical actions settled, but nothing on-chain
links any action to the member behind it: the members signed only commits, and
the relayer signed only executions. That gap is the behavioral cloak.

- **program:** `BFy2ehVxpBrtwMCWwufpfbbsoWtZVYVaZBzDE2eAG7az`
- **pool PDA:** `AmNgpCNp26bcFhKYJWeVRsP13QTMZYxzu5oPjboYkzZ9`
- **relayer (settled all 8, alone):** `rUogFRyKzPnwMbJj44HL3w5AzKKJcjE2yzwS1a77VtP`

## The crowd: 8 commits, 8 distinct member keys

Each transaction below was signed by a different member. The member key appears
here, joining the crowd, and nowhere in the executions.

| # | commit signature |
|---|---|
| 1 | `3pUjfyNo4CUnrXivELhUEXELDJq1xpcJyahYPwBtkKXAikr7xuvSy4kF2mCCLjiRASDDxXzfCcNZBUoPx7erZJwx` |
| 2 | `56aSGFALw6LXi76LL6BmTtjgrf6K5YitnyCUeWne4XosfbZ27JB4JWtLwwwpQGVSiDQA6BXWWcLKXxJviaiT3LJv` |
| 3 | `4T1aZtndwhxufJG3Lv3bk7KAHbV7URhJGm4BLB1JEAVGUuNMm9GW1x2YymswtPeLHVGf8i4qZbMjEogpQjhxPfkQ` |
| 4 | `5rviPQKLPRvR4xpnPqkkVA43LjtrC2w8qeCWw2UV28vhYRXfT4cWKUfXyq7sifKRNXTJ1J6D3nvtv1mKVQm4ceJP` |
| 5 | `2RQ7j3DxExZmVaXv85DwVS3KxnmTgm376hRxyzCYk68R9P99W3pCb4i5UGSmSJk4y48tS9xdJDR9ueSD7xHUwbQp` |
| 6 | `2Y5ycx5WwTqxJNep4DR8f2z9UhXE8HyKXMtsG2pfubmbRTYQbBctFyaxu64WpkeGhdfSgW3kYZnoGcotnxpqVM22` |
| 7 | `61DCmTzVNn7b7qPym8p4AewxrM5EnvnTs3dWVc8dqjrF2gSdnMChXYz46bibdWacPQ5WiwjwDHNRQcqnaGsWxffi` |
| 8 | `4AZ7rEQaiTNNBNEL8JS8CF5KrxFoYy2bJrfEDMpNRDtGABX3WaZJ4JH1pymVX3KbAmQyE5stkUpAztpKxd3Zc2ak` |

## The floor, enforced live

Before the crowd was complete (one member committed, `k_min = 8`), the relayer
attempted to settle. The program refused it:

```
execute @ 1 member   FAIL custom program error: 0x1777
```

`0x1777` is `6007`, Anchor error index 7, which is `AnonymitySetTooSmall`:
"the anonymity set is below the pool's floor: an execution here would not be
private." The floor that the effective-k and self-fill rulers argue for is not a
promise in a document; the program returns it.

## The settlement: 8 executions, the relayer alone, 8 distinct nullifiers

No member key signs any of these. Each spends a distinct nullifier, so each action
executes exactly once.

| # | execute signature |
|---|---|
| 1 | `4X5fQRpeY6B34sJU2vNsPbJXGWwXBSN3LZmsjjpwX2PfYcS9KdoGJix3SchauFLftJdocnjAcmeuFoRrwXtyiEui` |
| 2 | `3tyTRtAA8Qb1qZFyLUDxjrVYWVxV4PHQEYr4Gvi3HRkXKgpQZZdSxw7NzuVosLfLN7wivyWtiTMYtsGh2R5SEhu2` |
| 3 | `2NQj1oh43G6C2Re9hVwxC3oDuo6AXYeV4dzcymVCdBk4mriGFqGV3ubY9LaqDsCdANrdc28pU4GCFtmj7zE97HE8` |
| 4 | `3xvp2aSegi9jc5QesV2TCxuLUPsX9RShfPPaC7si2ofHS6fcrtL1XxQde35RDw3LB65q3nTpBH4MkoTRqVTXrc6p` |
| 5 | `3ixr1KppBivEX8zqQzU8y5HNAVV3Km4nYdtZRsWz5m5VpgaWzk7YZswchDLSPtmCFbL94qhnf6L82eQM1RiQhLmS` |
| 6 | `5ZJSPYCpx1QWUQbEAJGnE1gjmcrqQ8JppJq68B93Mf6TNM3GdivtMbn95zhcEaiGjwQidiaq65e5n133qtCQYH9K` |
| 7 | `Zruz2XXkDUpAGKKSgWn6ZwpYPbaXQ6o92qjAXKEoTFnGTnCyDi4umiLuvgKb813YLCfmJc5pH5pfset5s9QiPaV` |
| 8 | `3ZhMkHps2ACT85HNRKz5GYtDM4SELaH2yW7NEYue6ZZrwGe8WnTWUBgBxQUaCpUYcRw8KD6KE2XnV3tE2nZSVxCY` |

## Anti-replay, enforced live

Reusing a nullifier that was already spent:

```
execute (double-spend)   FAIL custom program error: 0x0
```

`0x0` is Anchor error index 0 on the per-nullifier PDA path: the nullifier account
already exists, so the second execution cannot be created. One action, one
execution, per member per round.

## Honest scope

This is the committee-attested settlement path (a committee of one here), the
same path the single-member `devnet_demo` exercises, run as a full round. The
post-quantum STARK membership proof is verified in the Solana VM (LiteSVM,
~160k CU) and is not yet the settlement path on a live cluster; bringing it there
is the next milestone. What is live here is the round structure, the floor, the
anti-replay, and the actor-action unlinkability, all on devnet, all checkable.

## A whole round in ONE transaction (execute_batch, live on devnet)

`execute_batch` settles multiple actions in a single transaction: one relayer
signature, one committee attestation over the whole batch, the vault pays every
recipient, no member key signs. An Address Lookup Table packs the accounts. The batch
digest binds every action, nullifier, and recipient, so a relayer can neither add,
drop, nor redirect one.

**7 actions in one transaction:**
[`2TqTQHMxC5CsTRicE8SaY5erjotvaNGs54Pv4NG4jc63PkJMknSfYAsUYqVxEKatH14MgSedwobnGVdVj99WBiq5`](https://explorer.solana.com/tx/2TqTQHMxC5CsTRicE8SaY5erjotvaNGs54Pv4NG4jc63PkJMknSfYAsUYqVxEKatH14MgSedwobnGVdVj99WBiq5?cluster=devnet)

Reproduce: `cargo run --manifest-path programs/mirror-pool/Cargo.toml --example batch_alt_devnet 7`

**Honest limit.** The committee's Ed25519 attestation is larger than a compact SNARK
proof, so it caps the count per transaction (7 here, the transaction size limit is
1232 bytes). A curve pool fits more because its proof is tiny. Raising riverrun's
count per transaction is exactly what the on-chain M31 STARK verifier is for: it
replaces the committee attestation with a single small proof. This is the one axis a
curve-based competitor still leads, and it is riverrun's named next milestone. Every
value settled here is a hash, so the batch is post-quantum.
