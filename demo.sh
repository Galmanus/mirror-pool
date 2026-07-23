#!/usr/bin/env bash
# riverrun — everything this repo claims, in one command.
#
#   ./demo.sh          the offline stages (no network, ~1 min)
#   ./demo.sh --live   also runs the mainnet measurement (needs network, ~5 min)
#
# Every stage prints numbers, not adjectives. Where a number is a floor rather
# than a result, the stage says so.

set -euo pipefail
cd "$(dirname "$0")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; OFF=$'\033[0m'
stage() { printf '\n%s── %s %s%s\n\n' "$BOLD" "$1" "$(printf '─%.0s' $(seq 1 $((60 - ${#1}))))" "$OFF"; }
note()  { printf '%s%s%s\n' "$DIM" "$1" "$OFF"; }

LIVE=0
[[ "${1:-}" == "--live" ]] && LIVE=1

stage "1/6  the whole test suite"
note "34 host + 23 STARK + 7 pool-zk. The on-chain e2e needs the SBF toolchain and runs in stage 6."
suite() { # <label> <extra cargo args...>
  local label="$1"; shift
  local out; out=$(cargo test --quiet "$@" 2>/dev/null)
  local pass; pass=$(echo "$out" | grep -oE '\b[0-9]+ passed' | awk '{s+=$1} END {print s+0}')
  if echo "$out" | grep -q "FAILED"; then
    printf '  %-28s %s\n' "$label" "FAILED"; echo "$out" | grep -E "FAILED|panicked"; exit 1
  fi
  printf '  %-28s %s passed\n' "$label" "$pass"
}
suite "host (core/eval/trace)" --workspace
suite "STARK (membership+binding)" --manifest-path crates/riverrun-stark/Cargo.toml
suite "pool driven by the STARK"  --manifest-path crates/riverrun-pool-zk/Cargo.toml

stage "2/6  the mechanism — commit, execute unlinkably, settle"
note "Four members commit the same action and all execute it in one round."
note "Same action, distinct nullifiers, one root, and no way back to a committer."
cargo run --quiet --release --manifest-path crates/riverrun-pool-zk/Cargo.toml \
  --example behavior_pool

stage "2b/6  what one execution costs"
note "The last column is the one that decides deployability: a pairing-based"
note "prover needs a ceremony-produced key shipped to every client; this needs none."
cargo run --quiet --release --manifest-path crates/riverrun-stark/Cargo.toml --example bench

stage "3/6  adversary 1 — the behavioural channel"
note "A clustering attacker that fingerprints wallets by co-buy timing and position"
note "sizing, run against the same population with and without a synchronized round."
cargo run --quiet --release -p riverrun-eval

stage "4/6  adversary 2 — the funding graph, and the ruler"
note "Every pool reports 1/k. This is what k is worth once the adversary sorts the"
note "set by where the money came from. Same metric, applied to riverrun itself."
cargo run --quiet --release -p riverrun-trace --bin provenance-tracer

if [[ $LIVE -eq 1 ]]; then
  stage "5/6  the same ruler, against a live pool on Solana mainnet"
  note "Real depositors of a live Tornado-style SOL privacy pool. Aggregates only:"
  note "no depositor is named. Public RPC, so this takes a few minutes."
  cargo run --quiet --release --features onchain -p riverrun-trace --bin pool-provenance \
    -- 9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD 15
else
  stage "5/6  the live mainnet measurement  (skipped)"
  note "Re-run with ./demo.sh --live to measure a real pool over the network."
fi

stage "6/6  the on-chain program"
if command -v cargo-build-sbf >/dev/null 2>&1; then
  note "Builds to a deployable .so, then 10 e2e tests against the compiled program"
  note "in LiteSVM: attestation, nullifier anti-replay, stale round, anonymity floor."
  # the Anchor derives emit a wall of cfg warnings that drown the signal here
  if cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml >/tmp/riverrun-sbf.log 2>&1; then
    echo "built programs/mirror-pool/target/deploy/riverrun_program.so"
  else
    echo "SBF build failed — see /tmp/riverrun-sbf.log"; exit 1
  fi
  cargo test --quiet --manifest-path programs/mirror-pool/Cargo.toml --test e2e 2>/dev/null
else
  note "SBF toolchain not found — skipping. Install it and re-run to build the"
  note "program and exercise the on-chain lifecycle:"
  note "  cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml"
fi

printf '\n%sdone.%s  Honest limits are in the README under "Security status", and the\n' "$BOLD" "$OFF"
printf 'measurement method — including the arithmetic that was wrong first — is in\n'
printf 'docs/EFFECTIVE_K.md.\n\n'
