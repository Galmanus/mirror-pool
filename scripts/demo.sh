#!/usr/bin/env bash
# The product, from the terminal: a person uses riverrun to become anonymous on Solana.
# Status panel, a plain-language menu, the step-by-step to disappear, and one secret
# becoming two unlinkable identities. Offline, no RPC, no hashes to paste.
set -euo pipefail
BIN="${RIVERRUN_BIN:-./target/debug/riverrun}"
export CLICOLOR_FORCE=1
rm -f "$HOME/.riverrun/session" 2>/dev/null || true

# Feed the interactive guide at a human pace, so it reads like a real session.
{
  sleep 2.2; printf '1\n'          # become anonymous
  sleep 2.6; printf '\n'           # (skip pasting a wallet, this is a demo)
  sleep 3.4; printf '\n'           # (skip the verify wallet too)
  sleep 2.0; printf '3\n'          # create an identity
  sleep 2.2; printf 'dao-vote\n'   # first context
  sleep 2.6; printf 'airdrop\n'    # second context, unlinkable
  sleep 2.8; printf '\n'           # finish
  sleep 1.8; printf 'q\n'          # quit
} | "$BIN" guide

rm -f "$HOME/.riverrun/session" 2>/dev/null || true
