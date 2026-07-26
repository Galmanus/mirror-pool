#!/usr/bin/env bash
# The guided, panel-first experience of riverrun, for the README recording.
# A Tor-style status panel, a plain-language menu, and one secret becoming two
# unlinkable identities. Offline, no RPC, no hashes to paste.
set -euo pipefail
BIN="${RIVERRUN_BIN:-./target/debug/riverrun}"
export CLICOLOR_FORCE=1
rm -f "$HOME/.riverrun/session" 2>/dev/null || true

# Feed the interactive guide at a human pace, so the recording reads like a real session.
{
  sleep 2.2; printf '2\n'          # create an identity
  sleep 2.2; printf 'dao-vote\n'   # first context
  sleep 2.6; printf 'airdrop\n'    # second context, unlinkable
  sleep 2.8; printf '\n'           # finish adding contexts
  sleep 1.8; printf 'c\n'          # connect (panel shows protected)
  sleep 2.6; printf 'q\n'          # quit
} | "$BIN" guide

rm -f "$HOME/.riverrun/session" 2>/dev/null || true
