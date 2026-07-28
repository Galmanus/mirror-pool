#!/usr/bin/env bash
# The product, from the terminal: a person uses riverrun to become anonymous on Solana.
# A post-quantum boot sequence, a status panel, a plain-language menu, the step-by-step
# to disappear, and one secret becoming two unlinkable identities. Offline, no RPC, no
# hashes to paste.
set -euo pipefail
BIN="${RIVERRUN_BIN:-./target/debug/riverrun}"
export CLICOLOR_FORCE=1
rm -f "$HOME/.riverrun/session" 2>/dev/null || true

# A cold-open flourish: streams of hex churning like key material being derived, purely
# cinematic (no claim is made about what is computed here), before the real session
# starts. Two shades of green for depth, a bright row breaking the pattern.
boot() {
  local GREEN='\033[38;5;46m' DGREEN='\033[38;5;28m' BGREEN='\033[1;38;5;46m' RESET='\033[0m'
  # Fill the whole 80x24 recording terminal (23 rows, one left for the banner
  # line after), not a small block in the corner leaving the rest black.
  local rows=23
  clear 2>/dev/null || true
  for frame in $(seq 1 16); do
    for l in $(seq 1 $rows); do
      local shade=$DGREEN
      if (( l % 3 == 0 )); then shade=$GREEN; fi
      local hex=""
      for ((i=0;i<76;i++)); do hex+=$(printf '%x' $((RANDOM % 16))); done
      printf "${shade}%s${RESET}\n" "$hex"
    done
    sleep 0.05
    if (( frame < 16 )); then printf "\033[${rows}A"; fi
  done
  echo
  printf "${BGREEN}riverrun: post-quantum engine initialized${RESET}\n"
  sleep 0.7
  clear 2>/dev/null || true
}
boot

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
