#!/usr/bin/env bash
# A short, scripted demo of riverrun ID from the terminal, for the README recording.
# One secret becomes a different, unlinkable identity per context, then the erosion
# ruler says when to rotate. Offline, deterministic, no RPC.
set -euo pipefail

BIN="${RIVERRUN_BIN:-./target/debug/riverrun}"
PS1_FAKE="\033[38;5;37m$\033[0m"   # a teal prompt
pause() { sleep "${1:-1.1}" 2>/dev/null || true; }
run()   { printf "%b riverrun %s\n" "$PS1_FAKE" "$*"; pause 0.5; "$BIN" "$@"; echo; pause 1.2; }

clear 2>/dev/null || true
printf "\033[1;38;5;37mriverrun ID\033[0m  one secret, a different unlinkable identity in every context\n\n"
pause 1.0

# 1. mint one secret
printf "%b riverrun id new\n" "$PS1_FAKE"; pause 0.5
SECRET=$("$BIN" id new | sed -n '2p' | tr -d ' ')
"$BIN" id new >/dev/null 2>&1 || true
printf "your riverrun ID secret (keep it safe, it is your whole identity):\n  %s\n\n" "$SECRET"
pause 1.4

# 2. your identity in one context
run id show "$SECRET" dao-vote

# 3. a different, UNLINKABLE identity in another context (same secret)
run id show "$SECRET" airdrop

printf "\033[38;5;244m  ^ same secret, two contexts, two identities nobody can link back to you.\033[0m\n\n"
pause 1.6

# 4. the erosion ruler: when to rotate
run id erosion

printf "\033[1;38;5;37mmeasured privacy, from the terminal.\033[0m  full paper: paper/riverrun.pdf\n\n"
pause 1.2
