#!/usr/bin/env bash
# The riverrun terminal, in one take: the post-quantum posture, the self-fill
# floor a whale leaves you, a plain-language answer, and one secret becoming two
# unlinkable identities. All offline, deterministic, no RPC. Rendered to the gif
# in the README.
set -euo pipefail
BIN="${RIVERRUN_BIN:-./target/debug/riverrun}"
export CLICOLOR_FORCE=1
rm -f "$HOME/.riverrun/session" 2>/dev/null || true

PS1_FAKE="\033[38;5;37m❯\033[0m"
pause() { sleep "${1:-1.1}" 2>/dev/null || true; }
run()   { printf "%b riverrun %s\n" "$PS1_FAKE" "$*"; pause 0.5; "$BIN" "$@"; echo; pause 1.6; }

clear 2>/dev/null || true
printf "\033[1;38;5;37mriverrun\033[0m  the anonymity layer for Solana. post-quantum.\n\n"
pause 1.1

# 1. the post-quantum posture: hash vs curve, and Mosca's inequality
run pq
pause 0.4

# 2. the floor a whale or Sybil leaves you: advertised k is a ceiling
run floor 30
pause 0.4

# 3. plain answers, because knowledge should be accessible
run explain effective-k
pause 0.4

# 4. one secret, a different unlinkable identity per context
SECRET=$("$BIN" id new 2>/dev/null | sed -n '2p' | tr -d ' ')
printf "%b riverrun id show <secret> dao-vote\n" "$PS1_FAKE"; pause 0.5
"$BIN" id show "$SECRET" dao-vote; echo; pause 1.2
printf "%b riverrun id show <secret> airdrop\n" "$PS1_FAKE"; pause 0.5
"$BIN" id show "$SECRET" airdrop; echo; pause 1.2
printf "\033[38;5;244m  same secret, two contexts, two identities nobody can link back to you.\033[0m\n\n"
pause 1.6

printf "\033[1;38;5;37mmeasured privacy, post-quantum, from the terminal.\033[0m  full paper: paper/riverrun.pdf\n\n"
pause 1.2
rm -f "$HOME/.riverrun/session" 2>/dev/null || true
