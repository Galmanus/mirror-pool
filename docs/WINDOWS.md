# Windows support: what actually runs natively, verified

**The measurement tooling runs natively on Windows.** Checked directly, not
assumed: `riverrun-core`, `riverrun-eval`, `riverrun-sdk`, and the `riverrun`
CLI (`riverrun-trace`) all cross-compile cleanly to `x86_64-pc-windows-gnu`,
producing a real, valid `riverrun.exe` (`file` reports `PE32+ executable
(console) x86-64, for MS Windows`). Reproduce:

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu -p riverrun-trace --features onchain --bin riverrun
cargo build --target x86_64-pc-windows-gnu -p riverrun-eval -p riverrun-sdk
```

This means `riverrun preflight` / `audit` / `trace` / `exhibit` (the ruler),
and the adversarial evaluation harness (`riverrun-eval`), work on a Windows
machine with no WSL, no Docker, no Linux VM. That was checked with a real
cross-compiled binary in this pass, not claimed from reading the code.

## What was found and fixed doing this check

`crates/riverrun-trace/src/cli.rs`'s session file (`~/.riverrun/session`,
holding a raw hex-encoded secret) already correctly gated its Unix
`chmod 0600` behind `#[cfg(unix)]`, so it was never a compile blocker. It was
a real gap on Windows specifically: no equivalent restriction existed there,
so the secret would be saved with whatever ACL the parent directory inherits,
not locked to the current user the way Unix's 0600 does. Fixed with a
`#[cfg(windows)]` best-effort `icacls` call (ships with every Windows install,
no new dependency) that strips inherited ACEs and grants Full Control to
`$USERNAME` alone. Failure there (e.g. a non-standard Windows install missing
`icacls`) is not fatal; the session still saves, just without the hardening.

## What does not run natively on Windows, named honestly

- **The demo scripts** (`demo.sh`, `scripts/demo.sh`, `scripts/demo_id.sh`) are
  bash; they need WSL or Git Bash. The underlying binaries they drive
  (`riverrun`, `riverrun-eval`) do not need that, only the scripts do.
- **On-chain program builds** (`cargo build-sbf` for `programs/mirror-pool`,
  `programs/stark-verifier`, `programs/riverrun-m31-verifier`) and Anchor's
  own CLI are not verified here to work on native Windows, and this is a
  known, ecosystem-wide constraint, not something specific to this repo:
  Solana's own toolchain documentation and community convention point Windows
  users at WSL for program development. Not attempted or claimed fixed in
  this pass; a real, separate, much larger undertaking (patching Solana's own
  SBF toolchain) that this repo does not take on.
