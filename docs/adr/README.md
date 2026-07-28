# Architecture Decision Records

This directory holds ADRs for riverrun: short, numbered records of decisions
that were genuinely debatable, where the reasoning matters as much as the
outcome. Format follows the standard lightweight ADR convention (Michael
Nygard, 2011): one file per decision, immutable once accepted (a changed mind
gets a new ADR that supersedes the old one, not an edit).

Not every change gets one. An ADR is for a decision with real alternatives
that were seriously considered, not a log of what was built. If you're
writing "we implemented X," that belongs in a commit message or a module doc,
not here.

## Template

```markdown
# ADR-NNNN: Title

**Status:** proposed | accepted | superseded by ADR-MMMM
**Date:** YYYY-MM-DD

## Context
What problem forced a decision. What was actually observed/measured, not
assumed.

## Decision
What was chosen, stated plainly.

## Alternatives considered
Each real alternative, and why it was not chosen. "We didn't think of X" is
a legitimate gap to name if true.

## Consequences
What this makes easier, what it makes harder, what it leaves unresolved.
Named honestly, including for the chosen option.
```

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-vendor-patch-over-fork-or-wait.md) | Vendor-patch third-party crates for SBF toolchain gaps, rather than fork or wait | accepted |
| [0002](0002-compose-proofs-via-shared-public-value.md) | Compose the M31 relation from two proofs via a shared public value, not one monolithic AIR | accepted |
| [0003](0003-tuned-vs-production-proof-parameters.md) | Expose explicit `_tuned` variants for reduced-security measurement, never silently weaken the production path | accepted |
