# windows-no-bullshit-audit

> Deep Windows 11 health, performance, security and hygiene audit. Evidence first. No cargo-cult fixes. Token-budgeted.

Version 0.2.0. Agent Skills package: `SKILL.md`, PowerShell collectors, focused
diagnostic references, state/report templates and quality gates.

## Scope

- Windows 11 client editions, x64 and ARM64. Windows PowerShell 5.1.
- Two execution styles:
  - **local/agentic**, only after the real Windows target is attested and confirmed;
  - **delegated**, when the runtime is a sandbox, helper VM or cloud host.
- A mandatory Target Machine Attestation gate stops the skill auditing its own
  sandbox instead of the operator's PC.
- Internet research is part of the method for current Microsoft/OEM/vendor facts.

## Elevation

`scripts/attest-target.ps1` deliberately runs **without** administrator rights,
because proving "this is the wrong machine" has to work everywhere.

Every other collector **requires an elevated session** and refuses to run
without one. Un-elevated collection returns partial evidence that looks
complete, which is worse than no evidence.

## Artifact tiers

The collectors deliberately produce two very different things:

| Tier | Files | Size | Who reads it |
|---|---|---|---|
| Digest | `TRIAGE.md`, `TRIAGE.json`, `DEEP-TRIAGE.md`, `AUTORUNS-TRIAGE.md` | ~10-30 KB | the agent, and the operator in delegated mode |
| Raw evidence | numbered folders, EVTX, CSV, logs | tens of MB | queried on demand, never read whole |

Counting, grouping, signer resolution and thresholding happen in PowerShell, not
in the model. `TRIAGE.json` is capped at 60 KB and reports its own trimming, so
"absent from the digest" never silently means "absent from the machine".

## Scripts

| Script | Purpose | Elevated | Typical time |
|---|---|---|---|
| `attest-target.ps1` | identify the executing machine | no | instant |
| `collect-baseline.ps1` | read-only evidence + digest | yes | 1-3 min (`-Depth Fast`) |
| `collect-deep.ps1` | DISM/SFC/CHKDSK/energy, pollable | yes | 20-60 min |
| `collect-performance.ps1` | CIM sampling + short WPR trace | yes | 1-5 min |
| `collect-autoruns.ps1` | Autoruns + reduced review list | yes | 1-2 min |
| `verify-after-repair.ps1` | scoped post-repair verification | yes | seconds to 25 min by scope |
| `assemble-report.ps1` | findings -> `REPORT.md` + state | no | instant |

Useful switches: `-Redact` (pseudonymize identity in digests before pasting into
a hosted chat), `-CopyToClipboard`, `-Depth Full`, `-Only <scope>`.

## Install / import

This directory is the canonical provider-neutral Agent Skill. Install it through
the surrounding plugin repository, or copy this directory into a runtime that
supports Agent Skills. The directory name must match `name` in `SKILL.md`.

## Safety model

The bundled collectors collect; they do not repair. Persistent Windows changes,
cleanup, tool installation and reboot all go through the approval policy in
`references/remediation-policy.md`.

## Package QA

`tests/validate-package.py` checks naming, frontmatter, resource links, orphaned
references and scripts, JSON validity and the SKILL.md size budget. The Windows
CI job parses every script, runs the fast collector for real and enforces the
digest byte cap. `tests/` is not shipped in release artifacts.
