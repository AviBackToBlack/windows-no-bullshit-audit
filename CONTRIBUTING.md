# Contributing to Windows No-Bullshit Audit

Thanks for helping improve the project. This repository is intentionally small:
one canonical Agent Skill, a bounded Windows evidence collector, deterministic
standalone packaging, and thin OpenAI/Claude plugin metadata around the same
Skill source.

## Ground rules

- **Windows 11 client is the target.** Runtime collector changes must work on the
  supported Windows 11 editions and Windows PowerShell 5.1.
- **Attest first.** The Skill must prove which machine is being audited before
  treating evidence as target evidence. Helper/sandbox hosts are never silently
  accepted as the target.
- **Evidence before diagnosis.** Event IDs and heuristics are clues, not diagnoses.
  `UNKNOWN` is a valid result when evidence is insufficient.
- **Keep collection bounded.** Do not replace capped queries or token-bounded
  digests with convenient unbounded dumps. Raw evidence stays queryable on disk;
  it is not default agent context.
- **Keep mutation conservative.** Risky/non-reversible repairs and reboots require
  explicit operator approval. Collection is not an excuse to mutate the host.
- **One canonical Skill source.** Provider manifests may point at the Skill, but
  do not create separate OpenAI/Claude copies that can drift.
- **Avoid unnecessary dependencies.** Python packaging/validation tooling is
  standard-library-only today. New third-party dependencies need a clear reason.

## Repository layout

- `skills/windows-no-bullshit-audit/` — canonical Skill, scripts, references and tests
- `.codex-plugin/` and `.agents/plugins/` — OpenAI plugin/marketplace metadata
- `.claude-plugin/` — Claude plugin/marketplace metadata
- `scripts/build-release.py` — deterministic `.zip` / `.skill` release builder
- `.github/workflows/release.yml` — Windows runtime validation and release build

## Validation

Run the package invariants and deterministic builder on any platform with Python 3:

```text
python skills/windows-no-bullshit-audit/tests/validate-package.py
python scripts/build-release.py
```

For PowerShell behavior changes, also test on Windows with Windows PowerShell 5.1.
Target attestation does not require elevation:

```powershell
powershell -NoProfile -File .\skills\windows-no-bullshit-audit\scripts\attest-target.ps1 -Redact
```

The Fast collector requires an elevated session:

```powershell
powershell -NoProfile -File .\skills\windows-no-bullshit-audit\scripts\collect-baseline.ps1 `
  -OutputRoot "$env:TEMP\WindowsNoBullshitAudit-smoke" -Depth Fast -EventDays 3 -NoZip -Redact
```

CI performs the authoritative Windows PowerShell 5.1 parse/runtime smoke tests,
digest budget/overflow checks, report round-trip validation, manifest checks and
deterministic packaging.

## Pull requests

- Keep diffs focused; unrelated cleanup belongs in another PR.
- Add or update validation when changing a contract or regression-prone behavior.
- Update README/Skill docs and version metadata when user-visible behavior changes.
- Do not weaken a safety/privacy invariant merely to make a test or unusual machine pass.
- Explain intentionally deferred review findings rather than silently ignoring them.

## Reporting audit problems

Use the dedicated **Audit accuracy problem** issue form for false positives,
false negatives, unjustified recommendations, target-attestation mistakes, or
confidence/`UNKNOWN` problems. The most useful report includes a sanitized target
attestation, the disputed finding, and the smallest evidence set that proves the
problem.

**Never upload an entire raw evidence tree by default.** Audit output can contain
usernames, serials, paths, hostnames and event text. `-Redact` is a reduction aid,
not a promise that arbitrary event text contains no identifying values; in
particular, dotted-quad values are intentionally not blanket-redacted.

## Security issues

Do not open a public issue for a suspected vulnerability or a privacy leak that
would expose sensitive evidence. Follow [SECURITY.md](SECURITY.md).
