# Pull Request

## What does this change?

<!-- Summarize the change, motivation, and related issue(s). Keep the diff focused. -->

## Type of change

- [ ] Bug fix
- [ ] Diagnostic / collector change
- [ ] New feature / enhancement
- [ ] Documentation
- [ ] Packaging / plugin metadata
- [ ] CI / repository tooling
- [ ] Refactoring (no intended behavior change)

## Audit contract checklist

Review the items affected by this PR; mark non-applicable items as such in the notes.

- [ ] Target attestation still happens before auditing or mutating a candidate machine
- [ ] Evidence remains the basis for findings; event IDs are not treated as diagnoses
- [ ] Bounded collection / digest guarantees are preserved
- [ ] Raw evidence is not made the default agent input
- [ ] Risky/non-reversible changes and reboots still require explicit operator approval
- [ ] `UNKNOWN` remains valid when evidence is insufficient
- [ ] Privacy/redaction documentation matches actual behavior
- [ ] Windows PowerShell 5.1 compatibility is preserved for the runtime payload
- [ ] The canonical Skill remains under `skills/windows-no-bullshit-audit/` with no provider-specific duplicate source

## Validation

- [ ] `python skills/windows-no-bullshit-audit/tests/validate-package.py`
- [ ] `python scripts/build-release.py`
- [ ] Relevant Windows PowerShell 5.1 runtime smoke test completed for PowerShell behavior changes
- [ ] User-facing docs/version metadata updated when required
- [ ] No secrets or unnecessary raw audit evidence are included in the PR

## Notes for the reviewer

<!-- Risky areas, intentionally deferred work, rejected alternatives, or validation limitations. -->
