# Reporting Contract

## Files

A completed audit produces:

- `REPORT.md` — human-readable findings and scoreboard;
- `audit-state.json` — machine-readable state/findings/approvals;
- `REMEDIATION-LOG.md` — exact performed changes and verification;
- `RESUME.md` — only while a reboot/handoff is pending.

## Scoreboard

Use:

- ✅ Healthy / Verified
- 🟡 Observe / Intentional / Validation pending
- 🟠 Action recommended
- 🔴 Critical
- ⚪ Historical / Noise / Informational

Show initial and final counts when available.

## Finding format

For each meaningful finding include:

- ID and domain;
- state/severity;
- confidence;
- local evidence;
- relevant lifecycle correlation;
- external/current evidence with citations when used;
- conclusion/root cause if justified;
- action taken/recommended/deferred;
- verification result;
- remaining uncertainty.

## Remediation log

Every mutation gets an entry:

- timestamp;
- finding ID;
- before state;
- exact action/command;
- approval reference;
- reason;
- result/exit code;
- after-state verification;
- rollback path if applicable.

## Final verdict

Summarize:

1. overall health;
2. verified strengths;
3. unresolved critical/action items;
4. intentional deviations;
5. historical/noise items that should not trigger cargo-cult fixes;
6. performance headroom;
7. deferred cleanup choices;
8. any `UNKNOWN` items and their next discriminating test.
