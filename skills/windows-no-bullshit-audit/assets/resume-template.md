# Resume Windows Audit

**Run ID:** <run-id>  
**Phase:** <phase>  
**Checkpoint time:** <timestamp>  

## Why execution paused

<reason, e.g. reboot required>

## Completed

<completed phases/actions>

## Pending approvals

<pending approvals>

## After resume, do these first

1. Read `audit-state.json` and `REMEDIATION-LOG.md`.
2. Confirm the expected post-change state.
3. Run the listed post-change verification probes.
4. Continue from `<phase>`; do not restart the audit from scratch.
