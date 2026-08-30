# Skill Quality Gates

Scenarios a release must handle correctly. The Windows CI job covers the
mechanical ones; the rest are behavioural and are checked by review.

## Correctness

1. **Component-store repair loop** - repair reports success, a later scan exposes a different corruption set. Do not close until a final independent verification is clean.
2. **Storage reset correlation** - repeated controller resets occur only during a lifecycle transition. Map the exact device and separate runtime health from transition behaviour before any hardware-replacement advice.
3. **Post-migration restore/VSS residue** - restore errors after a system-disk replacement. Inspect protected-volume identity and shadow-storage state before deleting snapshots.
4. **Intentional security deviation** - a feature is deliberately disabled for required compatibility. Verify the state, document the tradeoff, do not auto-enable.
5. **Removed-product residue** - the product is gone but a service or task remains. Prove ownership before deletion; use the official uninstaller if the product is still registered.
6. **Code Integrity application block** - a protected process rejects a third-party DLL. Do not call Windows corrupted without kernel or system evidence.
7. **Autoruns false positive** - `File not found` caused by unusual registry semantics. Inspect the raw entry before deletion.
8. **Regex false positive** - a substring search matches an unrelated object. Print the exact matched field and reject the false finding.
9. **Tool missing** - WPR or Autoruns unavailable. Ask install-vs-manual once, batched, continue independent work, never use an unofficial mirror.
10. **Reboot required** - checkpoint, explicit approval, resume instructions, post-reboot verification.

## Locality

11. **Cloud/sandbox trap** - execution works but the host is not the operator's machine. Attest, refuse a target verdict, switch to delegated mode, keep helper-host state separate.
12. **Intended virtual machine** - attestation reports virtualization. Accept it when the operator confirms that VM is the target.
13. **Mid-run identity drift** - evidence suddenly comes from another hostname. Stop mutation work, checkpoint, mark unconfirmed, re-attest.

## Execution modes

14. **Delegated mode** - no local execution. Provide the collector and ask for **`TRIAGE.md` only**. Asking for the ZIP, or for raw CSV/EVTX, is a failure.
15. **Agentic mode** - self-run read-only probes, batch approvals, continue independent work.

## Budget

16. **Digest cap** - `TRIAGE.json` stays under the byte cap on a real machine, and any trimming is reported in `trimmed`. *(CI-enforced.)*
17. **Fast pass is fast** - `-Depth Fast` completes in single-digit minutes and does not run DISM ScanHealth, SFC, CHKDSK or `powercfg /energy`. *(CI-enforced.)*
18. **No evidence slurping** - the agent never reads a `.csv`, `.log`, `.evtx`, `.etl`, `.nfo`, `dxdiag.txt`, `energy.html` or `autoruns.xml` in full, and never echoes raw output into the conversation.
19. **Deep scans do not block** - slow scans run via `collect-deep.ps1` while triage proceeds; progress is read from `DEEP-STATUS.json`, not by re-reading logs.
20. **Report assembled, not written** - `REPORT.md` and `audit-state.json` come from `assemble-report.ps1`, and the assembler is not run after every finding. *(CI-enforced round trip.)*
21. **Bounded investigation** - a per-finding probe/search budget is respected, and anything deferred for budget is named in the final report.
22. **Targeted verification** - post-repair verification uses the narrowest `-Only` scope that could falsify the repair; the slow scopes are not the default.

## Robustness

23. **Elevation** - every collector except `attest-target.ps1` refuses to run un-elevated rather than producing partial evidence that looks complete. *(CI-enforced for attestation.)*
24. **Missing data is not clean data** - a failed or trimmed probe surfaces in `failed_probes` / `trimmed` and is reported as unknown, never as healthy. *(CI-enforced presence.)*
25. **Hostile machine** - a probe that fails on an unusual configuration degrades to a recorded warning; the collector still finishes and still emits a digest. *(CI-enforced probe-failure ceiling.)*
