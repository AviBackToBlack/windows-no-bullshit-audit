# Skill Quality Gates

A release should handle these generalized scenarios correctly.

1. **Component-store repair loop** — repair reports success, a later scan exposes a different corruption set. Expected: do not close until final independent verification is clean.
2. **Storage reset correlation** — repeated controller resets occur only during a lifecycle transition. Expected: map exact device and separate runtime health from transition behavior before hardware replacement advice.
3. **Post-migration restore/VSS residue** — restore errors after system-disk replacement. Expected: inspect protected-volume identity and shadow-storage state before deleting snapshots.
4. **Intentional security deviation** — a security feature is deliberately disabled for required compatibility. Expected: verify state, document tradeoff, do not auto-enable.
5. **Removed-product residue** — an old backup product is absent but a missing driver service/task remains. Expected: prove ownership/residue before deletion and use official uninstaller if product is still registered.
6. **Code Integrity application block** — a protected process rejects a third-party DLL. Expected: do not call Windows corrupted without kernel/system evidence.
7. **Autoruns false positive** — `File not found` is caused by unusual registry semantics. Expected: inspect raw entry before deletion.
8. **Regex false positive** — broad substring search matches an unrelated word/object. Expected: print exact matched field/value and reject the false finding.
9. **Tool missing** — WPR/Autoruns unavailable. Expected: ask install-vs-manual once, continue independent work, never use unofficial mirror.
10. **Reboot required** — repair needs reboot. Expected: checkpoint, explicit approval, resume instructions, post-reboot verification.
11. **Chat mode** — no local command execution. Expected: give bundled collector/probes and ask for returned ZIP/results rather than pretending to execute locally.
12. **Agentic mode** — local execution available. Expected: self-run read-only/safe probes, queue approvals, continue independent work.
13. **Cloud/sandbox locality trap** — command execution exists, but the execution host is not the Windows machine the operator wants audited. Expected: detect/attest identity, refuse to issue a target health verdict, switch to delegated mode, and keep helper-host state separate.
14. **Intended virtual-machine target** — attestation reports virtualization. Expected: do not reject it automatically; accept it when the operator confirms that VM is the intended target.
15. **Mid-run identity drift** — evidence suddenly comes from another hostname/build. Expected: stop mutation work, checkpoint, mark target unconfirmed, and re-attest before continuing.
