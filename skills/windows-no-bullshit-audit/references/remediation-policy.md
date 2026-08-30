# Remediation and Approval Policy

## Guiding rule

Default to read-only evidence collection. Mutate only when the expected benefit
is supported by evidence and the approval policy permits it.

## Automatic after the pre-flight gate

Allowed without a second approval:

- read-only PowerShell/CIM/WMI/native diagnostic commands;
- exporting or copying logs into the audit workspace;
- creating ZIPs, hashes, indexes, digests and reports;
- web research;
- temporary diagnostic sessions that are reliably stopped and restored;
- deleting audit-owned temporary files only.

## Explicit approval required

Always ask before:

- reboot, shutdown, logoff;
- installing or uninstalling software, tools or drivers;
- persistent service, task or registry changes;
- driver package removal;
- filesystem, storage or partition changes;
- `DISM /RestoreHealth`;
- `sfc /scannow`;
- `chkdsk /f` or `/r`;
- Windows Update or driver update;
- firmware / BIOS update;
- System Restore or VSS configuration changes, or snapshot deletion;
- boot / BCD / WinRE changes;
- BitLocker, Secure Boot, TPM, VBS/HVCI/Memory Integrity, Defender or firewall
  policy changes;
- anything that can interrupt networking, storage, backup, security or the
  interactive session.

Cleanup is always opt-in, even when reversible.

## Batch approvals

Approval-only turns are the most wasteful thing in an interactive audit. When an
action needs approval:

1. record it in `pending_approvals` in `audit-state.json` with `id`, `action`,
   `reason`, `risk`, `rollback`, `status: pending`;
2. put **every** currently-known approval question in one message, together with
   the next independent safe step;
3. continue independent read-only work where the runtime allows it;
4. return to the blocked branch when the answer arrives.

Do not claim the runtime can keep executing while a blocking approval prompt is
open. It usually cannot. What you *can* do is make sure nothing else was left
un-asked, so the operator answers once.

## Reboot

1. never automatic;
2. finish every useful pre-reboot branch first;
3. checkpoint: `audit-state.json`, `REMEDIATION-LOG.md`, `RESUME.md`;
4. explain exactly why it is needed;
5. list the expected post-reboot state and the exact verification tests;
6. ask for explicit approval;
7. tell the operator to return to the same conversation and say
   `continue Windows audit`.

Windows booting is not evidence that the repair worked.

## Verification scope

Verify with the narrowest check that could falsify the repair:

```powershell
.\verify-after-repair.ps1 -Only Events,Pnp -Since '<pre-repair timestamp>'
```

`Integrity` and `Storage` are slow. Use them only when the repair actually
touched the component store or the filesystem. Then re-run the specific
discriminating test that exposed the finding in the first place: a clean broad
pass does not prove a specific fault is gone.

## Never run these just because they are popular

- Driver Verifier on a healthy production machine;
- `chkdsk /r` with no filesystem or media evidence;
- registry cleaners;
- generic debloat scripts;
- blanket service disabling;
- third-party driver updater suites;
- arbitrary storage timeout or LPM registry hacks;
- clearing event logs before diagnosis;
- BCD surgery with no boot-specific reason;
- toggling security features without compatibility and intent analysis.
