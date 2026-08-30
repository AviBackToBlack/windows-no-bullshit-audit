# Remediation and Approval Policy

## Guiding rule

Default to read-only evidence collection. Mutate only when the expected benefit is supported by evidence and the approval policy permits it.

## Automatic after pre-flight confirmation

Allowed without a second approval:

- read-only PowerShell/CIM/WMI/native diagnostic commands;
- exporting/copying logs into the audit workspace;
- creating ZIPs, hashes, indexes, summaries, and reports;
- web research;
- temporary diagnostic sessions that are reliably stopped and restored;
- deletion of audit-owned temporary files only.

## Explicit approval required

Always ask before:

- reboot/shutdown/logoff;
- software/tool/driver install or uninstall;
- persistent service/task/registry changes;
- driver package removal;
- filesystem/storage/partition changes;
- `DISM /RestoreHealth`;
- `sfc /scannow`;
- `chkdsk /f` or `/r`;
- Windows Update or driver update;
- firmware/BIOS update;
- System Restore/VSS configuration changes or snapshot deletion;
- boot/BCD/WinRE changes;
- BitLocker/Secure Boot/TPM/VBS/HVCI/Memory Integrity/Defender/firewall policy changes;
- actions that can interrupt networking, storage, backup, security, or the interactive session.

## Cleanup policy

Cleanup is always opt-in. Present a batch with:

- item;
- owner/product;
- why it is considered obsolete/orphan/unnecessary;
- impact if removed;
- rollback/reinstall path when known.

Prefer disabling a questionable startup entry as an A/B test before permanent deletion when that gives useful evidence.

## Approval queue

Do not stop useful work just because one branch needs approval.

Store pending actions in `audit-state.json` with fields such as:

- `id`
- `action`
- `reason`
- `risk`
- `rollback`
- `status: pending`

Continue independent diagnostics and research.

## Reboot policy

Reboot is special:

1. never automatic;
2. checkpoint first;
3. explain why;
4. list expected post-reboot state;
5. list exact verification tests;
6. instruct the operator to return to the same conversation and resume.

## Dangerous/cargo-cult operations

Never run merely because they are popular troubleshooting folklore:

- Driver Verifier on a healthy production/user machine;
- `chkdsk /r` without filesystem/media evidence;
- registry cleaners;
- generic debloat scripts;
- blanket service disabling;
- third-party driver updater suites;
- arbitrary storage timeout/LPM registry hacks;
- clearing event logs before diagnosis;
- BCD surgery without a boot-specific reason;
- security-feature enabling/disabling without compatibility and operator-intent analysis.
