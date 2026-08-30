---
name: windows-no-bullshit-audit
description: Deep Windows 11 health, performance, security, reliability, storage, driver, event-log, boot/recovery, power, network, software-hygiene, and autostart audit. Use when asked to comprehensively inspect, troubleshoot, validate, optimize, clean up, or repair a Windows 11 PC, including DISM/SFC, CHKDSK scans, WHEA, WER/dumps, PnP, minifilters, Code Integrity, VSS/WinRE, services/tasks/startup, Autoruns, and WPR/ETW performance. Evidence first. No cargo-cult fixes.
compatibility: Windows 11 Home/Pro/Enterprise/Education on x64 or ARM64. Internet access is expected for current Microsoft/OEM/vendor research. Designed for interactive agent runtimes; local execution depends on client tool access.
metadata:
  version: "0.1.1"
  scope: "windows-11-client"
---

# Windows No-Bullshit Audit

Deep-audit Windows 11 until the important findings are either verified healthy, explained, repaired and re-verified, intentionally accepted, or explicitly left unknown with a discriminating next test.

Do not optimize for a green dashboard. Optimize for justified conclusions.

## 1. Attest the target before auditing it

Do not confuse command capability with target identity.

A cloud sandbox, helper VM, container, or Work execution environment may expose shell/file access while **not** being the Windows 11 machine the operator intends to audit.

Before broad collection:

1. determine what environment commands are actually running in;
2. if it is Windows, run `scripts/attest-target.ps1` or collect equivalent identity evidence;
3. establish computer name, Windows edition/build, architecture, manufacturer/model, current/interactive user, system drive, and virtualization indicators;
4. classify locality as `CONFIRMED_TARGET`, `NOT_TARGET`, `UNCONFIRMED`, or `UNAVAILABLE`;
5. never issue a health verdict for an unconfirmed execution environment.

If the current environment is clearly not the intended target, **do not audit the sandbox**. Switch to delegated mode and have the operator run the attestation/baseline collector on the intended Windows host. The sandbox may still parse evidence, research current facts, and generate reports.

A virtual machine is valid if it is the machine the operator actually wants audited.

Read [references/target-attestation.md](references/target-attestation.md).

## 2. Detect execution mode

Determine capabilities **after target attestation**, not branding.

- **Agentic/local mode**: only when command execution is available **and** the candidate Windows host is confirmed as the intended target.
- **Chat/delegated mode**: when you cannot execute on the target host, give the operator bundled copy-paste commands or downloadable bundled scripts, then analyze returned output/files.
- Use the same diagnostic method in both modes.
- In delegated mode, avoid one-command-per-turn drip feeding. Bundle independent probes so one operator round trip returns useful evidence.

Read [references/methodology.md](references/methodology.md) and [references/remediation-policy.md](references/remediation-policy.md) before making repair decisions.

## 3. Mandatory pre-flight gate

At the beginning of every full audit, warn the operator that later diagnostic/remediation stages may close processes or require a reboot.

Require explicit confirmation that:

1. the attested machine is the intended audit target;
2. all important documents and application state are saved;
3. anything that could lose unsaved data is closed or intentionally left open at the operator's risk;
4. the operator is ready for a long-running audit.

When local attestation succeeds, combine target confirmation and this safety confirmation into **one** operator round trip.

Do not perform local system mutations before this confirmation. Minimal target attestation, current web research, and preparation may continue while waiting.

## 4. Create a durable audit run

Only after locality is `CONFIRMED_TARGET`, in agentic mode create a run directory such as:

`%SystemDrive%\WindowsNoBullshitAudit\<timestamp>`

Never create target-health state from a sandbox/helper host and later merge it into the target run.

Keep raw evidence, reports, checkpoints, and remediation history there. Never clear Windows logs as part of the audit.

Maintain:

- `REPORT.md`
- `audit-state.json`
- `REMEDIATION-LOG.md`
- `RESUME.md` whenever a reboot or handoff is pending

Use the schemas/templates under `assets/`.

## 5. State machine

Run the audit as a state machine, not as a fixed checklist that blindly repairs everything:

1. `TARGET_ATTESTATION`
2. `DISCOVERY`
3. `BASELINE_COLLECTION`
4. `TRIAGE`
5. `TARGETED_INVESTIGATION`
6. `CURRENT_WEB_RESEARCH`
7. `PERFORMANCE_BASELINE`
8. `REMEDIATION_PLANNING`
9. `REMEDIATION`
10. `POST_REPAIR_VERIFICATION`
11. `SOFTWARE_HYGIENE`
12. `FINAL_VALIDATION`
13. `COMPLETE`

A finding may loop through investigation, repair, and verification multiple times.

## 6. Collect broad read-only evidence first

Prefer `scripts/collect-baseline.ps1` for the first local pass. It is intentionally read-only with respect to Windows repair state.

It should establish enough evidence to cover the domains in [references/audit-domains.md](references/audit-domains.md), including:

- OS/build/firmware/hardware baseline;
- DISM health and SFC VerifyOnly;
- disks, volumes, filesystem scans, storage reliability, controller/device topology;
- PnP state, driver store, running drivers, minifilters;
- System/Application/Setup and high-signal operational event logs;
- WHEA, BugCheck, kernel power/lifecycle, storage, PnP, Code Integrity, update chronology;
- Reliability Monitor/WER and dump inventory without copying dump payloads by default;
- BCD/WinRE/VSS/System Restore state;
- power/sleep/hibernate/Fast Startup state;
- network adapters, routes, Winsock and firewall profiles;
- services, tasks, startup, installed software;
- Defender/Device Guard/BitLocker/TPM/Secure Boot/UAC state;
- update/pending-reboot state;
- lightweight performance counters.

In delegated mode, prefer giving the operator the collector once and asking for its ZIP rather than requesting dozens of individual commands.

Treat the audit ZIP as sensitive diagnostic data. Do not copy crash dumps or secret values by default.

## 7. Triage by evidence, not Event Viewer aesthetics

Read [references/evidence-rules.md](references/evidence-rules.md) and [references/event-and-storage-analysis.md](references/event-and-storage-analysis.md).

Core rules:

- An Event ID is a clue, not a diagnosis.
- A non-zero error count does not imply an unhealthy system.
- Correlate timestamps with boot, shutdown, sleep/resume, update, device migration, backup, recovery, install/uninstall, and user actions.
- Resolve generic controller paths to actual physical devices before blaming hardware.
- Separate current runtime faults from historical or lifecycle-only events.
- Use exact matching when possible. A regex hit is not a finding until the matched field/value is inspected.
- Old file timestamps are not sufficient reason to remove a driver.
- `File not found` in Autoruns is not sufficient reason to delete an entry without understanding the registry/task/service semantics and product owner.
- If evidence cannot distinguish hypotheses, report `UNKNOWN` and run the cheapest discriminating test.

## 8. Use current web research aggressively and correctly

Internet research is part of the audit, not decoration.

Automatically research when conclusions depend on current information such as:

- current Windows behavior/documentation;
- driver/firmware/software versions;
- vendor support status and replacement products;
- known issues/advisories;
- device-specific maintenance guidance;
- current security recommendations.

Source priority:

1. Microsoft official documentation/support
2. OEM/hardware/software vendor official sources
3. official project documentation/repositories
4. reputable technical sources
5. community reports only as supporting evidence

Never claim a current version, support status, firmware recommendation, or known issue solely from model memory when web access is available.

Keep `LOCAL EVIDENCE`, `WEB EVIDENCE`, and `INFERENCE` conceptually separate.

See [references/tooling-and-web.md](references/tooling-and-web.md).

## 9. Performance is always in scope

A user may not know that the machine is underperforming.

Always collect a lightweight performance baseline. Then, when WPR is available, run a short controlled runtime ETW trace using `scripts/collect-performance.ps1` unless doing so would interfere with active critical work.

If WPR/WPA is missing, ask one compact question while continuing independent work:

- option A: allow automatic installation from an official Microsoft source/package;
- option B: operator installs it manually and provides the path.

If automatic official installation fails, provide manual official installation instructions. Never substitute an unofficial download mirror.

Only request reboot-based boot tracing after explicit approval.

Read [references/performance-analysis.md](references/performance-analysis.md).

## 10. Approval queue: do not waste turns

In agentic mode, when an action needs approval:

- add it to `pending_approvals` in `audit-state.json`;
- ask the operator concisely;
- continue all independent read-only/safe work;
- return to the blocked action when approval arrives.

Batch approvals whenever possible.

In delegated chat mode, include approval questions and the next independent safe probe in the same response when practical. Avoid approval-only turns if other useful work can be delegated at the same time.

Do not pretend that the platform can literally continue execution while a blocking UI approval is unresolved; instead maximize independent work around the blocked branch.

## 11. Mutation policy

Automatically allowed without additional approval after pre-flight confirmation:

- read-only commands and queries;
- current web research;
- creation/update/removal of files owned by the audit run;
- hashing, parsing, correlation, report generation;
- temporary diagnostic sessions that are automatically stopped and restored to their prior state;
- other clearly low-risk, fully reversible diagnostic-only actions confined to the audit process.

Require explicit operator approval for:

- reboot, shutdown, logoff;
- installing or uninstalling software/tools/drivers;
- `DISM /RestoreHealth`, `sfc /scannow`, offline repair, `chkdsk /f` or `/r`;
- driver/service/task/registry deletion or persistent configuration changes;
- service restarts that can affect user/network/storage/security state;
- Windows Update, driver update, firmware/BIOS update;
- BitLocker, Secure Boot, TPM, VBS/HVCI/Memory Integrity, Defender, firewall policy changes;
- VSS/System Restore configuration changes or shadow-copy deletion;
- boot/BCD/WinRE changes;
- storage partition/filesystem changes;
- any action with realistic data-loss or boot-loss potential.

**Software cleanup is always opt-in**, even if reversible.

Never use registry cleaners, debloat scripts, broad driver updaters, or cargo-cult timeout/power-policy registry hacks.

## 12. Reboot protocol

A reboot is never automatic.

Before requesting one:

1. finish every useful pre-reboot branch;
2. save `audit-state.json`, `REMEDIATION-LOG.md`, and `RESUME.md`;
3. explain exactly why the reboot is needed;
4. list the post-reboot verification checks;
5. ask for explicit approval.

Tell the operator how to resume:

- resume the same agent conversation/session after Windows returns;
- say `continue Windows audit` (or equivalent);
- in agentic mode, read `RESUME.md` and `audit-state.json` before doing anything else.

Do not assume a repair worked merely because Windows booted.

## 13. Repair requires independent verification

A successful command is not proof of health.

For every remediation:

1. record the pre-change evidence;
2. record the exact action and rationale;
3. record exit/result;
4. run an independent post-change verification;
5. check for new or changed fault sets;
6. update the finding only after verification.

Use `scripts/verify-after-repair.ps1` as a generic post-repair pass when appropriate.

If a first repair reveals a different corruption/failure set, investigate again rather than declaring victory.

## 14. Security is an audit, not a defaults enforcer

Read [references/security-analysis.md](references/security-analysis.md).

Classify security state using:

`observed state + Microsoft/vendor recommendation + compatibility evidence + operator intent`

A deliberate deviation is not automatically broken. Examples include intentionally disabled virtualization/security features for a required legacy peripheral or workflow.

Do not silently enable BitLocker, Secure Boot, Memory Integrity/HVCI, Smart App Control, firewall policy, Defender features, or similar controls.

## 15. Software hygiene and Autoruns

Read [references/software-hygiene.md](references/software-hygiene.md).

Use Autoruns when available; prefer `scripts/collect-autoruns.ps1`.

Classify entries as:

- `KEEP`
- `OPTIONAL`
- `OBSOLETE`
- `ORPHAN`
- `UNNECESSARY_AUTOSTART`
- `INVESTIGATE`
- `INTENTIONAL`

If a product is still registered as installed, prefer its official uninstaller first. Only inspect/delete proven residue afterward.

Always offer cleanup as a choice and summarize exactly what will be removed before acting.

## 16. Finding states and dashboard

Use exactly these user-facing states:

- ✅ **Healthy / Verified**
- 🟡 **Observe / Intentional / Validation pending**
- 🟠 **Action recommended**
- 🔴 **Critical**
- ⚪ **Historical / Noise / Informational**

Track counts over time, but never downgrade severity merely to make the final dashboard look better.

Each non-trivial finding should contain:

- domain;
- observed evidence;
- lifecycle/context correlation;
- confidence;
- classification;
- hypothesis or root cause when justified;
- recommended/approved action;
- verification status;
- sources for current external claims.

## 17. Completion criteria

Do not call the audit complete until:

- target locality is `CONFIRMED_TARGET` and evidence provenance is attributable to that target;
- all high-signal domains were checked or explicitly marked unavailable;
- every 🔴/🟠 finding is repaired, intentionally deferred, or has a documented next test;
- every performed remediation has post-change verification;
- software cleanup choices are recorded;
- a performance baseline was collected and ETW/WPR was attempted when available;
- the final report distinguishes current faults from historical/noise;
- unresolved uncertainty is explicitly labeled `UNKNOWN` rather than guessed.

Generate the three durable deliverables using [references/reporting.md](references/reporting.md).

## 18. Tone and communication

Match the operator's language and technical level. Be direct, technically precise, and non-alarmist. The sarcastic skill name is not permission to be disrespectful.

Prefer concise progress checkpoints over repeated explanations. Explain reasoning when it changes a decision, prevents a dangerous fix, or distinguishes competing hypotheses.
