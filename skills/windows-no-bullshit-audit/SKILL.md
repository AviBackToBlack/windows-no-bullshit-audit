---
name: windows-no-bullshit-audit
description: Deep Windows 11 health, performance, security, reliability, storage, driver, event-log, boot/recovery, power, network, software-hygiene and autostart audit. Use when asked to inspect, troubleshoot, diagnose, validate, optimize, clean up or repair a Windows 11 PC - including vaguer requests like "my PC is slow", "it keeps freezing", "random restarts", "blue screen / BSOD", "check if this machine is healthy", "why is boot so slow", "clean up startup programs". Covers DISM/SFC, CHKDSK, WHEA, WER/dumps, PnP, minifilters, Code Integrity, VSS/WinRE, services/tasks/startup, Autoruns and WPR/ETW. Evidence first. No cargo-cult fixes. Token-budgeted.
license: MIT
compatibility: "Windows 11 Home/Pro/Enterprise/Education, x64 or ARM64. Windows PowerShell 5.1. Collectors require an elevated session. Internet access expected for current vendor research."
metadata:
  version: "0.2.2"
  scope: "windows-11-client"
---

# Windows No-Bullshit Audit

Deep-audit Windows 11 until the important findings are verified healthy,
explained, repaired and re-verified, intentionally accepted, or explicitly left
`UNKNOWN` with a named next test.

Do not optimize for a green dashboard. Optimize for justified conclusions,
delivered inside the operator's budget.

## 0. Budget is a constraint, not a nicety

The operator pays for this audit in context window and usage quota. An audit
that exhausts the quota halfway through is a failed audit.

Three rules, in priority order:

1. **Never trade a correct conclusion for tokens.**
2. **Always trade thoroughness theater for tokens.**
3. **Deterministic work belongs in PowerShell; judgement belongs in you.**

The bundled collectors already count, group, filter, resolve signers and
threshold the data. They emit a capped digest. Your job starts at the digest.

Read [references/token-discipline.md](references/token-discipline.md) now. It is
short and it is binding, especially the **evidence access protocol**.

Non-negotiable summary:

- Read `TRIAGE.md` (and `TRIAGE.json` for exact values). Read no other evidence
  file in full, ever.
- Raw evidence is **queried** with filters, projections and `-First N`. Never
  `Get-Content` a `.csv`, `.log`, `.evtx`, `.etl`, `.nfo`, `dxdiag.txt`,
  `energy.html` or `autoruns.xml`.
- Never echo raw command output into the conversation. Report the reduction.
- One probe, one question. If a probe cannot change a classification, skip it.

## 1. Attest the target before auditing it

Command capability is not target identity. A sandbox, helper VM, container or
cloud runtime can execute commands while being the wrong machine. Target
attestation is a **technical prerequisite**, not a conversational inference.

Hard gate:

1. determine whether the environment that will execute audit commands is
   Windows, using runtime metadata or the smallest OS-identity probe available;
2. on a candidate Windows command host, the **first Windows target probe MUST be
   the bundled `scripts/attest-target.ps1`** (no admin needed, by design);
3. establish computer name, edition/build, architecture, manufacturer/model,
   current/interactive user, system drive and virtualization indicators from
   that output;
4. ask the operator to confirm the returned fingerprint;
5. only then classify locality as `CONFIRMED_TARGET` and proceed.

**Operator confirmation cannot substitute for technical attestation.** Facts
from the conversation, memory, a host label, plugin invocation context, prior
audits, environment variables, or the operator saying "yes, this is the PC"
may suggest identity but never satisfy this gate. Without current output from
the bundled attestation script executed on the candidate target, agentic/local
mode cannot become `CONFIRMED_TARGET`.

The locality states mean exactly:

- `CONFIRMED_TARGET` - current bundled attestation evidence exists **and** the
  operator confirmed that returned machine fingerprint as the intended target;
- `NOT_TARGET` - the execution host is a helper/sandbox/non-target, or the
  operator rejects the attested fingerprint;
- `UNCONFIRMED` - a candidate Windows host was technically attested but its
  returned fingerprint has not yet been confirmed by the operator;
- `UNAVAILABLE` - the intended target cannot currently run or return the bundled
  attestation evidence.

If the execution host is clearly not the target, **do not ask the operator to
confirm the helper host and do not audit it**. Switch to delegated mode. The
helper may still parse returned evidence, research and write reports - labelled
as helper execution, never merged with target state.

A virtual machine is valid if it is the machine the operator wants audited.
Never issue a Windows health verdict for `NOT_TARGET`, `UNCONFIRMED` or
`UNAVAILABLE`.

Read [references/target-attestation.md](references/target-attestation.md).

## 2. One opening round trip, after technical attestation

Do not ask for target confirmation before technical attestation. Once a machine
fingerprint exists, combine target confirmation, the safety gate and the
appropriate elevation contract in **one message**, not three turns.

For an **agentic/local candidate**:

> I ran the bundled target attestation on `<computer>` - `<edition/build>`,
> `<manufacturer/model>`. Please confirm:
> 1. this fingerprint is the machine you want audited;
> 2. important work is saved and closed (later stages may close processes or
>    need a reboot);
> 3. you approve administrator-level **agent collection** for the read-only fast
>    pass.
>
> The first pass is read-only with respect to Windows configuration and usually
> takes 1-3 minutes.

For a **delegated target** whose attestation output was returned by the operator:

> The returned bundled attestation identifies `<computer>` - `<edition/build>`,
> `<manufacturer/model>`. Please confirm this is the intended target, that
> important work is saved and closed, and that you can run the collector from an
> **administrator Terminal**. The fast pass usually takes 1-3 minutes.

Do not mutate anything before that confirmation. Research and preparation may
continue while waiting.

**Approval is not elevation.** Every collector except `attest-target.ps1`
requires a genuinely elevated Windows token. In agentic/local mode, after the
operator approves administrator-level collection, request elevation through the
runtime if it supports that capability and then **verify the token that will
launch the collector is actually elevated**. Re-run the bundled attestation in
that execution context or use an equivalent minimal token check.

Do not claim that elevated collection has started until elevation is verified.
If the runtime cannot provide an elevated token, say `ELEVATION_UNAVAILABLE`
and switch only the collection step to delegated/manual execution. Do not use a
failed collector run as the way the operator discovers the runtime was not
actually elevated.

## 3. Execution mode and bundled-code provenance

- **Agentic/local**: command execution is available on the candidate Windows
  host, the bundled attestation script succeeded there, and the operator
  confirmed the returned fingerprint.
- **Delegated**: you cannot execute on the intended target. The operator runs
  the bundled attestation/collector on that target and returns the bounded
  output.

Same diagnostic method either way. Helper-host execution never becomes target
evidence.

### The installed bundle is the runtime source of truth

Every `scripts/...` path in this Skill means the file shipped in **this installed
Skill version**. Never fetch an individual bundled script from the network - not
from GitHub, `raw.githubusercontent.com`, a release page, search results, docs,
or any other URL - and never reconstruct a collector from prose. Web access is
for current diagnostic research, not for replacing the installed audit runtime.
Mixing instructions from one version with collectors from another is invalid.

In delegated mode:

1. if the runtime can surface/export a file from the installed Skill bundle,
   provide the bundled `scripts/attest-target.ps1` that way;
2. if the runtime cannot expose bundled files, say so explicitly. Direct the
   operator to the **matching versioned standalone release artifact** as the
   fallback; do not fetch or hand them an individual raw `.ps1` from the web;
3. after returned attestation plus operator confirmation, use the same installed
   bundle/version for `scripts/collect-baseline.ps1`;
4. ask for **`TRIAGE.md` only** (~10-15 KB). Never ask for the ZIP; it contains
   tens of MB of raw event evidence. Request specific raw data only when a
   specific question needs it, and ask for *the output of a query*, not the file.

Do not paste the full source of a bundled collector into the conversation as a
provenance workaround.

### Demonstrations must not fabricate evidence

Never fabricate target evidence, collector output, `TRIAGE` contents, Windows
events, probe results, repair outcomes, or verification results and present them
as an audit. A request to "make up a realistic user prompt and then use the
Skill" permits inventing the **prompt/scenario only**; execution still obeys the
real locality boundary and stops at delegated handoff if no real target evidence
is available.

A synthetic/hypothetical audit is allowed only when the operator explicitly
asks for a simulation. Label it synthetic throughout and never treat it as
validation of a real machine or of a repair.

## 4. Collect: fast first, slow in the background

Collection begins only after the attestation, operator-confirmation and elevation
contracts above are satisfied.

```powershell
# 1-3 minutes, read-only, produces TRIAGE.md + TRIAGE.json
.\collect-baseline.ps1
.\collect-baseline.ps1 -Redact -CopyToClipboard   # for hosted chat
```

`-Depth Fast` is the default and deliberately skips DISM ScanHealth, SFC,
CHKDSK, `powercfg /energy`, msinfo32 and dxdiag. Those are 20-60 minutes and
belong in the background:

```powershell
.\collect-deep.ps1 -RunDir '<run>'      # poll DEEP-STATUS.json, read DEEP-TRIAGE.md
```

Poll `DEEP-STATUS.json` (a few hundred bytes). Do not poll by re-reading logs,
and do not sit in a wait loop with a full context attached - triage the fast
digest while the deep scans run.

Until `DEEP-TRIAGE.md` exists, integrity is `NOT_RUN`, **not clean**.

The run directory (`%SystemDrive%\WindowsNoBullshitAudit\<stamp>`) holds raw
evidence, `findings/`, reports and checkpoints. Never clear Windows logs. Never
create target state from a helper host and merge it later.

Treat the evidence as sensitive. Crash dumps are inventoried, never copied.
Servicing logs are copied only if a scan reported corruption.

## 5. State machine

`TARGET_ATTESTATION` -> `TARGET_CONFIRMATION` -> `ELEVATION_VERIFICATION` ->
`BASELINE_COLLECTION` -> `TRIAGE` -> `TARGETED_INVESTIGATION` ->
`CURRENT_WEB_RESEARCH` -> `REMEDIATION_PLANNING` -> `REMEDIATION` ->
`POST_REPAIR_VERIFICATION` -> `SOFTWARE_HYGIENE` -> `FINAL_VALIDATION` ->
`COMPLETE`

In delegated mode `ELEVATION_VERIFICATION` is enforced by the elevated Terminal
and the collector's own hard gate. A finding may loop investigate/repair/verify
- but see the budget in §7.

## 6. Triage from the digest

Read [references/diagnostic-doctrine.md](references/diagnostic-doctrine.md)
once, here. It carries the whole method: the observe/contextualize/map/research/
hypothesize/discriminate/repair/verify loop, the evidence hierarchy, confidence
labels, and the eight recurring mistakes that produce wrong Windows diagnoses.

Core rules while reading `TRIAGE.md`:

- An Event ID is a clue, not a diagnosis. A non-zero count is not ill health.
- Correlate with boot, shutdown, sleep/resume, update, device migration, backup,
  recovery, install/uninstall and operator actions.
- Separate current runtime faults from historical and lifecycle-only events.
- Resolve generic controller paths to real devices before blaming hardware.
- A regex hit is not a finding until you have printed the matched field.
- If evidence cannot distinguish hypotheses, record `UNKNOWN` plus the cheapest
  discriminating test.
- Check `collection.failed_probes` and `trimmed` in the digest. A trimmed or
  failed section is unknown, not empty.

Produce a **severity-ordered worklist** before investigating anything.

## 7. Bounded investigation

Triage is cheap and deterministic. Investigation is neither, so it gets a budget.

- Work the worklist top-down. Defer the tail **explicitly and visibly** rather
  than grinding everything.
- Default per finding: **at most 3 local probes and 2 web searches.** Exceeding
  it means telling the operator why.
- One discriminating test beats three confirming ones.
- Once classified, store the classification plus an evidence *pointer* (file +
  filter). Do not reopen the evidence.
- Cache research verdicts in `research-cache.json` keyed by component+version.
- Where the runtime supports subagents or background tasks, delegate bulk
  evidence grepping so the raw output never enters the main context.

Research is mandatory when a conclusion depends on current facts - versions,
support status, advisories, current recommendations. Never assert a current
version or known issue from memory when web access exists. Keep
`LOCAL EVIDENCE`, `WEB EVIDENCE` and `INFERENCE` separate. See
[references/tooling-and-web.md](references/tooling-and-web.md).

Domain references are **conditional** - load one only when a finding in that
domain exists:
[event-and-storage-analysis.md](references/event-and-storage-analysis.md),
[security-analysis.md](references/security-analysis.md),
[software-hygiene.md](references/software-hygiene.md),
[performance-analysis.md](references/performance-analysis.md),
[audit-domains.md](references/audit-domains.md).

## 8. Performance

Tier 1 is already in the digest: CPU, DPC, interrupt, queue, memory, paging,
disk, top processes. Do not re-collect it.

Tier 2 (`scripts/collect-performance.ps1`, bounded CIM sampling plus a short WPR
trace) runs only when tier 1 or a reported symptom justifies it. "Baseline taken,
unremarkable, deeper tracing not warranted" is a legitimate finding, not a gap.

If WPR is missing, ask the install-or-manual question once, batched with other
questions. Official sources only. Boot tracing needs explicit approval.

## 9. Mutation and approval

Read [references/remediation-policy.md](references/remediation-policy.md).

Allowed after the pre-flight gate: read-only commands, web research, files owned
by the audit run, hashing/parsing/reporting, and temporary diagnostic sessions
that are reliably restored.

Explicit approval required: reboot/shutdown/logoff; install or uninstall;
`DISM /RestoreHealth`, `sfc /scannow`, `chkdsk /f` or `/r`; driver/service/task/
registry deletion or persistent config; service restarts affecting user,
network, storage or security state; Windows/driver/firmware update; BitLocker,
Secure Boot, TPM, VBS/HVCI, Defender or firewall changes; VSS/System Restore
changes; boot/BCD/WinRE changes; partition/filesystem changes; anything with
realistic data-loss or boot-loss potential.

**Software cleanup is always opt-in**, even when reversible.

Never use registry cleaners, debloat scripts, broad driver updaters, or
cargo-cult timeout/power-policy registry hacks.

**Batch approvals.** Put every known approval question plus the next independent
safe step in one message. Approval-only turns are the most wasteful thing in an
interactive audit. Do not claim the runtime keeps executing while a blocking
prompt is open - it usually cannot; instead make sure nothing was left un-asked.

## 10. Reboot

Never automatic. Finish pre-reboot branches, checkpoint `audit-state.json`,
`REMEDIATION-LOG.md` and `RESUME.md`, explain why, list the post-reboot
verification checks, then ask.

To resume: same conversation, `continue Windows audit`. On resume read
`RESUME.md` and `audit-state.json` **and nothing else** before continuing.

Windows booting is not evidence that a repair worked.

## 11. Verify narrowly

A successful command is not proof of health. For every remediation record the
pre-change evidence, the exact action and rationale, the result, an independent
post-change verification, and any new or changed fault set.

```powershell
.\verify-after-repair.ps1 -Only Events,Pnp -Since '<pre-repair timestamp>'
```

Use the narrowest scope that could falsify the repair. `Integrity` and `Storage`
are slow; use them only when the repair touched the component store or the
filesystem. Then re-run the specific discriminating test that exposed the
finding - a clean broad pass does not prove a specific fault is gone.

If a repair reveals a *different* fault set, investigate again rather than
declaring victory.

## 12. Security is an audit, not a defaults enforcer

Classify as `observed state + current vendor recommendation + compatibility
evidence + operator intent`. A deliberate deviation is not automatically broken.

Never silently enable BitLocker, Secure Boot, Memory Integrity/HVCI, Smart App
Control, LSA protection, firewall policy or Defender features. Report the
tradeoff; the operator decides.

## 13. Software hygiene

Run `scripts/collect-autoruns.ps1` and read `AUTORUNS-TRIAGE.md` - the capped
list of entries that are not Microsoft-signed, unsigned, or missing their image.
Never read `autoruns.xml`.

Classify: `KEEP`, `OPTIONAL`, `OBSOLETE`, `ORPHAN`, `UNNECESSARY_AUTOSTART`,
`INVESTIGATE`, `INTENTIONAL`.

If a product is still registered as installed, use its official uninstaller
first, then inspect what actually remains. Prefer an A/B disable over deletion.
Summarize exactly what will be removed before acting.

## 14. Findings and reporting

One small file per finding: `findings/<id>.json`, shaped like
`assets/finding-template.json`. Append-only.

`REPORT.md` and `audit-state.json` are **generated**, never hand-written:

```powershell
.\assemble-report.ps1 -RunDir '<run>'
```

Run it at `FINAL_VALIDATION` and before a reboot checkpoint - not after every
finding. Regenerating a growing report inside the model costs the whole report
in output tokens and again as input next turn.

User-facing states: white check healthy/verified, yellow observe/intentional/
validation-pending, orange action-recommended, red critical, white-circle
historical/noise. Set `initial_state` when a finding improves. Never downgrade
severity to flatter the dashboard.

Each non-trivial finding carries: domain, observed evidence, lifecycle
correlation, confidence, classification, root cause when justified,
recommended/approved action, verification status, and sources for external
claims.

Read [references/reporting.md](references/reporting.md).

## 15. Completion criteria

Do not call the audit complete until:

- locality is `CONFIRMED_TARGET`, backed by current bundled attestation evidence
  plus operator confirmation, and all target evidence provenance is attributable
  to that run;
- every high-signal domain was checked or **explicitly marked unavailable**,
  including anything listed in `failed_probes` or `trimmed`;
- every critical/action finding is repaired, intentionally deferred, or has a
  documented next test;
- every performed remediation has post-change verification;
- software cleanup choices are recorded;
- a performance baseline exists, and tier 2 was either run or explicitly judged
  unwarranted;
- the report distinguishes current faults from historical noise;
- unresolved uncertainty is labelled `UNKNOWN`, not guessed;
- anything deferred to stay within budget is **named in the report**.

The last point is not optional. An audit that quietly stopped early is worse
than one that says which stone it left unturned and why.

## 16. Tone

Match the operator's language and technical level. Direct, technically precise,
non-alarmist. The sarcastic skill name is not permission to be disrespectful.

Prefer concise progress checkpoints over repeated explanation. Explain reasoning
when it changes a decision, prevents a dangerous fix, or separates competing
hypotheses.