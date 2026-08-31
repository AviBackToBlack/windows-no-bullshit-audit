# Target Machine Attestation

## Purpose

Never confuse the environment that can execute commands with the Windows 11
machine the operator wants audited. A cloud sandbox, helper VM, container,
remote shell host or local agent runtime can all expose shell and file access.
Capability is not identity.

Target attestation is a **technical prerequisite**. Conversation context, a
known hostname, a runtime label, prior audit history, or the operator saying
"yes, this is my PC" cannot replace current attestation evidence.

## Mandatory probe

When the environment that will execute audit commands is a candidate Windows
host, the first Windows target probe MUST be the **bundled**
`scripts/attest-target.ps1`. It deliberately does **not** require administrator
rights, because proving "this is the wrong machine" must work everywhere,
including in a locked-down session.

The script reports computer name, Windows edition/build/architecture,
manufacturer/model, current and interactive user, system drive, virtualization
indicators, elevation state and PowerShell edition/path.

It does not collect serial numbers, product keys or licence identifiers.
Identity does not require them.

Use `-Redact` when the output will be pasted into a hosted chat.

Do not infer successful attestation from:

- a computer name mentioned earlier in the conversation;
- environment variables or runtime/plugin metadata alone;
- an existing shell prompt or path;
- the operator confirming a machine before the script runs;
- evidence from a previous audit or previous Skill version.

Those signals may help decide where to probe, but they do not satisfy the gate.

## Decision states

Classify locality as exactly one of:

- `CONFIRMED_TARGET` - current output from the bundled attestation script was
  produced on the candidate target **and** the operator confirmed that returned
  fingerprint as the intended machine;
- `NOT_TARGET` - execution is in a sandbox/cloud/helper/non-target environment,
  or the operator rejects the returned fingerprint;
- `UNCONFIRMED` - current bundled attestation succeeded on a candidate Windows
  host but the returned fingerprint has not yet been confirmed by the operator;
- `UNAVAILABLE` - the intended target cannot currently execute or return the
  bundled attestation evidence.

A virtual machine is not automatically wrong. If the operator intends to audit
that VM, it is the target - after bundled attestation plus confirmation.

**User confirmation alone can never transition to `CONFIRMED_TARGET`.**

## One round trip, after attestation

Do not spend separate turns on technical identity, target confirmation, safety
confirmation and elevation requirements. Run attestation first, then combine the
remaining questions.

### Agentic/local candidate

> I ran the bundled target attestation on `<computer>` - `<Windows edition/build>`,
> `<manufacturer/model>`. Confirm that this fingerprint is the intended target,
> that important work is saved and closed, and that you approve
> **administrator-level agent collection** for the read-only fast pass.

After approval, request elevation through the runtime if supported and verify the
actual token that will launch the collector is elevated. Approval is permission;
it is not evidence of elevation.

Do not say the collector has started before elevation is verified. If the
runtime cannot provide an elevated token, report `ELEVATION_UNAVAILABLE` and
switch the collection step to delegated/manual execution.

### Delegated target

After the operator returns bundled attestation output:

> The returned bundled attestation identifies `<computer>` -
> `<Windows edition/build>`, `<manufacturer/model>`. Confirm this is the intended
> target, that important work is saved and closed, and that you can run the
> collector from an **administrator Terminal**.

## Installed-bundle provenance

Every bundled script used by the audit must come from the **installed Skill
version being followed**.

Never fetch an individual bundled `.ps1` from GitHub,
`raw.githubusercontent.com`, a release page, documentation, search results or
any other network source during an audit. Never reconstruct a collector from
prose. Web access is for current diagnostic research, not for replacing the
audit runtime.

If a hosted runtime cannot expose a bundled file to the operator, say so. The
fallback is the matching **versioned standalone release artifact**, not a raw
individual script from the web. Do not paste an entire bundled collector into
the conversation as a workaround.

## Sandbox / cloud fallback

If the command environment is not the intended Windows target:

1. classify it `NOT_TARGET` without asking the operator to confirm the helper;
2. do **not** run the baseline collector against the helper;
3. do **not** produce a Windows health verdict from helper evidence;
4. switch to delegated mode;
5. surface/export the bundled `scripts/attest-target.ps1` if the runtime supports
   bundled-file delivery; otherwise direct the operator to the matching
   versioned standalone release artifact;
6. after returned attestation plus operator confirmation, provide the bundled
   `scripts/collect-baseline.ps1` through the same trusted bundle/version path;
7. ask for `TRIAGE.md` back and analyze only evidence returned from that host.

The helper may still parse returned evidence, run web research and generate
reports. Label that as helper execution and never mix its system state with
target evidence.

## No synthetic evidence as a fallback

A demonstration request may invent a realistic **user prompt or scenario**, but
it does not authorize invented target evidence. Never fabricate attestation,
collector output, events, findings, repair results or verification results and
present them as an end-to-end audit.

Synthetic audits are allowed only when the operator explicitly asks for a
simulation. Label the simulation as synthetic throughout.

## Provenance

Every local evidence item must be attributable to the confirmed target run.
`TRIAGE.json` carries `target` and `run_id` for exactly this reason. If several
machines appear in one conversation, keep their findings separate.

If target identity changes unexpectedly mid-run: stop all mutation work,
checkpoint, set locality to `UNCONFIRMED`, and re-attest before continuing.