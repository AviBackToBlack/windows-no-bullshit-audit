# Target Machine Attestation

## Purpose

Never confuse the environment that can execute commands with the Windows 11
machine the operator wants audited. A cloud sandbox, helper VM, container,
remote shell host or local agent runtime can all expose shell and file access.
Capability is not identity.

## Probe

Run `scripts/attest-target.ps1` when the current execution environment is
Windows. It deliberately does **not** require administrator rights, because
proving "this is the wrong machine" must work everywhere, including in a locked
down sandbox.

It reports computer name, Windows edition/build/architecture,
manufacturer/model, current and interactive user, system drive, virtualization
indicators, elevation state and PowerShell edition/path.

It does not collect serial numbers, product keys or licence identifiers.
Identity does not require them.

Use `-Redact` when the output will be pasted into a hosted chat.

## Decision

Classify locality as exactly one of:

- `CONFIRMED_TARGET` - the operator confirms this is the machine to audit.
- `NOT_TARGET` - execution is in a sandbox/cloud/helper environment, or the
  operator says it is the wrong machine.
- `UNCONFIRMED` - identity is known but not yet confirmed.
- `UNAVAILABLE` - this environment cannot attest the target at all.

A virtual machine is not automatically wrong. If the operator intends to audit
that VM, it is the target.

## One round trip, not three

Do not spend separate turns on target identity, safety confirmation and the
elevation requirement. When local attestation succeeds, combine them:

> I am about to audit `<computer>` - `<Windows edition/build>`,
> `<manufacturer/model>`. Confirm this is the intended target, that important
> work is saved and closed, and note that collection needs an **administrator**
> Terminal. The fast pass takes a couple of minutes.

That single message satisfies target confirmation, the pre-flight safety gate
and the elevation contract.

## Sandbox / cloud fallback

If the command environment is not the intended Windows target:

1. do **not** run the baseline collector against the sandbox;
2. do **not** produce a Windows health verdict from sandbox evidence;
3. switch to delegated mode;
4. give the operator `scripts/attest-target.ps1` and then
   `scripts/collect-baseline.ps1`, and ask for `TRIAGE.md` back;
5. analyze only evidence returned from that host.

The sandbox may still parse returned evidence, run web research and generate
reports. Label that as helper execution and never mix its system state with
target evidence.

## Provenance

Every local evidence item must be attributable to the confirmed target run.
`TRIAGE.json` carries `target` and `run_id` for exactly this reason. If several
machines appear in one conversation, keep their findings separate.

If target identity changes unexpectedly mid-run: stop all mutation work,
checkpoint, set locality to `UNCONFIRMED`, and re-attest before continuing.
