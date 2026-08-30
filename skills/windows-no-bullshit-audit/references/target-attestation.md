# Target Machine Attestation

## Purpose

Never confuse the environment that can execute commands with the Windows 11 machine the operator actually wants audited.

A cloud sandbox, helper VM, container, remote shell host, or local Work runtime may all expose shell/file capabilities. Capability alone is not proof of target identity.

## Mandatory rule

Before broad evidence collection, establish and confirm the audit target.

The candidate identity should include, at minimum:

- computer name;
- Windows edition/build and architecture;
- manufacturer/model;
- current and interactive user where available;
- system drive;
- virtualization indicators;
- execution environment basics such as PowerShell edition/path.

Use `scripts/attest-target.ps1` when the current execution environment is Windows.

Do not collect serial numbers, product keys, or other unnecessary unique identifiers for attestation.

## Decision

Classify locality as one of:

- `CONFIRMED_TARGET` — operator confirms the candidate identity is the Windows 11 machine to audit.
- `NOT_TARGET` — execution is clearly in a sandbox/cloud/helper environment or the operator says it is the wrong machine.
- `UNCONFIRMED` — identity is available but has not yet been confirmed.
- `UNAVAILABLE` — current environment cannot attest the target directly.

A virtual machine is not automatically the wrong target. If the operator intends to audit that VM, it is valid.

## Efficient first-turn confirmation

Do not create a separate conversational round trip for target identity and another for pre-flight safety.

When local Windows attestation succeeds, combine them:

> I am about to audit `<computer>` — `<Windows edition/build>`, `<manufacturer/model>`. Confirm that this is the intended target and that all important work is saved/closed before the audit proceeds.

This single confirmation satisfies both target confirmation and the mandatory pre-flight gate.

## Sandbox/cloud fallback

If the command environment is not the intended Windows target:

1. do **not** run the baseline collector against the sandbox;
2. do **not** create a Windows health verdict from sandbox evidence;
3. switch to delegated mode;
4. give the operator `scripts/attest-target.ps1` plus the baseline collector to run on the intended Windows 11 host;
5. analyze only evidence returned from that host.

It is acceptable to use the sandbox for parsing, web research, report generation, or other helper work, but label that work as helper execution and never mix its system state with target evidence.

## Evidence provenance

Every local evidence item should be attributable to the confirmed target run. If multiple machines appear in a conversation, preserve target identity in filenames/state and never merge their findings.

If target identity changes unexpectedly mid-run, stop mutation work, mark locality `UNCONFIRMED`, checkpoint state, and re-attest before proceeding.
