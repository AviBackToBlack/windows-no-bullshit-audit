# Methodology

## Purpose

A deep Windows audit is an evidence-correlation exercise, not a command checklist.

The goal is to determine, for each important domain, whether the state is:

- verified healthy;
- a current fault;
- historical/noise;
- an intentional deviation;
- awaiting validation;
- or genuinely unknown.

## Zero-th step: prove the target

Before the diagnostic loop, prove which machine the evidence comes from. Shell access is not enough: a sandbox, helper VM, cloud runtime, or container can execute commands while being the wrong machine.

Attest the candidate host, confirm it with the operator, and preserve target identity in audit state. If the current execution environment is not the intended Windows 11 target, switch to delegated collection rather than auditing the helper environment.

See [target-attestation.md](target-attestation.md).

## Diagnostic loop

Use this loop repeatedly:

1. **Observe** — collect raw state before changing anything.
2. **Contextualize** — correlate with lifecycle, operator actions, installs, updates, migrations, crashes, backup/recovery, power events, and symptoms.
3. **Map** — map generic abstractions to real objects: controller to device, service to product, task to installer, event to process, driver to device/package.
4. **Research** — verify current Microsoft/vendor behavior and support status online.
5. **Hypothesize** — list the smallest plausible set of explanations.
6. **Discriminate** — choose the cheapest/lowest-risk test that distinguishes them.
7. **Repair** — only after evidence supports an action and policy allows it.
8. **Verify** — independently verify the result and check for a new failure set.

## High-value general lessons

### Repair success is not verification

A repair command can return success while a later scan reveals a different corruption set. Always re-scan independently.

### Event IDs are clues

Never map `Event ID -> fix` without checking provider, message, timestamp, device/process context, repetition, and lifecycle.

### Lifecycle context changes meaning

A timeout during normal runtime is materially different from the same timeout that occurs only during shutdown, sleep/resume, update, device migration, or recovery.

### Map controller-level errors to devices

A controller path such as a port number does not, by itself, identify a physical disk. Use operational storage logs, bus/path/target/LUN, PnP topology, class device GUIDs, and vendor/product identifiers.

### User intent is evidence, not truth serum

When the operator says a feature is disabled or never used, verify the effective Windows state. Hidden mechanisms such as hybrid shutdown can differ from the operator's mental model.

### Old does not equal bad

A driver may be old yet signed, compatible, intentionally required, and free of Code Integrity or stability evidence. Age is a research trigger, not a removal verdict.

### `File not found` does not equal orphan

Autoruns and similar tools can misinterpret registry values or represent a deliberate placeholder. Resolve ownership and semantics first.

### Regex matches can lie

Substrings can match unrelated words. Inspect the exact field and exact matched text before elevating a regex hit to a finding.

### Code Integrity errors need context

Distinguish kernel driver failures from protected-process signing policy blocks, application DLL issues, and historical residue from software that is no longer present.

### Uninstall before archaeology

When a product is still registered as installed, use the vendor/Windows uninstaller first. Then inspect residual services, tasks, drivers, filters, startup entries, registry keys, and files.

### UNKNOWN is valid

If evidence does not distinguish A from B, say so and design a discriminating test. Do not fill the gap with confidence theater.
