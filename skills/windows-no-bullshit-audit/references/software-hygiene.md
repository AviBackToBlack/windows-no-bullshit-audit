# Software Hygiene and Autoruns

## Purpose

Find unnecessary background load and stale system integration without turning the audit into indiscriminate debloating.

## Autoruns collection

Prefer `scripts/collect-autoruns.ps1` with signature verification and hashes. VirusTotal lookup is optional because it shares file hashes with an external service.

Review non-Microsoft entries across:

- Logon/Run/Startup;
- services;
- drivers;
- scheduled tasks;
- Active Setup;
- Explorer/shell extensions;
- Winsock providers;
- codecs/print monitors/other extension points.

## Classification

- `KEEP` — needed/current.
- `OPTIONAL` — legitimate but not required at startup.
- `OBSOLETE` — supported product has a newer replacement or the component is no longer useful.
- `ORPHAN` — owning product absent and the entry points to missing/unused residue, proven by evidence.
- `UNNECESSARY_AUTOSTART` — legitimate software that need not start automatically.
- `INVESTIGATE` — ownership/semantics unclear.
- `INTENTIONAL` — deliberately retained despite age/unusual configuration.

## Never delete based on one signal

Before deleting an apparent orphan:

1. inspect raw registry/service/task entry;
2. resolve file path and signature;
3. resolve installed product/owner;
4. search uninstall inventory;
5. check whether the binary or device still exists;
6. inspect current vendor guidance if relevant.

Autoruns `File not found` can be a false positive for unusual registry semantics.

## Installed product first

If the product is still installed, use its official uninstaller. Reboot if required and approved. Then re-run Autoruns and inspect residue.

## Startup cleanup

Prefer an A/B disable when unsure. If functionality is unaffected and the operator wants cleanup, remove through the owning application's settings/uninstaller when possible.

## Legacy drivers/adapters

A disconnected legacy virtual adapter is not automatically a problem. Determine whether any active configuration still requires it. Disable as an A/B test before deleting the driver package.

## Exact matching

Avoid broad regex cleanup. A substring match can capture unrelated services/devices. Print the exact object before any deletion.
