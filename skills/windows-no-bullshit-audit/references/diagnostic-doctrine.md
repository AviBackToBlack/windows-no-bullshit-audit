# Diagnostic Doctrine

Single source for method, evidence rules and failure patterns. Read once, early.
Nothing here is repeated in the other references.

## The loop

1. **Observe** - collect raw state before changing anything.
2. **Contextualize** - correlate with lifecycle: boot, shutdown, sleep/resume, update, install/uninstall, migration, backup, recovery, operator actions, reported symptoms.
3. **Map** - resolve abstractions to real objects: controller to device, service to product, task to installer, event to process, driver to package.
4. **Research** - verify current Microsoft/vendor behaviour and support status.
5. **Hypothesize** - the smallest plausible set of explanations.
6. **Discriminate** - the cheapest low-risk test that separates them.
7. **Repair** - only when evidence supports it and policy allows it.
8. **Verify** - independently, and check for a *new* failure set.

For each domain the outcome is exactly one of: verified healthy, current fault,
historical/noise, intentional deviation, awaiting validation, or `UNKNOWN`.

## Evidence hierarchy

Strongest to weakest:

1. direct current local state
2. raw first-party Windows logs and operational telemetry
3. reproducible A/B tests
4. official current Microsoft/vendor documentation
5. signed package/file metadata
6. aggregated historical logs
7. community reports
8. model memory

Weaker evidence may motivate a probe. It never overrides stronger contradictory
evidence.

## Confidence

- `HIGH` - direct evidence, or a discriminating test succeeded.
- `MEDIUM` - several consistent signals, decisive test missing.
- `LOW` - plausible hypothesis needing targeted evidence.
- `UNKNOWN` - evidence cannot rank the hypotheses. Record the next discriminating test.

`UNKNOWN` is a valid, professional answer. Confidence theater is not.

## Current versus historical

Record for every finding: first seen, last seen, whether it predates a
hardware/software migration, whether it recurs after remediation, whether it
only occurs during a lifecycle transition, and whether the implicated component
is still present.

Errors from removed software, a replaced disk, recovery activity or a one-time
migration are normally historical unless they still imply unresolved risk.

## Negative evidence

Useful: no WHEA, no bugchecks, no new events after an A/B change, clean
filesystem scan, clean media counters, valid signatures, no PnP problem codes,
absence of a supposedly installed component.

Negative evidence narrows hypotheses. It rarely proves an unrelated component
perfect.

## Correlation windows

Match the window to the mechanism. Seconds for shutdown and storage resets.
Minutes for install/update. Days for intermittent faults. Two events on the same
day are not correlated by virtue of the date.

## Exact-object mapping

Before recommending replacement or removal, identify the exact object: physical
device serial/model or PnP instance, service key and image path, driver
INF/service/file, scheduled task path and action, installed product entry,
process and module, volume-to-disk mapping.

## The eight recurring mistakes

Each entry is a real pattern, stated as scenario, wrong move, right move.

### 1. Repair reported success, a later scan still finds corruption
**Wrong:** declare it repaired.
**Right:** compare the corruption *sets*, inspect servicing logs and source,
repair again only if justified, require a final clean independent scan. A
successful exit code is not a health verdict.

### 2. A storage controller reset appears repeatedly
**Wrong:** replace the cable or the disk based on the event ID.
**Right:** map the controller path to the exact device, inspect media and link
counters, and correlate every occurrence with runtime versus
shutdown/sleep/update lifecycle. A port number is not a physical disk.

### 3. Restore/VSS errors appear after a system-disk migration
**Wrong:** delete all shadow copies.
**Right:** inspect currently protected volumes, stale ghost volume references,
shadow-storage quotas, writer state, and whether restore points are being
created now.

### 4. A legacy peripheral driver coexists with a disabled security feature
**Wrong:** enable the security feature automatically.
**Right:** verify the effective setting, check driver signatures and Code
Integrity behaviour, establish operator intent, research current vendor
compatibility, and document the deliberate tradeoff.

### 5. An old product is gone but a service or task remains
**Wrong:** delete every matching file and service found by a name search.
**Right:** check the installed-product inventory, read the exact service/task
definition, confirm binary presence and signature, inspect current PnP/filter
state, then remove only proven residue. If the product is still registered as
installed, use its official uninstaller first and re-inspect afterwards.

### 6. Code Integrity blocks an application DLL
**Wrong:** conclude Windows is corrupted.
**Right:** determine process protection level, DLL owner and signing level,
recurrence, whether the file still exists, and whether policy blocked it by
design. Distinguish kernel driver load failures from protected-process signing
blocks from ordinary application module issues from residue of software that is
no longer installed.

### 7. A regex search matches something alarming
**Wrong:** trust the label the search produced.
**Right:** print the exact matched field and value. Substrings inside ordinary
words produce confident nonsense.

### 8. An autostart entry shows `File not found`
**Wrong:** delete it as an orphan.
**Right:** resolve ownership and registry/service/task semantics first. Unusual
but deliberate registry values legitimately produce this. Likewise, an old
driver may be signed, compatible, required and stable; age is a research
trigger, not a removal verdict.

## Operator intent is evidence, not truth

When the operator says a feature is off or unused, verify the effective Windows
state. Hidden mechanisms differ from mental models. Hybrid shutdown, for
example, performs a kernel hibernation even when the operator chose Shut down.
