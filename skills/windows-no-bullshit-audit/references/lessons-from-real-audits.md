# Generalized Lessons from Real Audits

These are intentionally hardware/vendor-agnostic.

## Scenario: repair reports success, later scan still reports corruption

Bad response: declare repaired immediately.

Correct response: compare corruption sets, inspect servicing logs/source, repair again only if justified, and require a final clean independent scan.

## Scenario: storage controller reset appears repeatedly

Bad response: replace the cable/disk based on the event ID.

Correct response: map the controller path to the exact device, inspect media/link counters, and correlate every occurrence with runtime versus shutdown/sleep/update lifecycle.

## Scenario: restore/VSS errors appear after a system-disk migration

Bad response: delete all shadow copies.

Correct response: inspect current protected volumes, stale/ghost volume references, shadow storage quotas, writers, and current restore-point creation before changing VSS state.

## Scenario: legacy peripheral driver coexists with disabled security feature

Bad response: automatically enable the security feature.

Correct response: verify the setting, driver signatures/Code Integrity behavior, operator intent, current vendor compatibility, and document the deliberate tradeoff.

## Scenario: old backup/security product is gone but service/task remains

Bad response: delete every matching file/service based on a name search.

Correct response: check installed-product inventory, exact service/task definition, binary presence, signatures, current PnP/filter state, then remove only proven residue.

## Scenario: application DLL is blocked by Code Integrity

Bad response: call Windows corrupted.

Correct response: determine process protection level, DLL owner/signing level, recurrence, current file presence, and whether policy blocked it by design.

## Scenario: regex search catches a scary unrelated object

Bad response: trust the regex label.

Correct response: print the exact matched field/value. Substrings in ordinary words can create false positives.
