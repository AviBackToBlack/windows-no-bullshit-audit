# Evidence Rules

## Evidence hierarchy

Prefer, in roughly this order:

1. direct current local state;
2. raw first-party Windows logs/operational telemetry;
3. reproducible A/B tests;
4. official current Microsoft/vendor documentation;
5. signed package/file metadata;
6. aggregated historical logs;
7. community reports;
8. intuition/model memory.

Lower-ranked evidence may guide a probe but should not override stronger contradictory evidence.

## Confidence labels

Use:

- `HIGH` — direct evidence or successful discriminating test supports the conclusion;
- `MEDIUM` — multiple consistent signals, but a decisive test is missing;
- `LOW` — plausible hypothesis requiring targeted evidence;
- `UNKNOWN` — insufficient evidence to rank hypotheses responsibly.

## Current versus historical

A finding should record:

- first seen;
- last seen;
- whether it predates a hardware/software migration;
- whether it recurs after remediation;
- whether it occurs only during a lifecycle transition;
- whether the affected component is still installed/present.

Historical errors from removed software, an old disk, recovery activity, or a one-time migration should normally become ⚪ unless they still imply unresolved risk.

## Negative evidence

Useful negative evidence includes:

- no WHEA events;
- no BugChecks;
- no new events after an A/B change;
- clean filesystem scan;
- clean media/error counters;
- valid signatures;
- no PnP problem devices;
- absence of a supposedly installed component.

Negative evidence narrows hypotheses but rarely proves an unrelated component perfect.

## Correlation window

Choose a time window based on the mechanism. Seconds matter for shutdown/storage resets. Minutes may matter for install/update. Days may matter for intermittent failures.

Do not correlate events merely because they happened on the same day.

## Exact-object mapping

Before recommending replacement/removal, identify the exact object:

- physical device serial/model or PnP instance;
- service key and image path;
- driver INF/service/file;
- scheduled task path/action;
- installed product entry;
- process and module;
- volume/disk mapping.
