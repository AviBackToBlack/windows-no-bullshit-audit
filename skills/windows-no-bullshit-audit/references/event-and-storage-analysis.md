# Event and Storage Analysis

## Event workflow

For a recurring warning/error:

1. get exact provider, ID, level, message and event XML/properties if needed;
2. count occurrences and record first/last timestamps;
3. inspect nearby lifecycle events;
4. identify the exact process/device/service involved;
5. compare against actual symptoms;
6. research current provider/vendor documentation;
7. design an A/B or targeted operational-log query.

## Storage reset/timeout workflow

Do not conclude "bad disk" or "bad cable" from a generic storage reset alone.

Resolve:

- storage miniport/controller;
- port/path/target/LUN when available;
- class disk GUID/device instance;
- vendor/product/serial;
- whether the same device has media errors, CRC/link errors, WHEA, filesystem errors, or reliability-counter anomalies;
- whether events occur during runtime or only during shutdown/sleep/resume/update/backup.

High-value operational logs may include Storage/Storport and device/PnP channels. Export raw EVTX where practical.

## Power-transition correlation

For events around shutdown/sleep/resume, inspect nearby:

- user/system shutdown initiation;
- Kernel-Power lifecycle events;
- unexpected shutdown markers;
- Fast Startup/hibernate effective state;
- device reset/timeouts;
- resume events.

Do not infer the user's selected UI action from a single kernel event. Windows hybrid shutdown can involve kernel hibernation even when the operator chose Shut down.

## Filesystem/media separation

Separate:

- filesystem consistency;
- storage media health;
- transport/link health;
- controller/driver timeout behavior;
- power-loss history.

A clean CHKDSK does not prove media health; clean SMART/media counters do not prove the controller path is flawless.

## A/B tests

Prefer low-risk changes that isolate one variable. Examples:

- disable a nonessential caching/acceleration layer, then observe whether the event recurs;
- disable Fast Startup while leaving hardware unchanged;
- disable a legacy virtual adapter before uninstalling it;
- temporarily disable a startup component rather than deleting it.

After the change, collect enough repetitions/time to make the absence/presence meaningful.
