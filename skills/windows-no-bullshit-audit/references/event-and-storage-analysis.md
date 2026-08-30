# Event and Storage Analysis

Load only when a storage, device or event-correlation finding actually exists.
General doctrine (including "a port number is not a disk") is in
`diagnostic-doctrine.md` and is not repeated here.

## Event workflow

For a recurring warning or error already visible in `TRIAGE.md`:

1. pull the exact provider, ID, level, message and event XML properties for a
   bounded sample, not the whole set;
2. you already have count and first/last from the digest - do not recount;
3. inspect nearby lifecycle events in a window matched to the mechanism;
4. identify the exact process, device or service involved;
5. compare against actual reported symptoms;
6. research current provider/vendor documentation;
7. design an A/B or targeted operational-log query.

Useful bounded query shape:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='<p>';Id=<n>;StartTime=$since} -MaxEvents 20 |
  Select-Object TimeCreated,Id,@{n='M';e={$_.Message -replace '\s+',' '}}
```

## Resolving a storage fault to a device

Resolve, in this order:

- storage miniport/controller;
- port, path, target and LUN where available;
- class disk GUID and device instance;
- vendor, product, serial;
- whether that same device shows media errors, CRC/link errors, WHEA,
  filesystem errors or reliability-counter anomalies;
- whether events occur during runtime, or only during
  shutdown/sleep/resume/update/backup.

Storage/Storport and device/PnP operational channels carry the detail. Export
raw EVTX where practical, then query it.

## Separate the four layers

- filesystem consistency;
- storage media health;
- transport and link health;
- controller and driver timeout behaviour;
- power-loss history.

A clean CHKDSK does not prove media health. Clean media counters do not prove
the controller path is flawless.

## Power-transition correlation

For events clustered around shutdown, sleep or resume, inspect nearby:

- user/system shutdown initiation;
- Kernel-Power lifecycle events;
- unexpected shutdown markers;
- effective Fast Startup / hibernate state;
- device reset and timeout events;
- resume events.

Do not infer the operator's chosen UI action from a single kernel event.

## A/B tests

Prefer a low-risk change that isolates one variable:

- disable a non-essential caching or acceleration layer, then watch for recurrence;
- disable Fast Startup with hardware unchanged;
- disable a legacy virtual adapter before uninstalling it;
- temporarily disable a startup component rather than deleting it.

Allow enough repetitions or elapsed time for absence to mean something. Record
the observation window in the finding, otherwise "it stopped" is unfalsifiable.
