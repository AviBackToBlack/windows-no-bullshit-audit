# Software Hygiene and Autoruns

Load only when doing the software-hygiene phase. Deletion doctrine
(`File not found` is not an orphan, one signal is never enough, exact-object
mapping) is in `diagnostic-doctrine.md` and is not repeated here.

## Goal

Find unnecessary background load and stale system integration. Not debloating.

## Collection

Run `scripts/collect-autoruns.ps1`. It keeps the full XML on disk and emits
`AUTORUNS-TRIAGE.md`, a capped list of only the entries where a decision is even
possible: not Microsoft-signed, unsigned/unverified, or image missing.

Read the digest. Query `autoruns-review.csv` for anything beyond it. Never read
`autoruns.xml`.

VirusTotal lookup (`-VirusTotal`) shares file hashes with a third party and
therefore needs operator approval.

Extension points worth attention: Logon/Run/Startup, services, drivers,
scheduled tasks, Active Setup, Explorer/shell extensions, Winsock providers,
codecs and print monitors.

## Classification

- `KEEP` - needed and current.
- `OPTIONAL` - legitimate, but not required at startup.
- `OBSOLETE` - superseded, or the component no longer does anything useful.
- `ORPHAN` - owning product absent and the entry points at proven residue.
- `UNNECESSARY_AUTOSTART` - legitimate software that need not start automatically.
- `INVESTIGATE` - ownership or semantics unclear.
- `INTENTIONAL` - deliberately retained despite age or unusual configuration.

## Order of operations

1. If the product is still registered as installed, use its official
   uninstaller. Reboot if required and approved.
2. Re-run Autoruns and inspect what actually remains.
3. Only then consider removing residue.

Prefer an A/B disable over deletion whenever the answer is uncertain. Disabling
produces evidence; deleting produces a guess and no way back.

## Legacy drivers and virtual adapters

A disconnected legacy virtual adapter is not automatically a problem. Determine
whether any active configuration still requires it. Disable as an A/B test
before removing the driver package.

## Presenting cleanup

Cleanup is always opt-in. Present a batch, and for each item give: the item, its
owner/product, why it is considered removable, the impact if removed, and the
reinstall or rollback path. Then let the operator choose.
