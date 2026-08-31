# Audit Domains

Coverage map. Most of this is collected automatically and summarized into
`TRIAGE.md`; the "digest" column says where the answer already is, so you do not
re-collect it. Use this as a completeness check, not as a reason to invent
findings.

Load this file only when checking coverage at `FINAL_VALIDATION`, or when
deciding whether a domain was actually examined.

| Domain | Covered by fast baseline | Where in the digest |
|---|---|---|
| System / firmware baseline | yes | `target` |
| Servicing / component store | CheckHealth only | `flags.dism_component_store`, deep pass for ScanHealth/SFC |
| Storage / filesystem | yes | `storage`, `flags.dirty_volumes` |
| Devices / drivers | yes | `pnp_problems`, `third_party_kernel_drivers`, `third_party_minifilters` |
| Event chronology | yes | `top_event_signatures`, `counters` |
| WER / dumps | inventory only | `flags.crash_dumps_present`, `flags.latest_dump` |
| Boot / recovery / restore | yes | `flags.secure_boot`, `winre_enabled`, `restore_point_count`, `vss_writer_failures` |
| Power | yes | `flags.fast_startup_enabled`, `hiberfile_present` |
| Network | raw only | `10-Network\*` - query it |
| Services / tasks / startup / software | yes | `third_party_auto_services`, `startup_entries`, `recent_software` |
| Security | yes | `flags.*` security block |
| Performance | tier 1 | `performance` |
| Autostart deep pass | no | run `collect-autoruns.ps1` |

## Notes per domain

**Servicing.** ScanHealth and SFC are in the deep pass, not the fast pass. Until
`DEEP-TRIAGE.md` exists, treat them as `NOT_RUN`, not as clean.

**Storage.** Reliability counters, dirty bit, controller topology and
disk/NVMe/AHCI/Storport/NTFS events. BitLocker state without exporting recovery
secrets.

**Devices.** PnP problem codes, driver store, running third-party kernel
drivers, minifilters and instances, Code Integrity operational log.

**WER / dumps.** Inventory manifests and dump metadata. Do not copy dump
payloads into the audit package. Analyze a dump only when a concrete crash
question requires it and the operator approves.

**Boot / recovery.** BCD inventory, WinRE state and location, Secure Boot, VSS
writers/providers/shadows/shadow storage, System Restore configuration.

**Power.** Available sleep states, active scheme, wake requests/timers/last
wake, effective hibernation and Fast Startup, `powercfg /energy` in the deep
pass, UPS and power-management software when present.

**Network.** Adapters and drivers, routes, IP configuration, Winsock catalog,
firewall profiles, listening TCP endpoints, VPN virtual adapters and legacy
residue. Not summarized by default - query `10-Network\` when a network finding
is in play.

**Security.** Defender state and configuration, Secure Boot, TPM,
VBS/Device Guard/HVCI, BitLocker, UAC and LSA protection, firewall profiles, and
intentional compatibility exceptions.

## Marking a domain unavailable

If a domain could not be examined, say so explicitly with the reason: probe
failed, tool missing, not elevated, deliberately deferred for budget.
`TRIAGE.json` lists `collection.failed_probes` and `trimmed` for exactly this.
An unexamined domain silently presented as healthy is the worst outcome this
skill can produce.
