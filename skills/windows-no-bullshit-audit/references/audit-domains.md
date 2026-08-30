# Audit Domains

Use this as coverage guidance, not as a reason to invent findings.

## System / firmware baseline

- edition, build, architecture, uptime;
- motherboard/system model, BIOS/UEFI version/date;
- CPU, memory, GPU, hypervisor state;
- recent hardware migration context when discoverable.

## Windows integrity / servicing

- DISM CheckHealth, AnalyzeComponentStore, ScanHealth;
- SFC VerifyOnly;
- CBS/DISM logs when scans report corruption or anomalous repairs;
- update servicing history and pending reboot state.

## Storage / filesystem

- physical disks, buses, volumes, partitions, filesystems;
- SMART/reliability counters when Windows exposes them;
- dirty bit and online CHKDSK scan for fixed NTFS volumes;
- storage controller topology;
- disk/NVMe/AHCI/Storport/NTFS events;
- BitLocker state without exporting recovery secrets;
- VSS/shadow storage interaction when relevant.

## Devices / drivers

- PnP problem codes;
- driver store and signed driver inventory;
- currently running third-party kernel drivers;
- filesystem minifilters and instances;
- Code Integrity operational log;
- Driver Frameworks/PnP failures when evidence warrants it.

## Event/reliability chronology

- System, Application, Setup;
- WHEA, BugCheck, Kernel-Power, Kernel-Boot, Kernel-PnP;
- storage providers;
- Service Control Manager;
- application crash/hang/.NET Runtime/WER;
- Windows Update and Code Integrity;
- Task Scheduler where failed tasks matter.

## WER / dumps

- inventory WER report manifests and dump metadata;
- do not copy crash dumps into the standard audit package;
- only analyze dump payloads when a concrete crash question requires it.

## Boot / recovery / restore

- BCD inventory;
- WinRE state and location;
- Secure Boot state;
- VSS writers/providers/shadows/shadow storage;
- System Restore configuration/restore points where supported.

## Power

- available sleep states;
- active power scheme;
- wake requests/timers/last wake;
- hibernation/Fast Startup effective state;
- powercfg energy/system reports when useful;
- UPS/power-management software and PnP identification when present.

## Network

- adapters, drivers, routes, IP configuration;
- Winsock catalog;
- firewall profiles;
- listening TCP endpoints for anomaly/hygiene review;
- VPN virtual adapters and legacy residues when present.

## Services / tasks / startup / installed software

- services and startup modes;
- scheduled tasks and actions;
- Run keys / Startup folders / Win32_StartupCommand;
- installed package inventory;
- Autoruns deep pass for shell extensions, drivers, services, tasks, Winsock, codecs, Active Setup, etc.

## Security

- Defender state/configuration;
- Secure Boot, TPM;
- VBS/Device Guard/HVCI/Memory Integrity state;
- BitLocker state;
- UAC/LSA protection indicators;
- firewall profile state;
- intentional compatibility exceptions.

## Performance

- CPU/queue/memory/paging/disk latency baseline;
- top CPU/working set/handle processes;
- DPC/interrupt baseline;
- short WPR/ETW runtime trace;
- deeper targeted trace only when evidence or symptoms justify it;
- reboot-based boot trace only with approval.
