# Performance Analysis

## Goal

Find avoidable latency and resource waste even when the operator thinks the
machine feels normal. Performance is in scope by default, but it is *bounded*
by default too.

## Two tiers

**Tier 1 - always, free.** `collect-baseline.ps1` already captures the CPU/DPC/
interrupt/queue/memory/paging/disk snapshot and the top processes by CPU and
working set. They are in `TRIAGE.md`. Do not re-collect them.

**Tier 2 - only when tier 1 or a reported symptom justifies it.** Run
`scripts/collect-performance.ps1` for a bounded CIM sample plus a short WPR
runtime trace.

Do not run tier 2 "for completeness" on a machine whose tier 1 snapshot is
unremarkable and whose operator reports no symptom. Say so in the report
instead: a baseline was taken, it showed nothing, deeper tracing was not
warranted. That is a finding, not a gap.

## Reading tier 1

Signals that justify escalating:

- sustained DPC or interrupt time above a few percent -> driver/interrupt analysis;
- processor queue length consistently above core count -> CPU contention;
- low available memory with sustained paging -> memory pressure;
- high disk queue or percent disk time at low throughput -> latency, not bandwidth;
- a process holding unexpected CPU seconds relative to uptime.

## Escalation targets

- high DPC/ISR -> which driver, via ETW;
- storage latency -> correlate with process/file I/O and storage events;
- CPU spikes -> process, thread and stack analysis;
- slow boot or logon -> reboot-based boot trace, **explicit approval required**;
- UI hangs without CPU saturation -> wait chains, disk, GPU, shell extensions.

## WPR

`collect-performance.ps1` runs a bounded `GeneralProfile` trace. Keep it short;
ETL files grow fast and are useless to read directly. If WPR is missing, ask the
install-or-manual question once (see `tooling-and-web.md`) and continue other
work meanwhile.

Never read an `.etl` file as text. Analyze it with WPA, or extract a specific
summary.

## Interpretation

- A synthetic throughput benchmark is not latency analysis. Do not recommend
  risky cache or acceleration features to improve a benchmark number.
- "Within limits" can still be poor for the hardware class. Compare the measured
  bottleneck to what that specific platform should deliver, using current vendor
  expectations.
