# Performance Analysis

## Goal

Find evidence of avoidable latency or resource waste even when the operator thinks the machine feels normal.

## Always collect

- CPU total and processor queue;
- available memory and paging activity;
- physical disk latency/queue/throughput;
- DPC and interrupt time;
- top processes by CPU time and working set;
- boot/logon/autostart context;
- a short WPR runtime trace when WPR is available.

## Short WPR trace

Use `scripts/collect-performance.ps1` for a bounded general trace. Keep it short enough to avoid needless ETL bloat.

If WPR is unavailable, ask whether the agent may install official Microsoft tooling or whether the operator will install it manually. Continue independent analysis while awaiting the answer.

## Escalate only when evidence warrants it

Examples:

- high DPC/ISR -> target driver/interrupt analysis;
- storage latency -> correlate with process/file I/O and storage events;
- CPU spikes -> process/thread/stack analysis;
- boot/logon slow -> reboot-based boot trace with explicit approval;
- UI hangs without CPU saturation -> wait-chain, disk, GPU, shell extensions, or ETW-specific investigation.

## Avoid benchmark theater

Synthetic throughput benchmarks are not a substitute for latency analysis. Do not recommend risky cache/acceleration features just to improve benchmark numbers.

## Interpret relative to hardware and workload

A baseline that is technically "within limits" can still be poor for the hardware class. Use current device/vendor expectations and compare the measured bottleneck to what the platform should reasonably deliver.
