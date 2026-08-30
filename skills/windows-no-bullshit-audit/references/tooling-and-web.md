# Tooling and Web Research

## Tool installation workflow

When a required tool is missing, ask one compact question:

> I need <tool> for <reason>. I can install it from an official Microsoft/vendor source, or you can install it manually and tell me the path. Which do you prefer?

Continue independent audit work while awaiting the answer.

Preferred acquisition order:

1. already installed tool;
2. Microsoft Store / WinGet / official Microsoft package;
3. official OEM/vendor package;
4. manual operator installation from the official source.

Do not use unofficial mirrors.

## Recommended optional tools

### Sysinternals Autoruns

Use for deep autostart/service/driver/task/shell-extension archaeology. Prefer command-line `Autorunsc` and XML output.

### Windows Performance Recorder / Analyzer

Use WPR for bounded ETW traces. Use WPA when deeper stack/timeline analysis is needed.

### Vendor diagnostics

Use only when local evidence identifies a specific hardware/software component and the official utility adds relevant telemetry (firmware, SMART, UPS state, etc.).

## Web research rules

Search current sources for:

- exact model/device ID when support or firmware matters;
- exact installed software/driver version;
- exact Windows build when behavior may be build-specific;
- official release notes/advisories;
- replacement software for discontinued products;
- current supported OS/architecture.

Prefer primary sources. Cite current-version/support claims in the final report.

## Offline behavior

If internet access is unavailable, continue local evidence collection but mark current-version/support/known-issue checks as `INCOMPLETE`. Do not substitute old model memory as if it were current research.
