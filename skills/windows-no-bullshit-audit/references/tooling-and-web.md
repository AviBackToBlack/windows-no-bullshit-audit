# Tooling and Web Research

## Missing tool

Ask one compact question, batched with other work, never as a turn of its own:

> I need <tool> for <reason>. I can install it from an official
> Microsoft/vendor source, or you can install it manually and give me the path.
> Which do you prefer?

Acquisition order: already installed, then Microsoft Store / WinGet / official
Microsoft package, then official OEM/vendor package, then manual operator
installation from the official source.

Never use an unofficial mirror. If automatic official installation fails, give
manual official instructions.

## Optional tools

- **Sysinternals Autoruns** - deep autostart, service, driver, task and shell
  extension archaeology. Use `autorunsc` with XML output via
  `scripts/collect-autoruns.ps1`.
- **Windows Performance Recorder / Analyzer** - bounded ETW traces, and WPA when
  stack or timeline analysis is genuinely needed.
- **Vendor diagnostics** - only when local evidence has already identified a
  specific component and the official utility adds telemetry Windows does not
  expose (firmware, SMART detail, UPS state).

## Web research: when

Research when the conclusion depends on current facts:

- current Windows behaviour or documented design;
- driver, firmware or software versions;
- vendor support status and replacement products;
- known issues and advisories;
- device-specific maintenance guidance;
- current security recommendations.

Never claim a current version, support status, firmware recommendation or known
issue from model memory when web access exists.

## Web research: how much

Research is not free either. Budget it.

- Default: **at most 2 searches per finding**, and read at most one primary
  source per claim.
- Search the exact identifier: exact model or device ID, exact driver/software
  version, exact Windows build. Vague searches return vague tokens.
- Cache verdicts in `research-cache.json` keyed by component and version. Never
  research the same driver twice in one audit.
- Do not fetch a whole vendor page when the release-notes fragment answers the
  question.

## Source priority

1. Microsoft official documentation and support
2. OEM / hardware / software vendor official sources
3. official project documentation and repositories
4. reputable technical sources
5. community reports, as supporting evidence only

Keep `LOCAL EVIDENCE`, `WEB EVIDENCE` and `INFERENCE` conceptually separate, and
cite sources for current-version and support claims in the report.

## Offline

If there is no internet access, continue local collection but mark
current-version, support-status and known-issue checks as `INCOMPLETE`. Do not
present old model memory as current research.
