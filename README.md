# Windows No-Bullshit Audit

Deep Windows 11 health, performance, security and hygiene audit. **Evidence first. No cargo-cult fixes. Token-budgeted.**

`windows-no-bullshit-audit` is a skills-only plugin for OpenAI ChatGPT/Codex and Claude Code. Both provider wrappers consume the same canonical Agent Skill under `skills/windows-no-bullshit-audit/`; there is no duplicated implementation and no MCP server.

## Scope

- **Windows 11 client only** (Home, Pro, Enterprise, Education; x64 or ARM64), Windows PowerShell 5.1.
- Health, reliability, storage, drivers, event logs, boot/recovery, power, networking, security, performance, software hygiene and autostart.
- Current Microsoft/OEM/vendor research is part of the method.

## How it stays cheap

A deep audit that exhausts the operator's usage quota halfway through is a failed audit. So the deterministic work lives in PowerShell and only judgement lives in the model.

- The collector **counts, groups, resolves signers and thresholds** the data itself, then emits `TRIAGE.md` / `TRIAGE.json` — roughly 10–30 KB, hard-capped at 60 KB.
- Raw evidence (tens of MB of EVTX, CSV and logs) stays on disk to be **queried**, never loaded. The skill forbids reading it in full.
- The fast pass runs in 1–3 minutes. The 20–60 minute scans (DISM ScanHealth, SFC, CHKDSK, `powercfg /energy`) move to `collect-deep.ps1`, which writes a small pollable status file so triage proceeds in parallel.
- `REPORT.md` is **generated** by `assemble-report.ps1` from append-only `findings/*.json`, instead of being rewritten inside the model on every turn.
- Investigation is budgeted per finding, and anything deferred for budget must be named in the final report.

The digest byte cap is enforced in CI against a real collector run, so it cannot quietly regress.

## Safety philosophy

- **Target Machine Attestation is mandatory and technical.** On a candidate Windows command host, the first Windows target probe is the bundled `scripts/attest-target.ps1`. A known hostname, prior conversation, runtime metadata or the operator saying "yes, this is the PC" cannot substitute for current bundled attestation evidence.
- `CONFIRMED_TARGET` requires both current bundled attestation output and operator confirmation of that returned fingerprint.
- The **installed Skill bundle is the source of truth** for audit scripts. Web access is for current diagnostic research, never for fetching an individual bundled `.ps1` or silently mixing Skill versions.
- In hosted/delegated mode, bundled files are surfaced/exported when the runtime supports it. If it cannot expose bundled files, the fallback is the matching **versioned standalone release artifact**, not a raw GitHub script.
- Every collector except attestation **requires an elevated session** and refuses to run without one. In agentic mode, administrator approval is not proof that the execution broker supplied an elevated token; elevation must be verified before collection is claimed to have started.
- Example/demo requests may invent a realistic user prompt, but must not fabricate target evidence, collector output, Windows events, findings, repairs or verification unless the operator explicitly requested a synthetic simulation.
- Read-only evidence comes before remediation. Risky or non-reversible changes require operator approval. Reboot always requires approval.
- Intentional security deviations are not automatically classified as broken.
- Event IDs are evidence, not diagnoses. Repair success must be independently verified, with the narrowest check that could falsify it.
- `UNKNOWN` is a valid conclusion — provided the next discriminating test is named. The report assembler enforces that.

## Privacy

Digests are meant to be pasted into a hosted chat. `-Redact` pseudonymizes computer name, user names, serial numbers, MAC addresses and profile paths in the digest, while raw on-disk evidence stays diagnostically complete. Dotted-quad values are intentionally not blanket-redacted because a version such as `1.54.0.120` is syntactically indistinguishable from IPv4; the digest does not include network configuration, but event text can still contain IP-like values. Secret scrubbing of command lines runs unconditionally. Crash dumps are inventoried, never copied; servicing logs are copied only when a scan actually reported corruption.

## OpenAI plugin installation from GitHub

Native OpenAI plugin manifest at `.codex-plugin/plugin.json`, repo marketplace at `.agents/plugins/marketplace.json`.

Normal installation:

```bash
codex plugin marketplace add AviBackToBlack/windows-no-bullshit-audit
```

For development/testing, pin the marketplace source to `main` instead:

```bash
codex plugin marketplace add AviBackToBlack/windows-no-bullshit-audit --ref main
```

Where the ChatGPT desktop Plugin Directory supports repo/local marketplaces, select the **Windows No-Bullshit Audit** source and install there. Availability varies by product surface, plan, workspace policy and rollout.

## Claude Code plugin installation from GitHub

```bash
claude plugin marketplace add AviBackToBlack/windows-no-bullshit-audit
claude plugin install windows-no-bullshit-audit@windows-no-bullshit-audit
```

For local development:

```bash
claude --plugin-dir .
```

Plugin skills are namespaced by Claude Code, so this skill is exposed through the plugin namespace.

## Standalone Skill artifacts

Tagged releases provide:

```text
windows-no-bullshit-audit-<version>.zip
windows-no-bullshit-audit-<version>.skill
```

Both contain the canonical `windows-no-bullshit-audit/` Agent Skill directory plus the MIT `LICENSE`, and exclude the `tests/` authoring infrastructure.

For ChatGPT surfaces that expose Skill upload, use **Plugins → Skills → Create → Upload from your computer**. For Claude Code standalone use, extract to `~/.claude/skills/windows-no-bullshit-audit/` (personal) or `.claude/skills/windows-no-bullshit-audit/` (project).

The `.skill` asset is **the same ZIP payload byte-for-byte** with a convenience extension. This repository does **not** claim `.skill` is a formally standardized OpenAI, Anthropic or Agent Skills container.

## Repository layout

```text
.codex-plugin/plugin.json              OpenAI plugin manifest
.agents/plugins/marketplace.json       OpenAI repo marketplace
.claude-plugin/plugin.json             Claude Code plugin manifest
.claude-plugin/marketplace.json        Claude Code marketplace
skills/windows-no-bullshit-audit/      canonical Agent Skill
scripts/build-release.py               deterministic standalone packager
.github/workflows/release.yml          Windows smoke tests + build/release CI
```

## Build and test locally

Python 3 standard library is sufficient for the packager:

```bash
python scripts/build-release.py
python scripts/build-release.py --tag v0.2.2
```

The build validates the Skill, checks manifest identity/version consistency, runs the package validator, and produces deterministic ZIP bytes.

On Windows, exercise the collectors themselves:

```powershell
# every script must parse
Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object {
  $e = $null; $t = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$t, [ref]$e)
  if ($e) { "FAIL $($_.Name): $($e[0].Message)" } else { "OK   $($_.Name)" }
}

# attestation is always the first Windows target probe
.\skills\windows-no-bullshit-audit\scripts\attest-target.ps1

# fast collector, only from a genuinely ELEVATED terminal/execution context
.\skills\windows-no-bullshit-audit\scripts\collect-baseline.ps1 -Depth Fast -NoZip -Redact
```

CI runs the same collector checks on `windows-latest`, plus the digest byte-cap assertion, report-assembler round trip, package invariants and release reproducibility.

## License

MIT. See [LICENSE](LICENSE). The software is provided **AS IS**, without warranty; the license includes the standard limitation of liability.
