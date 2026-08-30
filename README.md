# Windows No-Bullshit Audit

Deep Windows 11 health, performance, security and hygiene audit. **Evidence first. No cargo-cult fixes.**

`windows-no-bullshit-audit` is a skills-only plugin for OpenAI ChatGPT/Codex and Claude Code. Both provider wrappers consume the same canonical Agent Skill under `skills/windows-no-bullshit-audit/`; there is no duplicated OpenAI/Claude implementation and no MCP server.

## Scope

- **Windows 11 client only** for now (Home, Pro, Enterprise, Education; x64 or ARM64).
- Health, reliability, storage, drivers, event logs, boot/recovery, power, networking, security, performance, software hygiene, and autostart.
- Current Microsoft/OEM/vendor research is part of the diagnostic method when needed.

## Safety philosophy

The audit is evidence-driven, not a collection of folklore fixes. In particular:

- **Target Machine Attestation is mandatory.** Command access does not prove that commands are running on the Windows PC the operator intended to audit. A sandbox, helper VM, container, or cloud runtime must never be mistaken for the target.
- Read-only evidence comes before remediation.
- Safe/reversible actions may be autonomous where the runtime permits; risky or non-reversible changes require operator approval.
- Reboot always requires explicit approval.
- Before mutation-capable phases, important work must be saved/closed or explicitly accepted at risk.
- Intentional security deviations are not automatically classified as broken.
- Event IDs are evidence, not diagnoses.
- Repair success must be independently verified.
- `UNKNOWN` is a valid conclusion when the evidence is insufficient.

See the canonical skill for the complete methodology and permission model.

## OpenAI plugin installation from GitHub

This repository contains the native OpenAI plugin manifest at `.codex-plugin/plugin.json` and a repo marketplace at `.agents/plugins/marketplace.json`.

Add the GitHub marketplace with Codex CLI:

```bash
codex plugin marketplace add AviBackToBlack/windows-no-bullshit-audit
```

To pin the marketplace source to `main` while testing:

```bash
codex plugin marketplace add AviBackToBlack/windows-no-bullshit-audit --ref main
```

Where the ChatGPT desktop Plugin Directory supports repo/local marketplaces, select the **Windows No-Bullshit Audit** source and install the plugin there. Availability can vary by product surface, plan, workspace policy, and rollout.

## Claude Code plugin installation from GitHub

This repository contains the native Claude Code plugin manifest and marketplace metadata under `.claude-plugin/`.

```bash
claude plugin marketplace add AviBackToBlack/windows-no-bullshit-audit
claude plugin install windows-no-bullshit-audit@windows-no-bullshit-audit
```

For local development, Claude Code can also load the repository directly:

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

Both contain only the canonical `windows-no-bullshit-audit/` Agent Skill directory, not the plugin/CI wrappers.

For ChatGPT surfaces that expose Skill upload, use **Plugins → Skills → Create → Upload from your computer** and upload the ZIP-compatible skill package. Skill availability and upload permissions depend on the account/workspace.

For Claude Code standalone use, extract/copy the `windows-no-bullshit-audit/` directory to `~/.claude/skills/windows-no-bullshit-audit/` (personal) or `.claude/skills/windows-no-bullshit-audit/` (project).

The `.skill` release asset is intentionally **the same ZIP-compatible payload byte-for-byte** as the `.zip` asset, with a convenience extension. This repository does **not** claim that `.skill` is a formally standardized OpenAI, Anthropic, or Agent Skills archive container.

## Repository layout

```text
.codex-plugin/plugin.json              OpenAI plugin manifest
.agents/plugins/marketplace.json       OpenAI repo marketplace
.claude-plugin/plugin.json             Claude Code plugin manifest
.claude-plugin/marketplace.json        Claude Code marketplace
skills/windows-no-bullshit-audit/      canonical Agent Skill
scripts/build-release.py               deterministic standalone packager
.github/workflows/release.yml          minimal build/release CI
```

## Build locally

Python 3 and the standard library are sufficient:

```bash
python scripts/build-release.py
```

Artifacts are written to `dist/`. The build checks the canonical Skill, verifies OpenAI/Claude manifest identity/version consistency, runs the bundled package validator, and produces deterministic ZIP bytes with normalized ordering and metadata.

For a release-tag consistency check:

```bash
python scripts/build-release.py --tag v0.1.1
```

## License

MIT. See [LICENSE](LICENSE). The software is provided **AS IS**, without warranty; the license includes the standard limitation of liability.
