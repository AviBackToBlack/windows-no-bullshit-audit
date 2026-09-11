# AGENTS.md

Repository-wide instructions for coding agents and automation working on Windows No-Bullshit Audit.

## Project intent

This repository ships a Windows auditing skill/plugin and its supporting PowerShell/Python tooling. Preserve diagnostic correctness, operator safety, redaction behavior, deterministic packaging, and compatibility with the documented Windows/PowerShell target environments.

## Existing plugin-specific guidance

The `.agents/`, `.claude-plugin/`, and `.codex-plugin/` trees contain tool/plugin packaging metadata and platform-specific integration. Treat those as implementation-specific layers; repository-wide engineering and safety rules live here.

## Development

- Run the Windows validation/build workflow before proposing changes.
- Preserve Windows PowerShell 5.1 compatibility where the project claims it.
- Keep digest/triage size budgets and redaction guarantees enforced by tests.
- Keep plugin manifests and release artifacts deterministic.
- Add regression coverage for collector/report/packaging fixes.

## Safety and supply chain

- Never weaken redaction, safety checks, CI, dependency review, code scanning, or repository protections merely to make a change pass.
- Do not commit credentials, private machine inventories, real audit outputs, or sensitive user data.
- Keep GitHub Actions dependencies pinned to full commit SHAs with readable version comments.
- Release artifacts must come from the governed release workflow; published assets are not manually replaced.

## Documentation

Update README, skill/plugin metadata, and contribution documentation when user-facing behavior, supported environments, installation, artifact formats, or safety guarantees change.
