# windows-no-bullshit-audit

> Deep Windows 11 health, performance, security and hygiene audit. Evidence first. No cargo-cult fixes.

Version 0.1.1. This is an Agent Skills-format package with a required `SKILL.md`, PowerShell collectors, focused diagnostic references, report/state templates, and quality gates.

## Scope

- Windows 11 client editions only, x64 and ARM64.
- Designed to adapt to two execution styles:
  - local/agentic execution only after the actual Windows target is attested and confirmed;
  - delegated execution when the agent runtime is a sandbox, helper VM, cloud runtime, or otherwise cannot execute on the intended target.
- A mandatory Target Machine Attestation gate prevents the skill from accidentally auditing its own sandbox instead of the operator's PC.
- Internet research is part of the method for current Microsoft/OEM/vendor facts.

## Install / import

This directory is the canonical provider-neutral Agent Skill. Install it through the surrounding plugin repository, or copy/upload this skill directory through a runtime that supports Agent Skills.

The skill directory name matches the `name` in `SKILL.md`.

## Safety model

The bundled collectors are evidence collectors, not repair scripts. `scripts/attest-target.ps1` is the minimal first probe used to identify the candidate target before broad collection. Persistent Windows changes, cleanup, tool installation, and reboot require the approval policy defined in the skill.

## Package QA

`tests/validate-package.py` checks the basic Agent Skills naming/frontmatter/resource invariants for this package. It does not replace executing the PowerShell collectors on representative Windows 11 x64/ARM64 test machines.
