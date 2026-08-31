# Security Policy

## Security model

Windows No-Bullshit Audit is **not a sandbox**. The canonical Skill contains
instructions and PowerShell collectors intended to inspect a Windows 11 client;
some collectors are designed to run elevated. Installing or running a modified
copy therefore means trusting that copy's Skill instructions and scripts.

The project deliberately separates read-only evidence collection from repair:
risky or non-reversible changes, and reboots, require explicit operator approval.
Target attestation must also happen before a machine is treated as the audit
target.

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** (Security → "Report a
vulnerability" on the repository) rather than a public issue. If private
reporting is unavailable, contact the maintainer using the contact methods on
[@AviBackToBlack](https://github.com/AviBackToBlack) and avoid publishing exploit
details or sensitive audit evidence.

Include:

- affected Skill/plugin/release version or commit SHA;
- reproduction or proof of concept;
- expected vs actual security boundary;
- the minimum sanitized evidence needed to demonstrate impact.

## In scope

Examples of reports we want include:

- collector or packaging behavior that enables unintended command execution;
- a path traversal or unsafe write outside the explicitly selected output area;
- bypass of the documented approval boundary for risky/non-reversible repair or reboot;
- target-attestation failure that can cause helper/sandbox evidence to be treated as the real target in a security-relevant way;
- release/package construction that can substitute files outside the canonical Skill payload or produce materially different `.zip` and `.skill` payloads;
- a redaction/privacy failure that exposes data the documented `-Redact` contract says should be pseudonymized or removed;
- workflow/plugin supply-chain behavior that grants materially broader permissions than documented.

## Out of scope

- Windows, PowerShell, GitHub, OpenAI, Claude, or third-party platform vulnerabilities
  that are not caused by this repository;
- information deliberately retained by the documented audit contract (for example,
  arbitrary event text may still contain IP-like dotted-quad values);
- the expected read access of an administrator who intentionally runs an elevated
  diagnostic collector;
- findings that are diagnostically wrong but do not cross a security/privacy
  boundary — use the Audit accuracy issue form instead.
