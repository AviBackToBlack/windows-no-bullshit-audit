#!/usr/bin/env python3
"""Package invariants for the canonical Agent Skill.

Checks naming, frontmatter, resource links, orchestration guardrails and internal
consistency. It does not replace running the PowerShell collectors on real
Windows 11 hosts; the Windows CI job does that.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "SKILL.md"

MAX_SKILL_LINES = 500
MAX_SKILL_BYTES = 24_000
MAX_REFERENCE_BYTES = 12_000

REQUIRED_RESOURCES = [
    "scripts/attest-target.ps1",
    "scripts/collect-baseline.ps1",
    "scripts/collect-deep.ps1",
    "scripts/collect-autoruns.ps1",
    "scripts/collect-performance.ps1",
    "scripts/verify-after-repair.ps1",
    "scripts/assemble-report.ps1",
    "references/target-attestation.md",
    "references/diagnostic-doctrine.md",
    "references/token-discipline.md",
    "assets/audit-state.schema.json",
    "assets/finding-template.json",
]

# These phrases encode release-critical orchestration invariants discovered from
# real ChatGPT Web / Codex failures. Their removal must be an explicit review
# decision, not an accidental edit that still packages green. Checks normalize
# whitespace so ordinary Markdown wrapping cannot break validation.
REQUIRED_SKILL_PHRASES = {
    "first Windows target probe MUST be": "technical attestation must precede Windows audit probes",
    "Operator confirmation cannot substitute for technical attestation": "user confirmation must not replace attestation",
    "Approval is not elevation": "permission must not be confused with an elevated token",
    "installed Skill version": "bundled scripts must stay version-coherent",
    "Never fetch an individual bundled script from the network": "audit scripts must not be replaced from GitHub/web",
    "Demonstrations must not fabricate evidence": "example prompts must not become fake audits",
    "TARGET_CONFIRMATION": "the state machine must retain explicit target confirmation",
    "ELEVATION_VERIFICATION": "the state machine must retain elevation verification",
}

REQUIRED_ATTESTATION_PHRASES = {
    "User confirmation alone can never transition to `CONFIRMED_TARGET`": "attestation reference must forbid verbal-only confirmation",
    "Never fetch an individual bundled `.ps1` from GitHub": "attestation reference must preserve bundled-code provenance",
    "No synthetic evidence as a fallback": "attestation reference must forbid fabricated audit evidence",
}

errs: list[str] = []
warns: list[str] = []


def normalized_ws(value: str) -> str:
    return " ".join(value.split())


if not SKILL.is_file():
    print("FAIL")
    print("- SKILL.md missing")
    raise SystemExit(1)

text = SKILL.read_text(encoding="utf-8")
normalized_text = normalized_ws(text)

# ---------------------------------------------------------------- frontmatter

if not text.startswith("---\n"):
    errs.append("SKILL.md missing YAML frontmatter")
parts = text.split("---\n", 2)
fm = parts[1] if len(parts) >= 3 else ""
if not fm:
    errs.append("SKILL.md malformed frontmatter")


def field(name: str) -> str | None:
    m = re.search(rf"(?m)^{re.escape(name)}:\s*(.+)$", fm)
    return m.group(1).strip() if m else None


def single_line_string_field(name: str) -> str | None:
    """Parse enough YAML scalar syntax to validate portable string fields."""
    raw = field(name)
    if raw is None:
        return None
    if raw.startswith(("[", "{", "|", ">")):
        errs.append(f"{name} must be a single-line string")
        return None
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            errs.append(f"{name} has invalid double-quoted string syntax")
            return None
        if not isinstance(value, str):
            errs.append(f"{name} must be a string")
            return None
        return value
    if raw.startswith("'"):
        if len(raw) < 2 or not raw.endswith("'"):
            errs.append(f"{name} has invalid single-quoted string syntax")
            return None
        return raw[1:-1].replace("''", "'")
    if re.fullmatch(r"(?i:true|false|null|~|[-+]?(?:\d+(?:\.\d*)?|\.\d+))", raw):
        errs.append(f"{name} must be a string")
        return None
    return raw


name = field("name")
desc = field("description")
compat = single_line_string_field("compatibility")

if not name:
    errs.append("missing name")
else:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errs.append(f"invalid name (must be kebab-case): {name}")
    if name != ROOT.name:
        errs.append(f"name {name} != directory {ROOT.name}")
    if len(name) > 64:
        errs.append("name >64 chars")

if not desc:
    errs.append("missing description")
elif len(desc) > 1024:
    errs.append(f"description >1024 chars ({len(desc)})")

if field("compatibility") is not None:
    if compat is not None and not compat.strip():
        errs.append("compatibility must not be empty")
    elif compat is not None and len(compat) > 500:
        errs.append(f"compatibility >500 chars ({len(compat)})")

ALLOWED_FM_KEYS = {"name", "description", "license", "compatibility", "allowed-tools", "metadata"}
top_keys = set(re.findall(r"(?m)^([A-Za-z][A-Za-z0-9_-]*):", fm))
for key in sorted(top_keys - ALLOWED_FM_KEYS):
    errs.append(f"unrecognized top-level frontmatter key '{key}' (nest it under metadata:)")

version_match = re.search(
    r"(?m)^\s{2}version:\s*[\"']?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[\"']?\s*$",
    fm,
)
if not version_match:
    errs.append("metadata.version missing or not semver")

# ------------------------------------------------------------------- budgets

lines = len(text.splitlines())
if lines > MAX_SKILL_LINES:
    errs.append(f"SKILL.md >{MAX_SKILL_LINES} lines ({lines})")
skill_bytes = len(text.encode("utf-8"))
if skill_bytes > MAX_SKILL_BYTES:
    errs.append(f"SKILL.md >{MAX_SKILL_BYTES} bytes ({skill_bytes}) - it is loaded every session")

for ref in sorted((ROOT / "references").glob("*.md")):
    size = ref.stat().st_size
    if size > MAX_REFERENCE_BYTES:
        errs.append(f"{ref.name} >{MAX_REFERENCE_BYTES} bytes ({size})")

# ------------------------------------------------------------------ resources

linked = set(re.findall(r"\]\((references/[^)]+|assets/[^)]+|scripts/[^)]+)\)", text))
for rel in sorted(linked):
    if not (ROOT / rel).exists():
        errs.append(f"SKILL.md links a missing file: {rel}")

for rel in REQUIRED_RESOURCES:
    if not (ROOT / rel).exists():
        errs.append(f"missing required resource: {rel}")

mentioned = set(re.findall(r"references/[A-Za-z0-9._-]+\.md", text))
for ref in sorted((ROOT / "references").glob("*.md")):
    if f"references/{ref.name}" not in mentioned:
        errs.append(f"orphaned reference (never mentioned in SKILL.md): references/{ref.name}")

for script in sorted((ROOT / "scripts").glob("*.ps1")):
    if script.name not in text:
        errs.append(f"orphaned script (never mentioned in SKILL.md): scripts/{script.name}")

# ---------------------------------------------------------------------- JSON

for jf in sorted(ROOT.rglob("*.json")):
    try:
        json.loads(jf.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errs.append(f"invalid JSON in {jf.relative_to(ROOT).as_posix()}: {exc}")

schema_path = ROOT / "assets" / "audit-state.schema.json"
if schema_path.is_file():
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        sid = str(schema.get("$id", ""))
        if "example." in sid or not sid:
            errs.append("audit-state.schema.json has a placeholder or missing $id")
    except json.JSONDecodeError:
        pass

# ------------------------------------------------------------- token hygiene

for phrase, why in [
    ("token-discipline.md", "SKILL.md must point at the token discipline reference"),
    ("TRIAGE.md", "SKILL.md must name the digest the agent is supposed to read"),
]:
    if phrase not in text:
        errs.append(f"{why} (missing '{phrase}')")

# ------------------------------------------------------ orchestration contract

for phrase, why in REQUIRED_SKILL_PHRASES.items():
    if normalized_ws(phrase) not in normalized_text:
        errs.append(f"{why} (missing '{phrase}')")

attestation_path = ROOT / "references" / "target-attestation.md"
if attestation_path.is_file():
    attestation = normalized_ws(attestation_path.read_text(encoding="utf-8"))
    for phrase, why in REQUIRED_ATTESTATION_PHRASES.items():
        if normalized_ws(phrase) not in attestation:
            errs.append(f"{why} (missing '{phrase}')")

quality_path = ROOT / "tests" / "quality-gates.md"
if quality_path.is_file():
    quality = normalized_ws(quality_path.read_text(encoding="utf-8"))
    for phrase in (
        "Confirmation is not attestation",
        "Hosted helper cannot export bundled file",
        "Elevation approval is not elevation",
        "No synthetic end-to-end audit",
        "Installed bundle is authoritative",
    ):
        if normalized_ws(phrase) not in quality:
            errs.append(f"quality-gates.md missing orchestration regression '{phrase}'")

# ------------------------------------------------------------------- verdict

for w in warns:
    print("warning:", w)

if errs:
    print("FAIL")
    for e in errs:
        print("-", e)
    sys.exit(1)

print("OK")
print("SKILL.md lines:", lines, f"({skill_bytes} bytes)")
print("References:", len(list((ROOT / 'references').glob('*.md'))))
print("Scripts:", len(list((ROOT / 'scripts').glob('*.ps1'))))
print("Files:", sum(1 for p in ROOT.rglob("*") if p.is_file()))
