#!/usr/bin/env python3
"""Package invariants for the canonical Agent Skill.

Checks naming, frontmatter, resource links and internal consistency. It does not
replace running the PowerShell collectors on real Windows 11 hosts; the Windows
CI job does that.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "SKILL.md"

# Digest budget. The whole point of this skill's rewrite is that triage input
# stays small; if SKILL.md itself bloats, the budget goes with it.
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

errs: list[str] = []
warns: list[str] = []

if not SKILL.is_file():
    print("FAIL")
    print("- SKILL.md missing")
    raise SystemExit(1)

text = SKILL.read_text(encoding="utf-8")

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


name = field("name")
desc = field("description")

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

# Only these top-level frontmatter keys are recognized by both Claude Code and
# Codex. Anything else risks a warning under `claude plugin validate --strict`.
ALLOWED_FM_KEYS = {"name", "description", "license", "compatibility", "allowed-tools", "metadata"}
top_keys = set(re.findall(r"(?m)^([A-Za-z][A-Za-z0-9_-]*):", fm))
for key in sorted(top_keys - ALLOWED_FM_KEYS):
    errs.append(f"unrecognized top-level frontmatter key '{key}' (nest it under metadata:)")

if not re.search(r"(?m)^\s{2}version:\s*[\"']?\d+\.\d+\.\d+", fm):
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

# Reverse check. An unreferenced reference is dead weight that ships in every
# release and is never read - this is how lessons-from-real-audits.md rotted.
mentioned = set(re.findall(r"references/[A-Za-z0-9._-]+\.md", text))
for ref in sorted((ROOT / "references").glob("*.md")):
    if f"references/{ref.name}" not in mentioned:
        errs.append(f"orphaned reference (never mentioned in SKILL.md): references/{ref.name}")

# Scripts must be discoverable too, otherwise the agent never runs them.
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

# The skill must actually tell the agent not to slurp evidence. If these
# disappear in a future edit, the token budget quietly dies with them.
for phrase, why in [
    ("token-discipline.md", "SKILL.md must point at the token discipline reference"),
    ("TRIAGE.md", "SKILL.md must name the digest the agent is supposed to read"),
]:
    if phrase not in text:
        errs.append(f"{why} (missing '{phrase}')")

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
