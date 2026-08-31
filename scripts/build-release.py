#!/usr/bin/env python3
"""Build deterministic standalone Skill release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "windows-no-bullshit-audit"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
DIST = ROOT / "dist"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"ERROR: {message}")


def load_json(path: Path) -> dict:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def skill_metadata() -> tuple[str, str]:
    path = SKILL_DIR / "SKILL.md"
    if not path.is_file():
        fail(f"missing canonical Skill: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    name = re.search(r"(?m)^name:\s*([^\n]+)$", text)
    version = re.search(r'(?m)^\s{2}version:\s*["\']?([^"\'\n]+)["\']?\s*$', text)
    if not name or not version:
        fail("SKILL.md must contain top-level name and metadata.version")
    return name.group(1).strip(), version.group(1).strip()


def validate_metadata(version: str) -> None:
    required = [
        SKILL_DIR / "SKILL.md",
        ROOT / ".codex-plugin" / "plugin.json",
        ROOT / ".agents" / "plugins" / "marketplace.json",
        ROOT / ".claude-plugin" / "plugin.json",
        ROOT / ".claude-plugin" / "marketplace.json",
        ROOT / "LICENSE",
    ]
    for path in required:
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")

    codex = load_json(ROOT / ".codex-plugin" / "plugin.json")
    claude = load_json(ROOT / ".claude-plugin" / "plugin.json")
    openai_market = load_json(ROOT / ".agents" / "plugins" / "marketplace.json")
    claude_market = load_json(ROOT / ".claude-plugin" / "marketplace.json")

    for label, manifest in (("OpenAI", codex), ("Claude", claude)):
        if manifest.get("name") != SKILL_NAME:
            fail(f"{label} manifest name must be {SKILL_NAME!r}")
        if manifest.get("version") != version:
            fail(f"{label} manifest version {manifest.get('version')!r} != SKILL.md version {version!r}")
        if manifest.get("license") != "MIT":
            fail(f"{label} manifest license must be MIT")

    if codex.get("skills") != "./skills/":
        fail("OpenAI manifest must reference ./skills/")

    openai_plugins = openai_market.get("plugins") or []
    if len(openai_plugins) != 1 or openai_plugins[0].get("name") != SKILL_NAME:
        fail("OpenAI marketplace must expose exactly the canonical plugin")
    source = openai_plugins[0].get("source")
    if source != {"source": "local", "path": "./"}:
        fail("OpenAI marketplace source must point at repository root")

    claude_plugins = claude_market.get("plugins") or []
    if len(claude_plugins) != 1 or claude_plugins[0].get("name") != SKILL_NAME:
        fail("Claude marketplace must expose exactly the canonical plugin")
    if claude_plugins[0].get("source") != "./":
        fail("Claude marketplace source must point at repository root")


def run_skill_validator() -> None:
    validator = SKILL_DIR / "tests" / "validate-package.py"
    if not validator.is_file():
        fail(f"missing package validator: {validator.relative_to(ROOT)}")
    result = subprocess.run([sys.executable, str(validator)], cwd=ROOT, check=False)
    if result.returncode:
        fail("canonical Skill package validation failed")


def iter_files() -> list[tuple[str, Path]]:
    """Return (archive-relative path, source path), sorted for determinism."""
    ignored_names = {"__pycache__", ".DS_Store", "Thumbs.db"}
    # tests/ is authoring infrastructure. Shipping it wastes payload and invites
    # the agent to try running the validator at audit time.
    ignored_dirs = {"tests"}
    entries: list[tuple[str, Path]] = []
    for path in SKILL_DIR.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(SKILL_DIR).parts
        if any(part in ignored_names for part in path.parts):
            continue
        if rel_parts and rel_parts[0] in ignored_dirs:
            continue
        if path.suffix in {".pyc", ".pyo", ".tmp"}:
            continue
        entries.append((path.relative_to(SKILL_DIR).as_posix(), path))
    if not entries:
        fail("canonical Skill directory is empty")

    # MIT requires the notice to travel with copies, and the standalone artifact
    # is a copy.
    license_path = ROOT / "LICENSE"
    if not license_path.is_file():
        fail("missing LICENSE at repository root")
    entries.append(("LICENSE", license_path))

    return sorted(entries, key=lambda e: e[0])


def build_zip(target: Path, entries: list[tuple[str, Path]]) -> None:
    # ZIP_STORED avoids zlib-version-dependent output, making the archive bytes
    # deterministic across Python installations as long as the input bytes match.
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for rel, src in entries:
            arcname = f"{SKILL_NAME}/{rel}"
            info = zipfile.ZipInfo(arcname, FIXED_ZIP_TIME)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            archive.writestr(info, src.read_bytes())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="optional release tag; must equal v<SKILL.md version>")
    args = parser.parse_args()

    name, version = skill_metadata()
    if name != SKILL_NAME:
        fail(f"SKILL.md name {name!r} != canonical directory {SKILL_NAME!r}")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
        fail(f"unsupported version format: {version!r}")
    if args.tag and args.tag != f"v{version}":
        fail(f"release tag {args.tag!r} must be v{version}")

    validate_metadata(version)
    run_skill_validator()
    entries = iter_files()

    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    zip_path = DIST / f"{SKILL_NAME}-{version}.zip"
    skill_path = DIST / f"{SKILL_NAME}-{version}.skill"
    build_zip(zip_path, entries)
    shutil.copyfile(zip_path, skill_path)

    shipped = {rel for rel, _ in entries}
    if "LICENSE" not in shipped:
        fail("LICENSE missing from the standalone artifact")
    if any(rel.startswith("tests/") for rel in shipped):
        fail("tests/ must not ship in the standalone artifact")

    zip_hash = sha256(zip_path)
    skill_hash = sha256(skill_path)
    if zip_hash != skill_hash or zip_path.read_bytes() != skill_path.read_bytes():
        fail(".zip and .skill artifacts are not byte-identical")

    print(f"Version: {version}")
    print(f"Files: {len(entries)}")
    print(f"Built: {zip_path.relative_to(ROOT)}")
    print(f"SHA256: {zip_hash}")
    print(f"Built: {skill_path.relative_to(ROOT)}")
    print(f"SHA256: {skill_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
