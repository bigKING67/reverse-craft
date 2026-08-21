#!/usr/bin/env python3
from __future__ import annotations

import json
import py_compile
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "reverse-craft"
LIB = SKILL / "lib"
sys.path.insert(0, str(LIB))

from reverse_craft import __version__  # noqa: E402
from reverse_craft.provenance import audit_references  # noqa: E402

REQUIRED = (
    ".codex/config.toml", ".github/workflows/ci.yml", ".gitignore", "AGENTS.md", "LICENSE",
    "README.md", "THIRD_PARTY_NOTICES.md", "VERSION", "package.json", "pyproject.toml",
    "skills/reverse-craft/SKILL.md", "skills/reverse-craft/VERSION",
    "skills/reverse-craft/agents/openai.yaml", "skills/reverse-craft/scripts/reverse_craft.py",
    "skills/reverse-craft/references/modules.json", "skills/reverse-craft/references/provenance.json",
    "skills/reverse-craft/references/upstream/reverse-skill-routing.json",
    "scripts/run_route_bank.py", "scripts/run_scenario_bank.py", "scripts/run_host_eval.py",
    "scripts/check_browser67_mcp.py",
)
SCHEMAS = ("route", "case", "evidence", "finding", "path", "report")
FORBIDDEN_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "node_modules", "test-results"}


def source_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=True,
    )
    return sorted(ROOT / raw.decode("utf-8") for raw in completed.stdout.split(b"\0") if raw and (ROOT / raw.decode("utf-8")).is_file())


def main() -> int:
    errors: list[str] = []
    files = source_files()
    relative = {path.relative_to(ROOT).as_posix() for path in files}
    for required in REQUIRED:
        if required not in relative:
            errors.append(f"missing required file: {required}")
    for name in SCHEMAS:
        path = f"skills/reverse-craft/schemas/{name}.schema.json"
        if path not in relative:
            errors.append(f"missing schema: {path}")
    skills = sorted(path for path in files if path.name == "SKILL.md")
    if skills != [SKILL / "SKILL.md"]:
        errors.append(f"expected exactly one SKILL.md, found: {[str(path.relative_to(ROOT)) for path in skills]}")
    versions = {
        "root": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "skill": (SKILL / "VERSION").read_text(encoding="utf-8").strip(),
        "package": json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"],
        "runtime": __version__,
    }
    if len(set(versions.values())) != 1:
        errors.append(f"version mismatch: {versions}")
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    if package.get("private") is not True or package.get("pi", {}).get("skills") != ["skills/reverse-craft"]:
        errors.append("package must remain private and expose exactly one Pi skill")
    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    if not skill_text.startswith("---\nname: reverse-craft\ndescription:"):
        errors.append("SKILL.md frontmatter is missing required name/description")
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", skill_text):
        if "://" not in link and not link.startswith("#") and not (SKILL / link).resolve().is_file():
            errors.append(f"broken SKILL.md link: {link}")
    upstream = json.loads((SKILL / "references/upstream/reverse-skill-routing.json").read_text(encoding="utf-8"))
    modules = json.loads((SKILL / "references/modules.json").read_text(encoding="utf-8"))
    expected_ids = {f"R{index}" for index in range(42)}
    if set(upstream.get("routes", {})) != expected_ids or set(upstream.get("priority", [])) != expected_ids:
        errors.append("routing source must contain exactly R0..R41")
    if set(modules.get("routes", {})) != expected_ids:
        errors.append("module map must contain exactly R0..R41")
    for route_id, mapping in modules.get("routes", {}).items():
        reference = SKILL / "references" / mapping["reference"]
        if not reference.is_file():
            errors.append(f"route {route_id} has missing reference: {mapping['reference']}")
    for path in files:
        if path.suffix == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                errors.append(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
        if any(part in FORBIDDEN_PARTS for part in path.parts):
            errors.append(f"forbidden generated path: {path.relative_to(ROOT)}")
    unfinished_tokens = ("TO" + "DO", "FIX" + "ME", "T" + "BD", "PLACE" + "HOLDER")
    searchable = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in files
        if path != Path(__file__).resolve() and path.suffix in {".md", ".py", ".json", ".yaml", ".yml"}
    )
    if any(re.search(rf"\b{token}\b", searchable) for token in unfinished_tokens):
        errors.append("unfinished scaffold marker found")
    if "shell=True" in (SKILL / "lib/reverse_craft/setup_ops.py").read_text(encoding="utf-8"):
        errors.append("setup runtime must not use shell=True")
    for path in sorted((SKILL / "lib").rglob("*.py")) + sorted((SKILL / "scripts").glob("*.py")):
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"compile failed {path.relative_to(ROOT)}: {exc}")
    audit = audit_references()
    if not audit["valid"]:
        errors.append("provenance audit failed")
    result = {
        "schema": "reverse-craft.source-validation.v1",
        "valid": not errors,
        "version": versions["root"],
        "files": len(files),
        "routes": len(upstream["routes"]),
        "schemas": len(SCHEMAS),
        "scenarios": len(list((ROOT / "tests" / "scenarios").glob("*.json"))),
        "route_cases": sum(len(items) for items in json.loads((ROOT / "tests/fixtures/route_seeds.json").read_text(encoding="utf-8"))["routes"].values()),
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
