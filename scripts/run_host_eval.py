#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "reverse-craft"
SCHEMA = ROOT / "tests" / "fixtures" / "host-response.schema.json"
PROMPT = """Use $reverse-craft for this read-only planning question. An authorized sandbox task asks you to reverse a browser request signature. No artifact or live browser is available yet. Return exactly one JSON object with these exact values and no Markdown: {\"skill_name\":\"reverse-craft\",\"skill_version\":\"0.1.0\",\"route_id\":\"R3\",\"module_reference\":\"modules/web-api-identity.md\",\"runtime_truth\":\"browser67\",\"first_action\":\"check_browser_health\",\"mutates\":false,\"evidence_chain\":[\"Evidence\",\"Finding\",\"Path\",\"Report\"]}. Do not call tools or modify files."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real Codex and Pi Reverse Craft behavior evaluations")
    parser.add_argument("--host", choices=["all", "codex", "pi"], default="all")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args()


def extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    try:
        value = json.loads(stripped)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("host output does not contain a JSON object")


def validate_payload(value: dict[str, Any]) -> list[str]:
    expected = {
        "skill_name": "reverse-craft",
        "skill_version": "0.1.0",
        "route_id": "R3",
        "module_reference": "modules/web-api-identity.md",
        "runtime_truth": "browser67",
        "first_action": "check_browser_health",
        "mutates": False,
        "evidence_chain": ["Evidence", "Finding", "Path", "Report"],
    }
    errors = [f"{key}: expected {expected_value!r}, got {value.get(key)!r}" for key, expected_value in expected.items() if value.get(key) != expected_value]
    extra = sorted(set(value) - set(expected))
    if extra:
        errors.append(f"unexpected keys: {extra}")
    return errors


def safe_error_tail(value: str) -> str:
    tail = value[-1500:]
    tail = re.sub(r"(?i)(api key provided:\s*)[^.,\s]+", r"\1[REDACTED]", tail)
    tail = re.sub(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._-]+", r"\1[REDACTED]", tail)
    return tail


def run_codex(workspace: Path, timeout: int) -> dict[str, Any]:
    binary = shutil.which("codex")
    if not binary:
        return {"host": "codex", "status": "missing", "valid": False}
    skill_target = workspace / ".agents" / "skills" / "reverse-craft"
    skill_target.parent.mkdir(parents=True)
    try:
        skill_target.symlink_to(SKILL, target_is_directory=True)
    except OSError:
        shutil.copytree(SKILL, skill_target)
    output = workspace / "codex-output.json"
    codex_env = {**os.environ, "NO_COLOR": "1"}
    # A generic OPENAI_API_KEY can override Codex's own authenticated account.
    codex_env.pop("OPENAI_API_KEY", None)
    completed = subprocess.run(
        [
            binary, "exec", "--ephemeral", "--ignore-rules", "--sandbox", "read-only",
            "--disable", "hooks", "--disable", "memories", "--disable", "plugins", "--disable", "apps",
            "--skip-git-repo-check", "-C", str(workspace), "--output-schema", str(SCHEMA),
            "--output-last-message", str(output), PROMPT,
        ],
        text=True, capture_output=True, timeout=timeout, check=False,
        env=codex_env,
    )
    raw = output.read_text(encoding="utf-8") if output.is_file() else completed.stdout
    try:
        payload = extract_json(raw)
        errors = validate_payload(payload)
    except Exception as exc:
        payload = None
        errors = [f"{type(exc).__name__}: {exc}"]
    return {
        "host": "codex", "status": "passed" if completed.returncode == 0 and not errors else "failed",
        "valid": completed.returncode == 0 and not errors, "exit_code": completed.returncode,
        "version": subprocess.run([binary, "--version"], text=True, capture_output=True, timeout=10, check=False).stdout.strip(),
        "payload": payload, "errors": errors,
        "stderr_tail": safe_error_tail(completed.stderr) if completed.returncode else "",
    }


def run_pi(workspace: Path, timeout: int) -> dict[str, Any]:
    binary = shutil.which("pi")
    if not binary:
        return {"host": "pi", "status": "missing", "valid": False}
    session_dir = workspace / "pi-sessions"
    session_dir.mkdir()
    env = {**os.environ, "PI_CODING_AGENT_SESSION_DIR": str(session_dir), "NO_COLOR": "1"}
    completed = subprocess.run(
        [
            binary, "--print", "--no-session", "--no-extensions", "--no-context-files", "--no-tools",
            "--skill", str(SKILL), PROMPT,
        ],
        cwd=workspace, text=True, capture_output=True, timeout=timeout, check=False, env=env,
    )
    try:
        payload = extract_json(completed.stdout)
        errors = validate_payload(payload)
    except Exception as exc:
        payload = None
        errors = [f"{type(exc).__name__}: {exc}"]
    return {
        "host": "pi", "status": "passed" if completed.returncode == 0 and not errors else "failed",
        "valid": completed.returncode == 0 and not errors, "exit_code": completed.returncode,
        "version": subprocess.run([binary, "--version"], text=True, capture_output=True, timeout=10, check=False).stdout.strip(),
        "payload": payload, "errors": errors,
        "stderr_tail": safe_error_tail(completed.stderr) if completed.returncode else "",
    }


def main() -> int:
    args = parse_args()
    requested = ["codex", "pi"] if args.host == "all" else [args.host]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="reverse-craft-host-eval-") as raw:
        root = Path(raw)
        for host in requested:
            workspace = root / host
            workspace.mkdir()
            try:
                result = run_codex(workspace, args.timeout) if host == "codex" else run_pi(workspace, args.timeout)
            except subprocess.TimeoutExpired:
                result = {"host": host, "status": "timeout", "valid": False, "errors": [f"timeout after {args.timeout}s"]}
            results.append(result)
    missing = [item["host"] for item in results if item["status"] == "missing"]
    valid = all(item["valid"] or (args.allow_missing and item["status"] == "missing") for item in results)
    payload = {
        "schema": "reverse-craft.host-eval.v1", "valid": valid, "requested": requested,
        "missing": missing, "results": results,
        "isolation": {"codex": "ephemeral, ignore rules, hooks/memories/plugins/apps disabled, read-only sandbox", "pi": "no session/extensions/context/tools; temporary session directory"},
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).expanduser().resolve().write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
