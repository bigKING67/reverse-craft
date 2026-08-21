from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .common import bounded_text, home_root, utc_now

TOOLS: dict[str, tuple[str, ...]] = {
    "core": ("git", "file", "strings", "jq", "openssl"),
    "binary": ("gdb", "lldb", "objdump", "radare2", "r2", "ghidraRun"),
    "android": ("adb", "jadx", "apktool", "apksigner", "frida", "objection"),
    "ios": ("codesign", "otool", "lldb", "frida", "objection"),
    "web": ("node", "npm", "codex", "pi"),
    "forensics": ("yara", "tshark", "vol.py", "vol", "exiftool"),
    "firmware": ("binwalk", "unsquashfs", "qemu-system-x86_64", "qemu-system-aarch64"),
    "wireless": ("aircrack-ng", "tshark", "rtl_433", "rtl_sdr"),
}

VERSION_ARGS = {
    "git": ("--version",), "jq": ("--version",), "node": ("--version",), "npm": ("--version",),
    "codex": ("--version",), "pi": ("--version",), "radare2": ("-v",), "r2": ("-v",),
    "adb": ("version",), "jadx": ("--version",), "apktool": ("--version",), "frida": ("--version",),
    "yara": ("--version",), "tshark": ("--version",), "binwalk": ("--help",),
}


def _command_info(name: str, deep: bool) -> dict[str, Any]:
    path = shutil.which(name)
    result: dict[str, Any] = {"available": path is not None, "path": path, "version": None}
    if not path or not deep or name not in VERSION_ARGS:
        return result
    try:
        completed = subprocess.run(
            [path, *VERSION_ARGS[name]], text=True, capture_output=True, timeout=5, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        output = (completed.stdout or completed.stderr).strip().splitlines()
        result["version"] = bounded_text(output[0], 300) if output else None
        result["version_exit_code"] = completed.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["version_error"] = type(exc).__name__
    return result


def _mcp_inventory() -> dict[str, Any]:
    codex = shutil.which("codex")
    if not codex:
        return {"checked": False, "reason": "codex_not_found", "servers": []}
    try:
        completed = subprocess.run(
            [codex, "mcp", "list", "--json"], text=True, capture_output=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"checked": False, "reason": type(exc).__name__, "servers": []}
    if completed.returncode != 0:
        return {"checked": False, "reason": bounded_text(completed.stderr.strip(), 500), "servers": []}
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"checked": False, "reason": "invalid_codex_json", "servers": []}
    entries = payload if isinstance(payload, list) else payload.get("servers", [])
    servers: list[dict[str, Any]] = []
    for entry in entries:
        name = entry.get("name") or entry.get("server_name") or entry.get("id")
        if name in {"js-reverse", "tmwd_browser"}:
            servers.append({"name": name, "enabled": entry.get("enabled", True), "transport": entry.get("transport")})
    return {"checked": True, "reason": None, "servers": servers}


def _browser67_candidates() -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("BROWSER67_HOME"):
        candidates.append(Path(os.environ["BROWSER67_HOME"]).expanduser())
    repo_candidate = Path(__file__).resolve().parents[5] / "browser67"
    candidates.append(repo_candidate)
    candidates.append(Path.home() / "Documents" / "sixseven" / "codeproject" / "browser67")
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in unique:
            unique.append(resolved)
    return unique


def doctor(deep: bool = False, home: str | None = None) -> dict[str, Any]:
    commands = sorted({name for values in TOOLS.values() for name in values})
    tool_data = {name: _command_info(name, deep) for name in commands}
    profiles = {
        profile: {
            "available": [name for name in names if tool_data[name]["available"]],
            "missing": [name for name in names if not tool_data[name]["available"]],
        }
        for profile, names in TOOLS.items()
    }
    mcp = _mcp_inventory()
    browser67_path = next(
        (path for path in _browser67_candidates() if (path / "src" / "mcp" / "js-reverse" / "server.mjs").is_file()),
        None,
    )
    names = {entry["name"] for entry in mcp["servers"] if entry.get("enabled")}
    root = home_root(home)
    return {
        "schema": "reverse-craft.doctor.v1",
        "version": __version__,
        "checked_at": utc_now(),
        "deep": deep,
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "python": platform.python_version()},
        "home": {"path": str(root), "exists": root.exists(), "writable_parent": os.access(root if root.exists() else root.parent, os.W_OK)},
        "profiles": profiles,
        "tools": tool_data,
        "integrations": {
            "codex_mcp": mcp,
            "js_reverse_mcp": "js-reverse" in names,
            "tmwd_browser_mcp": "tmwd_browser" in names,
            "browser67": {"available": browser67_path is not None, "path": str(browser67_path) if browser67_path else None},
        },
    }
