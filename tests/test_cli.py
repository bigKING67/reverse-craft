from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_support import ROOT

CLI = ROOT / "skills" / "reverse-craft" / "scripts" / "reverse_craft.py"


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(CLI), *args], text=True, capture_output=True, timeout=20, check=False)

    def test_version(self) -> None:
        completed = self.run_cli("--version")
        self.assertEqual(0, completed.returncode)
        self.assertEqual("0.1.0", completed.stdout.strip())

    def test_route_json(self) -> None:
        completed = self.run_cli("route", "--hint", "JS reverse request signature", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("R3", json.loads(completed.stdout)["primary"]["id"])

    def test_invalid_case_returns_structured_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            completed = self.run_cli("case", "status", "--case", "../escape", "--home", raw)
        self.assertEqual(2, completed.returncode)
        self.assertEqual("reverse-craft.error.v1", json.loads(completed.stderr)["schema"])


if __name__ == "__main__":
    unittest.main()

