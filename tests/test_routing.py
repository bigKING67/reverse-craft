from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from test_support import ROOT, route


class RoutingTests(unittest.TestCase):
    def test_all_curated_routes(self) -> None:
        bank = json.loads((ROOT / "tests" / "fixtures" / "route_seeds.json").read_text(encoding="utf-8"))
        self.assertEqual(42, len(bank["routes"]))
        self.assertGreaterEqual(sum(len(items) for items in bank["routes"].values()), 220)
        for expected, hints in bank["routes"].items():
            for hint in hints:
                with self.subTest(route=expected, hint=hint):
                    self.assertEqual(expected, route(hint)["primary"]["id"])

    def test_fallback(self) -> None:
        result = route("understand this opaque artifact")
        self.assertEqual("R0", result["primary"]["id"])
        self.assertEqual(42, result["routing_source"]["routes"])

    def test_exclusion_rules(self) -> None:
        self.assertEqual("R14", route("LLM prompt jailbreak")["primary"]["id"])
        self.assertEqual("R2", route("iOS iPhone jailbreak")["primary"]["id"])
        self.assertEqual("R37", route("OAuth2 OIDC single sign-on")["primary"]["id"])
        self.assertEqual("R12", route("OAuth API authorization")["primary"]["id"])
        self.assertEqual("R17", route("CTF pwn ROP challenge")["primary"]["id"])

    def test_artifact_magic_is_read_only_hint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            artifact = Path(raw) / "opaque.bin"
            artifact.write_bytes(b"\x7fELF" + b"\x00" * 60)
            result = route("inspect artifact", str(artifact))
            self.assertEqual("R6", result["primary"]["id"])
            self.assertEqual("ELF binary", result["artifact"]["magic"])
            self.assertEqual(64, result["artifact"]["size"])

    def test_missing_artifact_fails(self) -> None:
        from reverse_craft.common import ReverseCraftError

        with self.assertRaises(ReverseCraftError):
            route("inspect", "/definitely/missing/reverse-craft-artifact")


if __name__ == "__main__":
    unittest.main()

