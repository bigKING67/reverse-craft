from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from test_support import ROOT  # noqa: F401

from reverse_craft.case_store import (
    add_evidence,
    add_finding,
    add_path,
    case_dir,
    case_status,
    init_case,
    render_report,
    seal_case,
    validate_case,
)
from reverse_craft.common import FileLock, ReverseCraftError, pid_is_alive


class CaseStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.artifact = self.root / "sample.bin"
        self.artifact.write_bytes(b"reverse-craft-fixture\x00\x01")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def new_case(self) -> str:
        return init_case("Fixture case", "offline fixture", "R0", str(self.home))["case"]["id"]

    def add_graph(self, case_id: str) -> tuple[str, str, str]:
        evidence = add_evidence(case_id, str(self.artifact), "binary", home=str(self.home))["evidence"]
        finding = add_finding(
            case_id,
            "Controlled fixture branch",
            "high",
            "confirmed",
            [evidence["id"]],
            reproduction="Replay the local fixture",
            confidence="high",
            home=str(self.home),
        )["finding"]
        path = add_path(
            case_id,
            "Input to fixture branch",
            [finding["id"]],
            status="confirmed",
            validation="Clean replay succeeds",
            home=str(self.home),
        )["path"]
        return evidence["id"], finding["id"], path["id"]

    def test_full_lifecycle_and_seal(self) -> None:
        case_id = self.new_case()
        evidence_id, finding_id, path_id = self.add_graph(case_id)
        report = render_report(case_id, home=str(self.home))
        self.assertTrue(Path(report["path"]).is_file())
        self.assertTrue(validate_case(case_id, str(self.home))["valid"])
        sealed = seal_case(case_id, str(self.home))
        self.assertTrue(sealed["valid"])
        status = case_status(case_id, str(self.home))
        self.assertEqual({"evidence": 1, "findings": 1, "paths": 1, "events": 6}, status["counts"])
        self.assertEqual("sealed", status["case"]["state"])
        self.assertEqual((evidence_id, finding_id, path_id), ("E-0001", "F-0001", "P-0001"))
        with self.assertRaises(ReverseCraftError):
            add_evidence(case_id, str(self.artifact), "binary", home=str(self.home))

    def test_tampered_artifact_is_detected(self) -> None:
        case_id = self.new_case()
        self.add_graph(case_id)
        directory = case_dir(case_id, str(self.home))
        stored = next((directory / "artifacts").iterdir())
        stored.write_bytes(b"tampered")
        result = validate_case(case_id, str(self.home))
        self.assertFalse(result["valid"])
        self.assertTrue(any("evidence" in error and "mismatch" in error for error in result["errors"]))

    def test_tampered_event_chain_is_detected(self) -> None:
        case_id = self.new_case()
        directory = case_dir(case_id, str(self.home))
        events_path = directory / "events.ndjson"
        event = json.loads(events_path.read_text(encoding="utf-8"))
        event["data"]["id"] = "changed"
        events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        result = validate_case(case_id, str(self.home))
        self.assertFalse(result["valid"])
        self.assertIn("event hash mismatch at 1", result["errors"])

    def test_external_evidence_fixity(self) -> None:
        case_id = self.new_case()
        add_evidence(case_id, str(self.artifact), "binary", external=True, home=str(self.home))
        self.assertTrue(validate_case(case_id, str(self.home))["valid"])
        self.artifact.write_bytes(b"changed")
        self.assertFalse(validate_case(case_id, str(self.home))["valid"])

    def test_finding_requires_known_evidence(self) -> None:
        case_id = self.new_case()
        with self.assertRaises(ReverseCraftError):
            add_finding(case_id, "bad", "high", "confirmed", ["E-9999"], confidence="high", home=str(self.home))
        with self.assertRaises(ReverseCraftError):
            add_finding(case_id, "bad", "high", "confirmed", [], home=str(self.home))

    def test_path_rejects_unknown_or_refuted_finding(self) -> None:
        case_id = self.new_case()
        with self.assertRaises(ReverseCraftError):
            add_path(case_id, "bad", ["F-9999"], home=str(self.home))
        finding = add_finding(case_id, "refuted", "info", "refuted", [], home=str(self.home))["finding"]
        with self.assertRaises(ReverseCraftError):
            add_path(case_id, "bad", [finding["id"]], status="supported", home=str(self.home))

    def test_case_id_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(ReverseCraftError):
            case_dir("../outside", str(self.home))

    def test_invalid_route_is_rejected(self) -> None:
        with self.assertRaises(ReverseCraftError):
            init_case("bad route", "offline fixture", "R99", str(self.home))

    def test_concurrent_evidence_ids_are_unique(self) -> None:
        case_id = self.new_case()
        files: list[Path] = []
        for index in range(6):
            path = self.root / f"sample-{index}.bin"
            path.write_bytes(f"fixture-{index}".encode())
            files.append(path)
        errors: list[Exception] = []

        def add(path: Path) -> None:
            try:
                add_evidence(case_id, str(path), "binary", home=str(self.home))
            except Exception as exc:  # test thread collects failures
                errors.append(exc)

        threads = [threading.Thread(target=add, args=(path,)) for path in files]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        snapshot = json.loads((case_dir(case_id, str(self.home)) / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(6, len(snapshot["items"]))
        self.assertEqual(6, len({item["id"] for item in snapshot["items"]}))

    @mock.patch("reverse_craft.common.os.kill")
    def test_windows_pid_probe_never_uses_os_kill(self, kill: mock.Mock) -> None:
        with mock.patch("reverse_craft.common.os.name", "nt"):
            self.assertIsNone(pid_is_alive(1234))
        kill.assert_not_called()

    def test_permission_error_for_existing_lock_is_treated_as_contention(self) -> None:
        lock_path = self.root / "contended.lock"
        lock_path.write_text("{}\n", encoding="utf-8")
        with mock.patch("reverse_craft.common.os.open", side_effect=PermissionError("busy")):
            with self.assertRaisesRegex(ReverseCraftError, "timed out waiting for lock"):
                with FileLock(lock_path, timeout=0.01):
                    self.fail("an inaccessible existing lock must not be acquired")


if __name__ == "__main__":
    unittest.main()
