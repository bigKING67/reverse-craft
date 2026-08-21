from __future__ import annotations

import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .common import (
    FileLock,
    ReverseCraftError,
    atomic_write_bytes,
    atomic_write_json,
    canonical_json,
    home_root,
    load_json,
    safe_component,
    sha256_bytes,
    sha256_file,
    slugify,
    utc_now,
)

SNAPSHOTS = ("case.json", "evidence.json", "findings.json", "paths.json")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"hypothesis", "supported", "confirmed", "refuted"}
CONFIDENCES = {"low", "medium", "high"}
PATH_STATUSES = {"hypothesis", "supported", "confirmed", "refuted"}
ROUTE_IDS = {f"R{index}" for index in range(42)}


def runs_root(home: str | None = None) -> Path:
    return home_root(home) / "runs"


def case_dir(case_id: str, home: str | None = None) -> Path:
    safe_component(case_id, field="case id")
    root = runs_root(home)
    target = (root / case_id).resolve()
    if target.parent != root.resolve():
        raise ReverseCraftError("case path escapes run root")
    return target


def _empty_collection(schema: str) -> dict[str, Any]:
    return {"schema": schema, "items": []}


def _load_case(case_id: str, home: str | None = None) -> tuple[Path, dict[str, Any]]:
    directory = case_dir(case_id, home)
    case = load_json(directory / "case.json")
    if case.get("id") != case_id:
        raise ReverseCraftError(f"case identity mismatch in {directory / 'case.json'}")
    return directory, case


def _require_open(case: dict[str, Any]) -> None:
    if case.get("state") != "open":
        raise ReverseCraftError(f"case is {case.get('state')}; mutation is not allowed")


def _next_id(items: Iterable[dict[str, Any]], prefix: str) -> str:
    maximum = 0
    for item in items:
        raw = str(item.get("id", ""))
        if raw.startswith(prefix + "-"):
            try:
                maximum = max(maximum, int(raw.split("-", 1)[1]))
            except ValueError:
                continue
    return f"{prefix}-{maximum + 1:04d}"


def _read_events(directory: Path) -> list[dict[str, Any]]:
    path = directory / "events.ndjson"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReverseCraftError(f"invalid event JSON at line {line_no}: {exc}") from exc
            events.append(event)
    return events


def _event_material(seq: int, at: str, event_type: str, data: Any, prev_hash: str | None) -> dict[str, Any]:
    return {"seq": seq, "at": at, "type": event_type, "data": data, "prev_hash": prev_hash}


def _append_event(directory: Path, event_type: str, data: Any) -> dict[str, Any]:
    events = _read_events(directory)
    prev_hash = events[-1]["event_hash"] if events else None
    material = _event_material(len(events) + 1, utc_now(), event_type, data, prev_hash)
    event = {**material, "event_hash": sha256_bytes(canonical_json(material))}
    path = directory / "events.ndjson"
    with path.open("ab") as handle:
        handle.write(canonical_json(event) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    return event


def init_case(title: str, scope: str, route_id: str | None = None, home: str | None = None) -> dict[str, Any]:
    if not title.strip() or not scope.strip():
        raise ReverseCraftError("title and scope must not be empty")
    if route_id is not None and route_id not in ROUTE_IDS:
        raise ReverseCraftError("route id must be R0..R41")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_id = f"{timestamp}-{slugify(title)}-{secrets.token_hex(2)}"
    directory = case_dir(case_id, home)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "artifacts").mkdir()
    (directory / "reports").mkdir()
    case = {
        "schema": "reverse-craft.case.v1",
        "id": case_id,
        "title": title.strip(),
        "scope": scope.strip(),
        "route_id": route_id,
        "state": "open",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "sealed_at": None,
    }
    atomic_write_json(directory / "case.json", case)
    atomic_write_json(directory / "evidence.json", _empty_collection("reverse-craft.evidence.v1"))
    atomic_write_json(directory / "findings.json", _empty_collection("reverse-craft.findings.v1"))
    atomic_write_json(directory / "paths.json", _empty_collection("reverse-craft.paths.v1"))
    (directory / "events.ndjson").touch(mode=0o600)
    _append_event(directory, "case.initialized", {"id": case_id, "route_id": route_id})
    return {"schema": "reverse-craft.case-init.v1", "case": case, "directory": str(directory)}


def case_status(case_id: str, home: str | None = None) -> dict[str, Any]:
    directory, case = _load_case(case_id, home)
    evidence = load_json(directory / "evidence.json")["items"]
    findings = load_json(directory / "findings.json")["items"]
    paths = load_json(directory / "paths.json")["items"]
    return {
        "schema": "reverse-craft.case-status.v1",
        "case": case,
        "directory": str(directory),
        "counts": {"evidence": len(evidence), "findings": len(findings), "paths": len(paths), "events": len(_read_events(directory))},
        "sealed": (directory / "seal.json").exists(),
    }


def add_evidence(
    case_id: str,
    file_path: str,
    kind: str,
    note: str | None = None,
    external: bool = False,
    source: str | None = None,
    home: str | None = None,
) -> dict[str, Any]:
    source_path = Path(file_path).expanduser().resolve()
    if not source_path.is_file():
        raise ReverseCraftError(f"evidence file not found or not regular: {source_path}")
    if not kind.strip():
        raise ReverseCraftError("evidence kind must not be empty")
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        collection = load_json(directory / "evidence.json")
        evidence_id = _next_id(collection["items"], "E")
        source_stat = source_path.stat()
        digest = sha256_file(source_path)
        stored_path: str | None = None
        if not external:
            name = re_safe_filename(source_path.name)
            destination = directory / "artifacts" / f"{evidence_id}-{name}"
            temp = destination.with_name(f".{destination.name}.{secrets.token_hex(4)}.tmp")
            try:
                shutil.copyfile(source_path, temp)
                if temp.stat().st_size != source_stat.st_size or sha256_file(temp) != digest:
                    raise ReverseCraftError("evidence changed or copy verification failed")
                os.replace(temp, destination)
            finally:
                temp.unlink(missing_ok=True)
            stored_path = str(destination.relative_to(directory))
        item = {
            "id": evidence_id,
            "kind": kind.strip(),
            "source": source or str(source_path),
            "acquisition": "external-reference" if external else "verified-copy",
            "observed_at": utc_now(),
            "size": source_stat.st_size,
            "sha256": digest,
            "stored_path": stored_path,
            "external_path": str(source_path) if external else None,
            "note": note,
        }
        collection["items"].append(item)
        atomic_write_json(directory / "evidence.json", collection)
        _touch_case(directory, case)
        _append_event(directory, "evidence.added", {"id": evidence_id, "sha256": digest, "size": source_stat.st_size})
    return {"schema": "reverse-craft.evidence-add.v1", "case_id": case_id, "evidence": item}


def re_safe_filename(name: str) -> str:
    cleaned = "".join(character if character.isalnum() or character in ".-_" else "_" for character in name)
    cleaned = cleaned.strip(".")[:120]
    return cleaned or "artifact.bin"


def _touch_case(directory: Path, case: dict[str, Any]) -> None:
    case["updated_at"] = utc_now()
    atomic_write_json(directory / "case.json", case)


def add_finding(
    case_id: str,
    title: str,
    severity: str,
    status: str,
    evidence_ids: list[str],
    statement: str | None = None,
    reproduction: str | None = None,
    confidence: str = "medium",
    home: str | None = None,
) -> dict[str, Any]:
    if severity not in SEVERITIES:
        raise ReverseCraftError(f"severity must be one of {sorted(SEVERITIES)}")
    if status not in FINDING_STATUSES:
        raise ReverseCraftError(f"status must be one of {sorted(FINDING_STATUSES)}")
    if confidence not in CONFIDENCES:
        raise ReverseCraftError(f"confidence must be one of {sorted(CONFIDENCES)}")
    if not title.strip():
        raise ReverseCraftError("finding title must not be empty")
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        evidence = load_json(directory / "evidence.json")["items"]
        known = {item["id"] for item in evidence}
        unknown = sorted(set(evidence_ids) - known)
        if unknown:
            raise ReverseCraftError(f"unknown evidence ids: {', '.join(unknown)}")
        if status in {"supported", "confirmed"} and not evidence_ids:
            raise ReverseCraftError(f"{status} finding requires evidence")
        if status == "confirmed" and confidence != "high" and not reproduction:
            raise ReverseCraftError("confirmed finding requires high confidence or a reproduction note")
        collection = load_json(directory / "findings.json")
        finding_id = _next_id(collection["items"], "F")
        item = {
            "id": finding_id,
            "title": title.strip(),
            "statement": statement or title.strip(),
            "severity": severity,
            "status": status,
            "confidence": confidence,
            "evidence_ids": list(dict.fromkeys(evidence_ids)),
            "reproduction": reproduction,
            "created_at": utc_now(),
        }
        collection["items"].append(item)
        atomic_write_json(directory / "findings.json", collection)
        _touch_case(directory, case)
        _append_event(directory, "finding.added", {"id": finding_id, "status": status, "evidence_ids": item["evidence_ids"]})
    return {"schema": "reverse-craft.finding-add.v1", "case_id": case_id, "finding": item}


def add_path(
    case_id: str,
    title: str,
    finding_ids: list[str],
    status: str = "supported",
    preconditions: str | None = None,
    impact: str | None = None,
    validation: str | None = None,
    home: str | None = None,
) -> dict[str, Any]:
    if status not in PATH_STATUSES:
        raise ReverseCraftError(f"status must be one of {sorted(PATH_STATUSES)}")
    if not title.strip() or not finding_ids:
        raise ReverseCraftError("path title and at least one finding are required")
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        findings = load_json(directory / "findings.json")["items"]
        by_id = {item["id"]: item for item in findings}
        unknown = sorted(set(finding_ids) - set(by_id))
        if unknown:
            raise ReverseCraftError(f"unknown finding ids: {', '.join(unknown)}")
        refuted = [finding_id for finding_id in finding_ids if by_id[finding_id]["status"] == "refuted"]
        if refuted and status != "refuted":
            raise ReverseCraftError(f"non-refuted path cannot include refuted findings: {', '.join(refuted)}")
        collection = load_json(directory / "paths.json")
        path_id = _next_id(collection["items"], "P")
        item = {
            "id": path_id,
            "title": title.strip(),
            "status": status,
            "finding_ids": list(dict.fromkeys(finding_ids)),
            "preconditions": preconditions,
            "impact": impact,
            "validation": validation,
            "created_at": utc_now(),
        }
        collection["items"].append(item)
        atomic_write_json(directory / "paths.json", collection)
        _touch_case(directory, case)
        _append_event(directory, "path.added", {"id": path_id, "status": status, "finding_ids": item["finding_ids"]})
    return {"schema": "reverse-craft.path-add.v1", "case_id": case_id, "path": item}


def _validate_events(directory: Path) -> list[str]:
    errors: list[str] = []
    try:
        events = _read_events(directory)
    except ReverseCraftError as exc:
        return [str(exc)]
    previous: str | None = None
    for expected_seq, event in enumerate(events, 1):
        material = _event_material(event.get("seq"), event.get("at"), event.get("type"), event.get("data"), event.get("prev_hash"))
        expected_hash = sha256_bytes(canonical_json(material))
        if event.get("seq") != expected_seq:
            errors.append(f"event sequence mismatch at {expected_seq}")
        if event.get("prev_hash") != previous:
            errors.append(f"event previous hash mismatch at {expected_seq}")
        if event.get("event_hash") != expected_hash:
            errors.append(f"event hash mismatch at {expected_seq}")
        previous = event.get("event_hash")
    return errors


def _manifest(directory: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for name in (*SNAPSHOTS, "events.ndjson"):
        path = directory / name
        files.append({"path": name, "size": path.stat().st_size, "sha256": sha256_file(path)})
    for subdir in ("artifacts", "reports"):
        for path in sorted((directory / subdir).glob("**/*")):
            if path.is_file():
                files.append({"path": str(path.relative_to(directory)), "size": path.stat().st_size, "sha256": sha256_file(path)})
    return {"files": files, "manifest_sha256": sha256_bytes(canonical_json(files))}


def validate_case(case_id: str, home: str | None = None) -> dict[str, Any]:
    directory, case = _load_case(case_id, home)
    errors: list[str] = []
    warnings: list[str] = []
    if case.get("schema") != "reverse-craft.case.v1":
        errors.append("unsupported case schema")
    if case.get("state") not in {"open", "sealed"}:
        errors.append("invalid case state")
    collections: dict[str, list[dict[str, Any]]] = {}
    for name, schema in (
        ("evidence", "reverse-craft.evidence.v1"),
        ("findings", "reverse-craft.findings.v1"),
        ("paths", "reverse-craft.paths.v1"),
    ):
        document = load_json(directory / f"{name}.json")
        if document.get("schema") != schema or not isinstance(document.get("items"), list):
            errors.append(f"invalid {name} snapshot")
            collections[name] = []
        else:
            collections[name] = document["items"]
    evidence_ids: set[str] = set()
    for item in collections["evidence"]:
        evidence_id = item.get("id")
        if not isinstance(evidence_id, str) or evidence_id in evidence_ids:
            errors.append(f"invalid or duplicate evidence id: {evidence_id}")
            continue
        evidence_ids.add(evidence_id)
        if item.get("acquisition") not in {"verified-copy", "external-reference"}:
            errors.append(f"invalid evidence acquisition: {evidence_id}")
        if not isinstance(item.get("size"), int) or item.get("size", -1) < 0:
            errors.append(f"invalid evidence size: {evidence_id}")
        digest = item.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            errors.append(f"invalid evidence sha256: {evidence_id}")
        if bool(item.get("stored_path")) == bool(item.get("external_path")):
            errors.append(f"evidence must have exactly one stored/external path: {evidence_id}")
        artifact_path: Path | None = None
        if item.get("stored_path"):
            candidate = (directory / item["stored_path"]).resolve()
            if directory.resolve() not in candidate.parents:
                errors.append(f"evidence path escapes case: {evidence_id}")
            else:
                artifact_path = candidate
        elif item.get("external_path"):
            artifact_path = Path(item["external_path"])
        if artifact_path is None or not artifact_path.is_file():
            errors.append(f"evidence artifact missing: {evidence_id}")
            continue
        if artifact_path.stat().st_size != item.get("size"):
            errors.append(f"evidence size mismatch: {evidence_id}")
        elif sha256_file(artifact_path) != item.get("sha256"):
            errors.append(f"evidence hash mismatch: {evidence_id}")
    finding_ids: set[str] = set()
    finding_status: dict[str, str] = {}
    for item in collections["findings"]:
        finding_id = item.get("id")
        if not isinstance(finding_id, str) or finding_id in finding_ids:
            errors.append(f"invalid or duplicate finding id: {finding_id}")
            continue
        finding_ids.add(finding_id)
        finding_status[finding_id] = item.get("status", "")
        if item.get("severity") not in SEVERITIES or item.get("status") not in FINDING_STATUSES or item.get("confidence") not in CONFIDENCES:
            errors.append(f"invalid finding classification: {finding_id}")
        missing = sorted(set(item.get("evidence_ids", [])) - evidence_ids)
        if missing:
            errors.append(f"finding {finding_id} references missing evidence: {', '.join(missing)}")
        if item.get("status") in {"supported", "confirmed"} and not item.get("evidence_ids"):
            errors.append(f"finding {finding_id} lacks required evidence")
        if item.get("status") == "confirmed" and item.get("confidence") != "high" and not item.get("reproduction"):
            errors.append(f"confirmed finding {finding_id} lacks high confidence or reproduction")
    path_ids: set[str] = set()
    for item in collections["paths"]:
        path_id = item.get("id")
        if not isinstance(path_id, str) or path_id in path_ids:
            errors.append(f"invalid or duplicate path id: {path_id}")
            continue
        path_ids.add(path_id)
        if item.get("status") not in PATH_STATUSES:
            errors.append(f"invalid path status: {path_id}")
        refs = item.get("finding_ids", [])
        if not refs:
            errors.append(f"path {path_id} has no findings")
        missing = sorted(set(refs) - finding_ids)
        if missing:
            errors.append(f"path {path_id} references missing findings: {', '.join(missing)}")
        if item.get("status") != "refuted":
            refuted = [finding_id for finding_id in refs if finding_status.get(finding_id) == "refuted"]
            if refuted:
                errors.append(f"path {path_id} includes refuted findings: {', '.join(refuted)}")
    errors.extend(_validate_events(directory))
    if not evidence_ids:
        warnings.append("case has no evidence")
    if case.get("state") == "sealed":
        seal_path = directory / "seal.json"
        if not seal_path.is_file():
            errors.append("sealed case has no seal.json")
        else:
            seal = load_json(seal_path)
            if seal.get("schema") != "reverse-craft.seal.v1" or seal.get("case_id") != case_id:
                errors.append("invalid seal identity")
            current = _manifest(directory)
            if seal.get("manifest_sha256") != current["manifest_sha256"] or seal.get("files") != current["files"]:
                errors.append("seal manifest mismatch")
    elif (directory / "seal.json").exists():
        errors.append("open case unexpectedly has seal.json")
    return {
        "schema": "reverse-craft.case-validation.v1",
        "case_id": case_id,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "counts": {name: len(items) for name, items in collections.items()},
        "checked_at": utc_now(),
    }


def render_report(case_id: str, output: str | None = None, home: str | None = None) -> dict[str, Any]:
    directory, case = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        evidence = load_json(directory / "evidence.json")["items"]
        findings = load_json(directory / "findings.json")["items"]
        paths = load_json(directory / "paths.json")["items"]
        validation = validate_case(case_id, home)
        lines = [
            f"# {case['title']}",
            "",
            "## Objective and scope",
            "",
            case["scope"],
            "",
            "## Outcome",
            "",
            "Generated from the current Reverse Craft case graph. Confirmed conclusions are listed below; "
            "absence from this report is not evidence of absence.",
            "",
            "## Findings",
            "",
        ]
        if not findings:
            lines.append("No findings recorded.")
        for item in findings:
            lines.extend([
                f"### {item['id']} - {item['title']}",
                "",
                f"- Status: `{item['status']}`",
                f"- Severity: `{item['severity']}`",
                f"- Confidence: `{item['confidence']}`",
                f"- Evidence: {', '.join(f'`{value}`' for value in item['evidence_ids']) or 'none'}",
                f"- Statement: {item['statement']}",
            ])
            if item.get("reproduction"):
                lines.append(f"- Reproduction: {item['reproduction']}")
            lines.append("")
        lines.extend(["## Paths", ""])
        if not paths:
            lines.append("No paths recorded.")
        for item in paths:
            lines.extend([
                f"### {item['id']} - {item['title']}",
                "",
                f"- Status: `{item['status']}`",
                f"- Findings: {' -> '.join(f'`{value}`' for value in item['finding_ids'])}",
                f"- Preconditions: {item.get('preconditions') or 'not recorded'}",
                f"- Impact: {item.get('impact') or 'not recorded'}",
                f"- Validation: {item.get('validation') or 'not recorded'}",
                "",
            ])
        lines.extend(["## Evidence", ""])
        if not evidence:
            lines.append("No evidence recorded.")
        for item in evidence:
            location = item.get("stored_path") or item.get("external_path")
            lines.append(f"- `{item['id']}` {item['kind']}: `{item['sha256']}` ({item['size']} bytes, `{location}`)")
        lines.extend([
            "",
            "## Verification and limitations",
            "",
            f"- Case validation: `{'PASS' if validation['valid'] else 'FAIL'}`",
            f"- Validation errors: {len(validation['errors'])}",
            f"- Validation warnings: {len(validation['warnings'])}",
            f"- Route: `{case.get('route_id') or 'not recorded'}`",
            f"- Generated at: `{utc_now()}`",
            "",
        ])
        content = "\n".join(lines).encode("utf-8")
        if output:
            destination = Path(output).expanduser().resolve()
        else:
            destination = directory / "reports" / "report.md"
        if directory.resolve() not in destination.parents:
            raise ReverseCraftError("report output must remain inside the case directory")
        atomic_write_bytes(destination, content)
        digest = sha256_file(destination)
        _touch_case(directory, case)
        _append_event(directory, "report.rendered", {"path": str(destination.relative_to(directory)), "sha256": digest})
    return {"schema": "reverse-craft.report.v1", "case_id": case_id, "path": str(destination), "sha256": digest}


def seal_case(case_id: str, home: str | None = None) -> dict[str, Any]:
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        validation = validate_case(case_id, home)
        if not validation["valid"]:
            raise ReverseCraftError("case validation failed: " + "; ".join(validation["errors"]))
        if validation["counts"]["evidence"] < 1:
            raise ReverseCraftError("cannot seal a case without evidence")
        sealed_at = utc_now()
        case["state"] = "sealed"
        case["sealed_at"] = sealed_at
        case["updated_at"] = sealed_at
        atomic_write_json(directory / "case.json", case)
        _append_event(directory, "case.sealed", {"id": case_id, "sealed_at": sealed_at})
        manifest = _manifest(directory)
        seal = {
            "schema": "reverse-craft.seal.v1",
            "case_id": case_id,
            "sealed_at": sealed_at,
            **manifest,
        }
        atomic_write_json(directory / "seal.json", seal)
    final_validation = validate_case(case_id, home)
    if not final_validation["valid"]:
        raise ReverseCraftError("post-seal validation failed: " + "; ".join(final_validation["errors"]))
    return {"schema": "reverse-craft.case-seal.v1", "case_id": case_id, "seal": seal, "valid": True}
