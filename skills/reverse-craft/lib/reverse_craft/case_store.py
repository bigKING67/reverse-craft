from __future__ import annotations

import json
import os
import re
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
    ensure_private_directory,
    home_root,
    load_json,
    parse_utc,
    PRIVATE_FILE_MODE,
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
CASE_REQUIRED_FIELDS = {
    "schema", "id", "title", "scope", "route_id", "state", "created_at", "updated_at", "sealed_at",
}
CASE_OPTIONAL_FIELDS = {"event_count", "last_event_hash"}
CASE_ALLOWED_FIELDS = CASE_REQUIRED_FIELDS | CASE_OPTIONAL_FIELDS
COLLECTION_REQUIRED_FIELDS = {"schema", "items"}
EVIDENCE_REQUIRED_FIELDS = {
    "id", "kind", "source", "acquisition", "observed_at", "size", "sha256", "stored_path",
    "external_path", "note",
}
FINDING_REQUIRED_FIELDS = {
    "id", "title", "statement", "severity", "status", "confidence", "evidence_ids", "reproduction",
    "created_at",
}
PATH_REQUIRED_FIELDS = {
    "id", "title", "status", "finding_ids", "preconditions", "impact", "validation", "created_at",
}
EVENT_REQUIRED_FIELDS = {"seq", "at", "type", "data", "prev_hash", "event_hash"}
EVENT_TYPES = {"case.initialized", "evidence.added", "finding.added", "path.added", "report.rendered", "case.sealed"}
EVENT_DATA_FIELDS = {
    "case.initialized": {"id", "route_id"},
    "evidence.added": {"id", "sha256", "size"},
    "finding.added": {"id", "status", "evidence_ids"},
    "path.added": {"id", "status", "finding_ids"},
    "report.rendered": {"path", "sha256"},
    "case.sealed": {"id", "sealed_at"},
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ID_RE = re.compile(r"^E-[0-9]{4,}$")
FINDING_ID_RE = re.compile(r"^F-[0-9]{4,}$")
PATH_ID_RE = re.compile(r"^P-[0-9]{4,}$")


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
    if not isinstance(case, dict):
        raise ReverseCraftError(f"invalid case document in {directory / 'case.json'}")
    if case.get("id") != case_id:
        raise ReverseCraftError(f"case identity mismatch in {directory / 'case.json'}")
    return directory, case


def _require_open(case: dict[str, Any]) -> None:
    if case.get("state") != "open":
        raise ReverseCraftError(f"case is {case.get('state')}; mutation is not allowed")


def _next_id(items: Iterable[dict[str, Any]], prefix: str) -> str:
    maximum = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("id", ""))
        if raw.startswith(prefix + "-"):
            try:
                maximum = max(maximum, int(raw.split("-", 1)[1]))
            except ValueError:
                continue
    return f"{prefix}-{maximum + 1:04d}"


def _read_events(directory: Path) -> list[Any]:
    path = directory / "events.ndjson"
    if not path.exists():
        return []
    events: list[Any] = []
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


def _assert_event_stream_appendable(directory: Path, case: dict[str, Any]) -> list[Any]:
    events = _read_events(directory)
    event_errors = _validate_event_records(events)
    if event_errors:
        raise ReverseCraftError("event stream validation failed: " + "; ".join(event_errors))
    prev_hash = events[-1]["event_hash"] if events else None
    has_count = "event_count" in case
    has_hash = "last_event_hash" in case
    if has_count != has_hash:
        raise ReverseCraftError("case event anchor is incomplete")
    if has_count and (case["event_count"] != len(events) or case["last_event_hash"] != prev_hash):
        raise ReverseCraftError("case event anchor does not match the event stream")
    return events


def _append_event(directory: Path, case: dict[str, Any], event_type: str, data: Any) -> dict[str, Any]:
    events = _assert_event_stream_appendable(directory, case)
    prev_hash = events[-1]["event_hash"] if events else None
    material = _event_material(len(events) + 1, utc_now(), event_type, data, prev_hash)
    event = {**material, "event_hash": sha256_bytes(canonical_json(material))}
    path = directory / "events.ndjson"
    with path.open("ab") as handle:
        handle.write(canonical_json(event) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    return event


def _record_case_event(directory: Path, case: dict[str, Any], event_type: str, data: Any) -> dict[str, Any]:
    event = _append_event(directory, case, event_type, data)
    case["updated_at"] = event["at"]
    case["event_count"] = event["seq"]
    case["last_event_hash"] = event["event_hash"]
    atomic_write_json(directory / "case.json", case)
    return event


def init_case(title: str, scope: str, route_id: str | None = None, home: str | None = None) -> dict[str, Any]:
    if not title.strip() or not scope.strip():
        raise ReverseCraftError("title and scope must not be empty")
    if route_id is not None and (not isinstance(route_id, str) or route_id not in ROUTE_IDS):
        raise ReverseCraftError("route id must be R0..R41")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case_id = f"{timestamp}-{slugify(title)}-{secrets.token_hex(2)}"
    directory = case_dir(case_id, home)
    ensure_private_directory(runs_root(home))
    ensure_private_directory(directory, parents=False, exist_ok=False)
    ensure_private_directory(directory / "artifacts", parents=False)
    ensure_private_directory(directory / "reports", parents=False)
    created_at = utc_now()
    case = {
        "schema": "reverse-craft.case.v1",
        "id": case_id,
        "title": title.strip(),
        "scope": scope.strip(),
        "route_id": route_id,
        "state": "open",
        "created_at": created_at,
        "updated_at": created_at,
        "sealed_at": None,
        "event_count": 0,
        "last_event_hash": None,
    }
    atomic_write_json(directory / "case.json", case)
    atomic_write_json(directory / "evidence.json", _empty_collection("reverse-craft.evidence.v1"))
    atomic_write_json(directory / "findings.json", _empty_collection("reverse-craft.findings.v1"))
    atomic_write_json(directory / "paths.json", _empty_collection("reverse-craft.paths.v1"))
    (directory / "events.ndjson").touch(mode=0o600)
    if os.name != "nt":
        (directory / "events.ndjson").chmod(PRIVATE_FILE_MODE)
    _record_case_event(directory, case, "case.initialized", {"id": case_id, "route_id": route_id})
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
        _assert_event_stream_appendable(directory, case)
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
                if os.name != "nt":
                    temp.chmod(PRIVATE_FILE_MODE)
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
        _record_case_event(
            directory, case, "evidence.added",
            {"id": evidence_id, "sha256": digest, "size": source_stat.st_size},
        )
    return {"schema": "reverse-craft.evidence-add.v1", "case_id": case_id, "evidence": item}


def re_safe_filename(name: str) -> str:
    cleaned = "".join(character if character.isalnum() or character in ".-_" else "_" for character in name)
    cleaned = cleaned.strip(".")[:120]
    return cleaned or "artifact.bin"


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
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ReverseCraftError(f"severity must be one of {sorted(SEVERITIES)}")
    if not isinstance(status, str) or status not in FINDING_STATUSES:
        raise ReverseCraftError(f"status must be one of {sorted(FINDING_STATUSES)}")
    if not isinstance(confidence, str) or confidence not in CONFIDENCES:
        raise ReverseCraftError(f"confidence must be one of {sorted(CONFIDENCES)}")
    if not title.strip():
        raise ReverseCraftError("finding title must not be empty")
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        _assert_event_stream_appendable(directory, case)
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
        _record_case_event(
            directory, case, "finding.added",
            {"id": finding_id, "status": status, "evidence_ids": item["evidence_ids"]},
        )
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
    if not isinstance(status, str) or status not in PATH_STATUSES:
        raise ReverseCraftError(f"status must be one of {sorted(PATH_STATUSES)}")
    if not title.strip() or not finding_ids:
        raise ReverseCraftError("path title and at least one finding are required")
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        _assert_event_stream_appendable(directory, case)
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
        _record_case_event(
            directory, case, "path.added",
            {"id": path_id, "status": status, "finding_ids": item["finding_ids"]},
        )
    return {"schema": "reverse-craft.path-add.v1", "case_id": case_id, "path": item}


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _validate_timestamp(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"invalid {label} timestamp")
        return
    try:
        parsed = parse_utc(value)
    except (TypeError, ValueError):
        errors.append(f"invalid {label} timestamp")
        return
    if parsed.tzinfo is None:
        errors.append(f"invalid {label} timestamp")


def _validate_exact_fields(value: dict[str, Any], required: set[str], label: str, errors: list[str]) -> None:
    missing = sorted(required - set(value))
    unexpected = sorted(set(value) - required)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if unexpected:
        errors.append(f"{label} has unexpected fields: {', '.join(unexpected)}")


def _load_validation_json(path: Path, label: str, errors: list[str]) -> Any:
    try:
        return load_json(path)
    except (OSError, ReverseCraftError) as exc:
        errors.append(f"invalid {label}: {exc}")
        return None


def _validate_event_records(events: list[Any]) -> list[str]:
    errors: list[str] = []
    previous: str | None = None
    for expected_seq, event in enumerate(events, 1):
        if not isinstance(event, dict):
            errors.append(f"event at line {expected_seq} is not an object")
            previous = None
            continue
        _validate_exact_fields(event, EVENT_REQUIRED_FIELDS, f"event at line {expected_seq}", errors)
        material = _event_material(event.get("seq"), event.get("at"), event.get("type"), event.get("data"), event.get("prev_hash"))
        expected_hash = sha256_bytes(canonical_json(material))
        if not _is_integer(event.get("seq")) or event.get("seq") != expected_seq:
            errors.append(f"event sequence mismatch at {expected_seq}")
        _validate_timestamp(event.get("at"), f"event {expected_seq}", errors)
        event_type = event.get("type")
        if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
            errors.append(f"invalid event type at {expected_seq}")
        data = event.get("data")
        if not isinstance(data, dict):
            errors.append(f"invalid event data at {expected_seq}")
        elif isinstance(event_type, str) and event_type in EVENT_DATA_FIELDS:
            _validate_exact_fields(data, EVENT_DATA_FIELDS[event_type], f"event data at line {expected_seq}", errors)
        if event.get("prev_hash") is not None and not _is_sha256(event.get("prev_hash")):
            errors.append(f"invalid event previous hash at {expected_seq}")
        if event.get("prev_hash") != previous:
            errors.append(f"event previous hash mismatch at {expected_seq}")
        if not _is_sha256(event.get("event_hash")) or event.get("event_hash") != expected_hash:
            errors.append(f"event hash mismatch at {expected_seq}")
        previous = event.get("event_hash") if _is_sha256(event.get("event_hash")) else None
    return errors


def _validated_events(directory: Path) -> tuple[list[Any], list[str]]:
    if not (directory / "events.ndjson").is_file():
        return [], ["event stream is missing"]
    try:
        events = _read_events(directory)
    except (OSError, ReverseCraftError) as exc:
        return [], [str(exc)]
    return events, _validate_event_records(events)


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
    directory = case_dir(case_id, home)
    errors: list[str] = []
    warnings: list[str] = []
    case_document = _load_validation_json(directory / "case.json", "case document", errors)
    case: dict[str, Any] = case_document if isinstance(case_document, dict) else {}
    if case_document is not None and not isinstance(case_document, dict):
        errors.append("case document is not an object")
    if isinstance(case_document, dict):
        missing = sorted(CASE_REQUIRED_FIELDS - set(case))
        unexpected = sorted(set(case) - CASE_ALLOWED_FIELDS)
        if missing:
            errors.append(f"case missing fields: {', '.join(missing)}")
        if unexpected:
            errors.append(f"case has unexpected fields: {', '.join(unexpected)}")
        if case.get("schema") != "reverse-craft.case.v1":
            errors.append("unsupported case schema")
        if case.get("id") != case_id:
            errors.append("case identity mismatch")
        if not _is_non_empty_string(case.get("title")):
            errors.append("invalid case title")
        if not _is_non_empty_string(case.get("scope")):
            errors.append("invalid case scope")
        if case.get("route_id") is not None and (
            not isinstance(case.get("route_id"), str) or case.get("route_id") not in ROUTE_IDS
        ):
            errors.append("invalid case route id")
        if not isinstance(case.get("state"), str) or case.get("state") not in {"open", "sealed"}:
            errors.append("invalid case state")
        _validate_timestamp(case.get("created_at"), "case created_at", errors)
        _validate_timestamp(case.get("updated_at"), "case updated_at", errors)
        if case.get("state") == "sealed":
            _validate_timestamp(case.get("sealed_at"), "case sealed_at", errors)
        elif case.get("sealed_at") is not None:
            errors.append("open case has sealed_at")
        has_count = "event_count" in case
        has_hash = "last_event_hash" in case
        if has_count != has_hash:
            errors.append("case event anchor is incomplete")
        elif not has_count:
            warnings.append("legacy case has no event tail anchor")
        else:
            event_count = case.get("event_count")
            last_event_hash = case.get("last_event_hash")
            if not _is_integer(event_count) or event_count < 0:
                errors.append("invalid case event_count")
            if event_count == 0 and last_event_hash is not None:
                errors.append("empty case event anchor has a hash")
            if _is_integer(event_count) and event_count > 0 and not _is_sha256(last_event_hash):
                errors.append("invalid case last_event_hash")
    collections: dict[str, list[dict[str, Any]]] = {}
    for name, schema in (
        ("evidence", "reverse-craft.evidence.v1"),
        ("findings", "reverse-craft.findings.v1"),
        ("paths", "reverse-craft.paths.v1"),
    ):
        document = _load_validation_json(directory / f"{name}.json", f"{name} snapshot", errors)
        if not isinstance(document, dict):
            if document is not None:
                errors.append(f"invalid {name} snapshot")
            collections[name] = []
            continue
        _validate_exact_fields(document, COLLECTION_REQUIRED_FIELDS, f"{name} snapshot", errors)
        if document.get("schema") != schema or not isinstance(document.get("items"), list):
            errors.append(f"invalid {name} snapshot")
            collections[name] = []
        else:
            collections[name] = document["items"]
    evidence_ids: set[str] = set()
    for index, item in enumerate(collections["evidence"], 1):
        if not isinstance(item, dict):
            errors.append(f"evidence item {index} is not an object")
            continue
        _validate_exact_fields(item, EVIDENCE_REQUIRED_FIELDS, f"evidence item {index}", errors)
        evidence_id = item.get("id")
        if (
            not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None or
            evidence_id in evidence_ids
        ):
            errors.append(f"invalid or duplicate evidence id: {evidence_id}")
            continue
        evidence_ids.add(evidence_id)
        if not _is_non_empty_string(item.get("kind")) or not _is_non_empty_string(item.get("source")):
            errors.append(f"invalid evidence metadata: {evidence_id}")
        _validate_timestamp(item.get("observed_at"), f"evidence {evidence_id} observed_at", errors)
        if not isinstance(item.get("acquisition"), str) or item.get("acquisition") not in {
            "verified-copy", "external-reference",
        }:
            errors.append(f"invalid evidence acquisition: {evidence_id}")
        if not _is_integer(item.get("size")) or item.get("size", -1) < 0:
            errors.append(f"invalid evidence size: {evidence_id}")
        digest = item.get("sha256")
        if not _is_sha256(digest):
            errors.append(f"invalid evidence sha256: {evidence_id}")
        stored_path = item.get("stored_path")
        external_path = item.get("external_path")
        if item.get("note") is not None and not isinstance(item.get("note"), str):
            errors.append(f"invalid evidence note: {evidence_id}")
        if not ((isinstance(stored_path, str) and bool(stored_path) and external_path is None) or
                (stored_path is None and isinstance(external_path, str) and bool(external_path))):
            errors.append(f"evidence must have exactly one stored/external path: {evidence_id}")
        artifact_path: Path | None = None
        if isinstance(stored_path, str) and stored_path:
            try:
                candidate = (directory / stored_path).resolve()
                artifacts_root = (directory / "artifacts").resolve()
            except OSError:
                candidate = None
                artifacts_root = None
            if (
                candidate is None or artifacts_root is None or Path(stored_path).is_absolute() or
                artifacts_root not in candidate.parents
            ):
                errors.append(f"evidence path escapes case: {evidence_id}")
            else:
                artifact_path = candidate
        elif isinstance(external_path, str) and external_path:
            candidate = Path(external_path)
            if not candidate.is_absolute():
                errors.append(f"external evidence path is not absolute: {evidence_id}")
            else:
                artifact_path = candidate
        try:
            artifact_exists = artifact_path is not None and artifact_path.is_file()
        except OSError:
            artifact_exists = False
        if not artifact_exists:
            errors.append(f"evidence artifact missing: {evidence_id}")
            continue
        try:
            if artifact_path.stat().st_size != item.get("size"):
                errors.append(f"evidence size mismatch: {evidence_id}")
            elif _is_sha256(digest) and sha256_file(artifact_path) != digest:
                errors.append(f"evidence hash mismatch: {evidence_id}")
        except OSError:
            errors.append(f"evidence artifact unreadable: {evidence_id}")
    finding_ids: set[str] = set()
    finding_status: dict[str, str] = {}
    for index, item in enumerate(collections["findings"], 1):
        if not isinstance(item, dict):
            errors.append(f"finding item {index} is not an object")
            continue
        _validate_exact_fields(item, FINDING_REQUIRED_FIELDS, f"finding item {index}", errors)
        finding_id = item.get("id")
        if not isinstance(finding_id, str) or FINDING_ID_RE.fullmatch(finding_id) is None or finding_id in finding_ids:
            errors.append(f"invalid or duplicate finding id: {finding_id}")
            continue
        finding_ids.add(finding_id)
        status_value = item.get("status") if isinstance(item.get("status"), str) else ""
        finding_status[finding_id] = status_value
        if not _is_non_empty_string(item.get("title")) or not _is_non_empty_string(item.get("statement")):
            errors.append(f"invalid finding text: {finding_id}")
        _validate_timestamp(item.get("created_at"), f"finding {finding_id} created_at", errors)
        if (
            not isinstance(item.get("severity"), str) or item.get("severity") not in SEVERITIES or
            not isinstance(item.get("status"), str) or item.get("status") not in FINDING_STATUSES or
            not isinstance(item.get("confidence"), str) or item.get("confidence") not in CONFIDENCES
        ):
            errors.append(f"invalid finding classification: {finding_id}")
        refs = item.get("evidence_ids")
        if not isinstance(refs, list) or any(
            not isinstance(value, str) or EVIDENCE_ID_RE.fullmatch(value) is None for value in refs
        ):
            errors.append(f"invalid finding evidence_ids: {finding_id}")
            refs = []
        elif len(refs) != len(set(refs)):
            errors.append(f"duplicate finding evidence_ids: {finding_id}")
        if item.get("reproduction") is not None and not isinstance(item.get("reproduction"), str):
            errors.append(f"invalid finding reproduction: {finding_id}")
        missing = sorted(set(refs) - evidence_ids)
        if missing:
            errors.append(f"finding {finding_id} references missing evidence: {', '.join(missing)}")
        if status_value in {"supported", "confirmed"} and not refs:
            errors.append(f"finding {finding_id} lacks required evidence")
        if status_value == "confirmed" and item.get("confidence") != "high" and not item.get("reproduction"):
            errors.append(f"confirmed finding {finding_id} lacks high confidence or reproduction")
    path_ids: set[str] = set()
    for index, item in enumerate(collections["paths"], 1):
        if not isinstance(item, dict):
            errors.append(f"path item {index} is not an object")
            continue
        _validate_exact_fields(item, PATH_REQUIRED_FIELDS, f"path item {index}", errors)
        path_id = item.get("id")
        if not isinstance(path_id, str) or PATH_ID_RE.fullmatch(path_id) is None or path_id in path_ids:
            errors.append(f"invalid or duplicate path id: {path_id}")
            continue
        path_ids.add(path_id)
        if not _is_non_empty_string(item.get("title")):
            errors.append(f"invalid path title: {path_id}")
        _validate_timestamp(item.get("created_at"), f"path {path_id} created_at", errors)
        if not isinstance(item.get("status"), str) or item.get("status") not in PATH_STATUSES:
            errors.append(f"invalid path status: {path_id}")
        refs = item.get("finding_ids")
        if not isinstance(refs, list) or any(
            not isinstance(value, str) or FINDING_ID_RE.fullmatch(value) is None for value in refs
        ):
            errors.append(f"invalid path finding_ids: {path_id}")
            refs = []
        elif len(refs) != len(set(refs)):
            errors.append(f"duplicate path finding_ids: {path_id}")
        for field in ("preconditions", "impact", "validation"):
            if item.get(field) is not None and not isinstance(item.get(field), str):
                errors.append(f"invalid path {field}: {path_id}")
        if not refs:
            errors.append(f"path {path_id} has no findings")
        missing = sorted(set(refs) - finding_ids)
        if missing:
            errors.append(f"path {path_id} references missing findings: {', '.join(missing)}")
        if item.get("status") != "refuted":
            refuted = [finding_id for finding_id in refs if finding_status.get(finding_id) == "refuted"]
            if refuted:
                errors.append(f"path {path_id} includes refuted findings: {', '.join(refuted)}")
    events, event_errors = _validated_events(directory)
    errors.extend(event_errors)
    if events:
        first = events[0] if isinstance(events[0], dict) else {}
        initialized = [event for event in events if isinstance(event, dict) and event.get("type") == "case.initialized"]
        if len(initialized) != 1 or first.get("type") != "case.initialized":
            errors.append("case must have exactly one first case.initialized event")
        elif not isinstance(initialized[0].get("data"), dict) or initialized[0]["data"] != {
            "id": case_id, "route_id": case.get("route_id"),
        }:
            errors.append("case.initialized event data does not match the case snapshot")
        expected_event_ids = {
            "evidence.added": evidence_ids,
            "finding.added": finding_ids,
            "path.added": path_ids,
        }
        for event_type, expected_ids in expected_event_ids.items():
            observed_values = [
                event["data"].get("id")
                for event in events
                if isinstance(event, dict) and event.get("type") == event_type and isinstance(event.get("data"), dict)
            ]
            if any(not isinstance(value, str) for value in observed_values):
                errors.append(f"invalid {event_type} event id")
            observed_ids = [value for value in observed_values if isinstance(value, str)]
            if len(observed_ids) != len(set(observed_ids)):
                errors.append(f"duplicate {event_type} event ids")
            if set(observed_ids) != expected_ids:
                errors.append(f"{event_type} events do not match the snapshot")
        snapshot_by_event = {
            "evidence.added": {
                item["id"]: {"id": item["id"], "sha256": item.get("sha256"), "size": item.get("size")}
                for item in collections["evidence"] if isinstance(item, dict) and isinstance(item.get("id"), str)
            },
            "finding.added": {
                item["id"]: {"id": item["id"], "status": item.get("status"), "evidence_ids": item.get("evidence_ids")}
                for item in collections["findings"] if isinstance(item, dict) and isinstance(item.get("id"), str)
            },
            "path.added": {
                item["id"]: {"id": item["id"], "status": item.get("status"), "finding_ids": item.get("finding_ids")}
                for item in collections["paths"] if isinstance(item, dict) and isinstance(item.get("id"), str)
            },
        }
        for event in events:
            if (
                not isinstance(event, dict) or not isinstance(event.get("type"), str) or
                event.get("type") not in snapshot_by_event or not isinstance(event.get("data"), dict)
            ):
                continue
            event_type = event["type"]
            event_id = event["data"].get("id")
            expected_data = snapshot_by_event[event_type].get(event_id) if isinstance(event_id, str) else None
            if expected_data is not None and event["data"] != expected_data:
                errors.append(f"{event_type} event data does not match snapshot item {event_id}")
        for event in events:
            if (
                not isinstance(event, dict) or event.get("type") != "report.rendered" or
                not isinstance(event.get("data"), dict)
            ):
                continue
            report_path = event["data"].get("path")
            report_digest = event["data"].get("sha256")
            if not isinstance(report_path, str) or not report_path or not _is_sha256(report_digest):
                errors.append("invalid report.rendered event data")
                continue
            try:
                candidate = (directory / report_path).resolve()
                reports_root = (directory / "reports").resolve()
                if Path(report_path).is_absolute() or reports_root not in candidate.parents or not candidate.is_file():
                    errors.append("report.rendered artifact is missing or outside the case")
                elif sha256_file(candidate) != report_digest:
                    errors.append("report.rendered artifact hash mismatch")
            except OSError:
                errors.append("report.rendered artifact is unreadable")
        sealed_events = [event for event in events if isinstance(event, dict) and event.get("type") == "case.sealed"]
        if case.get("state") == "sealed":
            if len(sealed_events) != 1 or not isinstance(events[-1], dict) or events[-1].get("type") != "case.sealed":
                errors.append("sealed case must end with exactly one case.sealed event")
            elif not isinstance(sealed_events[0].get("data"), dict) or sealed_events[0]["data"] != {
                "id": case_id, "sealed_at": case.get("sealed_at"),
            }:
                errors.append("case.sealed event data does not match the case snapshot")
        elif sealed_events:
            errors.append("open case has a case.sealed event")
    else:
        errors.append("case has no initialization event")
    if "event_count" in case and "last_event_hash" in case:
        actual_hash = events[-1].get("event_hash") if events and isinstance(events[-1], dict) else None
        if case.get("event_count") != len(events):
            errors.append("case event_count does not match the event stream")
        if case.get("last_event_hash") != actual_hash:
            errors.append("case last_event_hash does not match the event stream")
    if not evidence_ids:
        warnings.append("case has no evidence")
    if case.get("state") == "sealed":
        seal_path = directory / "seal.json"
        if not seal_path.is_file():
            errors.append("sealed case has no seal.json")
        else:
            seal_document = _load_validation_json(seal_path, "seal document", errors)
            seal = seal_document if isinstance(seal_document, dict) else {}
            if seal_document is not None and not isinstance(seal_document, dict):
                errors.append("seal document is not an object")
            if seal.get("schema") != "reverse-craft.seal.v1" or seal.get("case_id") != case_id:
                errors.append("invalid seal identity")
            try:
                current = _manifest(directory)
            except OSError as exc:
                errors.append(f"could not build seal manifest: {exc}")
            else:
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
        _assert_event_stream_appendable(directory, case)
        evidence = load_json(directory / "evidence.json")["items"]
        findings = load_json(directory / "findings.json")["items"]
        paths = load_json(directory / "paths.json")["items"]
        validation = validate_case(case_id, home)
        if not validation["valid"]:
            raise ReverseCraftError("case validation failed: " + "; ".join(validation["errors"]))
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
        reports_root = (directory / "reports").resolve()
        if reports_root not in destination.parents:
            raise ReverseCraftError("report output must remain inside the case reports directory")
        ensure_private_directory(destination.parent)
        atomic_write_bytes(destination, content)
        digest = sha256_file(destination)
        _record_case_event(
            directory, case, "report.rendered",
            {"path": str(destination.relative_to(directory)), "sha256": digest},
        )
    return {"schema": "reverse-craft.report.v1", "case_id": case_id, "path": str(destination), "sha256": digest}


def seal_case(case_id: str, home: str | None = None) -> dict[str, Any]:
    directory, _ = _load_case(case_id, home)
    with FileLock(directory / ".case.lock"):
        case = load_json(directory / "case.json")
        _require_open(case)
        _assert_event_stream_appendable(directory, case)
        validation = validate_case(case_id, home)
        if not validation["valid"]:
            raise ReverseCraftError("case validation failed: " + "; ".join(validation["errors"]))
        if validation["counts"]["evidence"] < 1:
            raise ReverseCraftError("cannot seal a case without evidence")
        sealed_at = utc_now()
        case["state"] = "sealed"
        case["sealed_at"] = sealed_at
        _record_case_event(directory, case, "case.sealed", {"id": case_id, "sealed_at": sealed_at})
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
