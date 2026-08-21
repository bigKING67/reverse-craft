# Case and evidence contract

## Layout

```text
<home>/runs/<case-id>/
|-- case.json
|-- evidence.json
|-- findings.json
|-- paths.json
|-- events.ndjson
|-- artifacts/
|-- reports/
`-- seal.json                 present only after seal
```

JSON snapshots are written atomically. `events.ndjson` is append-only and each event includes its previous
event hash, making truncation/reordering detectable. A per-case lock serializes writers.

## State

`open -> sealed`. Open cases accept evidence, findings, paths, and report rendering. A sealed case is
logically immutable: mutating CLI commands fail. `case validate` remains read-only after seal and verifies
snapshot shape, references, artifact hashes, event hash continuity, and the seal manifest.

## Entities

- **Evidence**: `E-NNNN`, source, kind, acquisition method, timestamp, size, SHA-256, stored or external path,
  optional note and route/run reference.
- **Finding**: `F-NNNN`, title, status (`hypothesis|supported|confirmed|refuted`), severity, confidence,
  evidence IDs, statement, and optional reproduction.
- **Path**: `P-NNNN`, ordered finding IDs, title, status, preconditions, impact, and validation note.
- **Report**: deterministic Markdown projection; it is not new evidence.

## Minimum evidence rules

- `supported` and `confirmed` findings require at least one existing evidence ID.
- A `confirmed` finding requires `confidence=high` or an explicit reproduction note.
- Paths require at least one existing, non-refuted finding.
- Sealing requires zero validation errors and at least one evidence item.
- External evidence must remain readable with matching size/hash at validation time.

Use evidence notes for provenance and observation, not secrets or entire logs. Put large output in an artifact
and cite its hash/ID.

## browser67 references

Do not copy browser67 run directories into a case by default. Add a small JSON receipt or external evidence
record containing the browser67 `run_id`, selected evidence artifact path, size, and hash. browser67 remains
the runtime owner; Reverse Craft owns the cross-domain finding/path graph.

