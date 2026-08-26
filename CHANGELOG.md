# Changelog

## Unreleased

- Split case mutation/orchestration from case validation and manifest logic without changing the public CLI or data contracts.
- Added event-record and seal JSON Schemas with source/runtime field-drift checks and stricter seal reconciliation.
- Added redacted `crash.v1` diagnostics for unexpected CLI exceptions without exposing exception messages or tracebacks.
- Hardened `doctor` MCP discovery so raw transport arguments, environment/header values, URL secrets, unknown
  transport fields, and failing command stderr are never returned.
- Made new case/setup runtime directories and generated artifacts owner-only on POSIX.
- Added strict fail-closed validation for malformed case snapshots/events and schema/runtime field-drift checks.
- Anchored new case event tails in `case.json`, reconciled entity events with snapshots, and documented the
  remaining local-consistency versus external-authenticity boundary.
- Restricted copied evidence and rendered reports to their dedicated case subdirectories.

## 0.1.0 - 2026-08-21

- Added one installable `$reverse-craft` Skill with 42 deterministic specialist routes.
- Added dependency-free case, evidence, finding, path, report, seal, doctor, setup, and provenance CLI.
- Added browser67 `js-reverse` orchestration boundary and live MCP gate.
- Added 252 bilingual routing cases, 10 offline end-to-end scenarios, unit tests, and real Codex/Pi evaluations.
- Added macOS, Linux, and Windows CI validation. No npm publication, tag, or release is part of this version.
