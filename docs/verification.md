# Verification model

Reverse Craft keeps evidence tiers separate:

1. **Source validation**: structure, versions, JSON parseability, route/module completeness, event/seal schema-runtime
   field parity, provenance hashes, Python compile.
2. **Unit behavior**: path safety, private file modes, artifact fixity, event-chain tail anchors, snapshot/event
   reconciliation, malformed-data fail-closed behavior, seal shape/timestamp reconciliation, redacted crash diagnostics,
   MCP secret projection, concurrency, seal, setup tamper rejection.
3. **Routing bank**: 252 manually curated English/Chinese prompts across all 42 routes, including priority/exclusion cases.
4. **Offline scenarios**: 10 isolated end-to-end cases through route -> evidence -> finding -> path -> report -> seal.
5. **Real hosts**: Codex and Pi load the real Skill and return an exact R3/browser67/evidence-contract decision.
6. **Live browser runtime**: pinned browser67 process executes MCP `initialize -> tools/list -> tools/call`, sees 60 tools,
   opens a scoped managed fixture tab, records evidence, exports a rebuild bundle, and finalizes the task.
7. **CI portability**: source/unit/route/scenario gates on Python 3.10 and 3.13 across macOS, Ubuntu, and Windows.

Passing a lower tier does not imply a higher tier. In particular, CI does not prove the user's current browser extension
or authenticated host, and an MCP surface-only check does not prove managed-tab lifecycle.

## Commands

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/run_route_bank.py
python3 scripts/run_scenario_bank.py
python3 scripts/run_host_eval.py --host all
python3 scripts/check_browser67_mcp.py
```

The last two commands are intentionally outside `check:all`: they depend on authenticated/local runtimes and must be
reported as live evidence with host versions and current pins.
