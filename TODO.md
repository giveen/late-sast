# TODO

## Preserve What Is Working

- Preserve deterministic orchestration and validated phase transitions in `internal/orchestrator/base.go` and `internal/orchestrator/state_machine.go`.
- Preserve shared cache plus invalidation behavior in `internal/executor/toolcache.go` and `internal/executor/executor.go`.
- Preserve GPU coordination in `internal/executor/coordinator.go`.
- Preserve structured scan/report tooling in `internal/tool/run_trivy_scan.go`, `internal/tool/run_semgrep_scan.go`, `internal/tool/run_secrets_scanner.go`, `internal/tool/run_exploit_replay.go`, `internal/tool/cleanup_scan_environment.go`, and `internal/tool/write_sast_report.go`.
- Preserve malformed tool-call repair and session hardening in `internal/session/session.go`.

## Highest-Priority Work

### ~~1. Add full-pipeline regression coverage~~ ✓ DONE

- ~~Build end-to-end coverage for setup -> readiness -> scan -> replay -> report -> cleanup.~~
- ~~Add `cmd/late-sast` tests that protect cross-component contracts instead of only isolated tool behavior.~~
- ~~Add failure-injection coverage for cleanup, report writing, retest parsing, MCP discovery, and user-visible error paths.~~

> Completed: scan assembly extraction with injectable deps, 11 regression tests in `cmd/late-sast/main_test.go` covering core tools registration, report round-trip, retest parsing, blackboard injection, and 4 failure-injection paths (prompt load, mkdirAll, retest readFile, non-existent retest path).  Backend discovery tests added in `internal/client/client_test.go`.

### 2. Finish incremental rescan architecture

- ~~Phase 1: deterministic keys (`HashFile`, `HashBytes`, `TransformKey`), `Store` interface, `FileStore` with atomic writes and reopen safety, `ComputeDeltaScope` — done in `internal/rescan/`.~~
- ~~Phase 2: stable `FindingID` (CWE+location+title SHA-256), `FindingRecord` model, `FindingStatus` enum, `GetFinding`/`PutFinding`/`ListFindings` on `Store` + `FileStore`, `Reconcile()` with insert/update/resolve/unchanged logic, 14 new tests — done.~~
- Phase 3: full lineage edges, scope-aware retest mode.
- Measure rescan performance and report churn before/after.

### 3. Standardize operator-visible error handling

- Surface important failures in the GUI/event stream, not only stderr or Fyne logs.
- Focus areas: MCP discovery, cleanup failures, allowlist persistence, report writing, rescan lifecycle.

## Outstanding Issues

- ~~Missing full-pipeline regression coverage is still the biggest practical risk.~~ ✓ Done.
- Incremental rescan Phase 1 scaffolded in `internal/rescan/`; Phases 2–3 (reconciliation, lineage, diff-first reports) still needed.
- Architecture metadata fetch can still be lost too early if fetch timing is wrong.
- Some failures still log only to stderr/Fyne logs instead of appearing in the operator workflow.
- Setup/container bootstrap remains expensive.
- The lingering `--tui` behavior in `cmd/late-sast/main.go` should be made explicit or removed.

## Performance Opportunities

### Best near-term wins

- Reduce setup overhead in `internal/tool/bootstrap_scan_toolchain.go`, `internal/tool/setup_container.go`, and `internal/tool/launch_docker.go`.
- Fix/revisit architecture metadata fetch retry behavior in `cmd/late-sast/main.go`.
- Benchmark cache-hit ratio and tool/runtime distribution before optimizing execution ordering.

### Later performance work

- Explore bounded parallel execution for independent read-only tools in `internal/executor/executor.go` after stronger integration coverage exists.
- Consider more granular cache invalidation only after correctness harnesses are in place.

## Recommended Execution Order

1. ~~Add full-pipeline regression tests.~~ ✓ Done.
2. Finish incremental rescan architecture (Phases 2–3).
3. Standardize operator-visible error propagation.
4. Reduce setup/runtime overhead.
5. Revisit executor-level parallelism only after the above is protected by tests.
