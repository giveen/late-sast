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

### ~~2. Finish incremental rescan architecture~~ ✓ DONE

- ~~Phase 1: deterministic keys (`HashFile`, `HashBytes`, `TransformKey`), `Store` interface, `FileStore` with atomic writes and reopen safety, `ComputeDeltaScope` — done in `internal/rescan/`.~~
- ~~Phase 2: stable `FindingID` (CWE+location+title SHA-256), `FindingRecord` model, `FindingStatus` enum, `GetFinding`/`PutFinding`/`ListFindings` on `Store` + `FileStore`, `Reconcile()` with insert/update/resolve/unchanged logic, 14 new tests — done.~~
- ~~Phase 3: full lineage edges (`LineageEdge`, `PutLineageEdge`, `ListEdgesFrom`/`To`/`All`, persisted in `storeState`), scope-aware retest (`RetestScope` — triggers on changed source, unconfirmed exploit, new/updated status, or lineage ancestor needing retest), 16 new tests — done.~~
- Measure rescan performance and report churn before/after.

### ~~CVE search quality fix~~ ✓ DONE

> Parse CVE 5.x API format in Go (`parseCVE5SearchResponse`, `parseCVE5SingleResponse`, `parseCVE5LastResponse`); return `ParsedCVEFinding` records with real `cvss`, `package`, `severity`, `description`, `affected_versions`; added `min_cvss` and `limit` params to `vul_vendor_product_cve`; updated SAST scanner prompts to document structured output and forbid inventing CVE IDs.

### ~~3. Standardize operator-visible error handling~~ ✓ DONE

- ~~Surface important failures in the GUI/event stream, not only stderr or Fyne logs.~~
- ~~Focus areas: MCP discovery, cleanup failures, allowlist persistence, report writing, rescan lifecycle.~~

> `debug.Logger.LogOperatorError` added — always writes `[operator-error] <component>: <msg>` to stderr, also writes `OPERATOR_ERROR` event to debug log when enabled. MCP load/connect/close errors use the prefix. `confirm.go` allowlist-save failures replaced with `dialog.ShowError`. `cleanup_scan_environment` partial responses include `operator_note` listing failed steps. `WriteSASTReportTool.OnError` callback wired to `debugLog.LogOperatorError` in scan build. 2 new debug logger tests.

## Outstanding Issues

- ~~Missing full-pipeline regression coverage is still the biggest practical risk.~~ ✓ Done.
- ~~CVE tools returned raw API JSON causing `unknown:unknown` packages and `0.0` CVSS scores.~~ ✓ Fixed.
- ~~Incremental rescan Phases 1–2 done; Phase 3 (lineage edges, scope-aware retest) still needed.~~ ✓ Done.
- ~~Architecture metadata fetch can still be lost too early if fetch timing is wrong.~~ ✓ Fixed.
- ~~Some failures still log only to stderr/Fyne logs instead of appearing in the operator workflow.~~ ✓ Fixed.
- ~~Setup/container bootstrap remains expensive.~~ ✓ Partially addressed (bootstrap batch execs + docker inspect merge).
- ~~The lingering `--tui` behavior in `cmd/late-sast/main.go` should be made explicit or removed.~~ ✓ Fixed (flag description updated to reflect actual behavior).

## Performance Opportunities

### ~~5. Reduce setup/runtime overhead~~ ✓ DONE

- ~~Reduce setup overhead in `internal/tool/bootstrap_scan_toolchain.go`, `internal/tool/setup_container.go`, and `internal/tool/launch_docker.go`.~~
- ~~Fix/revisit architecture metadata fetch retry behavior in `cmd/late-sast/main.go`.~~
- ~~Benchmark cache-hit ratio and tool/runtime distribution before optimizing execution ordering.~~

> `bootstrap_scan_toolchain` batches 12 serial `commandAvailable` docker execs into one (`batchAvailabilityCmd`/`parseBatchAvailability`) and collapses PM detection + node/go/cargo presence + project marker scans into one more (`batchProbeCmd`/`parseBatchProbe`) — ~18-20 exec calls → ~9-11 per invocation. Architecture metadata fetch replaced `sync.Once` with `sync.Mutex + bool` so failed fetches (e.g. MCP not yet connected) are retried on subsequent subagent spawns.

### Later performance work

- Explore bounded parallel execution for independent read-only tools in `internal/executor/executor.go` after stronger integration coverage exists.
- Consider more granular cache invalidation only after correctness harnesses are in place.

## Recommended Execution Order

1. ~~Add full-pipeline regression tests.~~ ✓ Done.
2. ~~CVE search quality fix (parse CVE 5.x format).~~ ✓ Done.
3. ~~Finish incremental rescan (Phases 1–3).~~ ✓ Done.
4. ~~Standardize operator-visible error propagation.~~ ✓ Done.
5. ~~Reduce setup/runtime overhead.~~ ✓ Done.
6. ~~Revisit executor-level parallelism only after the above is protected by tests.~~ ✓ Done.

## Codebase Health Backlog

Coverage gaps and correctness issues identified during post-TODO health scan. All items are fixes/hardening, no new features.

### Test Coverage Gaps (by risk)

- ✅ **`buildReplayEndpoint` (13.3%)** in `internal/tool/run_exploit_replay.go` — URL assembly for exploit replays; missing cases: empty host, invalid port, path normalization, query encoding.
- ✅ **`cacheTTLFor` (16.7%) / `toolTimeoutFor` (30.8%)** in `internal/executor/toolcache.go` — entire switch tables lack coverage; any refactor silently breaks TTL/timeout assignments.
- ✅ **`asInt` (22.2%) / `extractTrufflehogLocation` (37.5%)** in `internal/tool/run_secrets_scanner.go` — output parsing helpers; missing branch coverage on malformed input.
- ✅ **`replayCandidateFromArgs` (26.7%) / `looksLikeAdHocCleanup` (28.6%)** in `internal/agent/agent.go` — agent middleware heuristics; untested negative/edge branches.
- ✅ **`classifyReplayVerdict` (63.6%)** in `internal/tool/run_exploit_replay.go` — missing verdict paths: blocked, patched, inconclusive.
- ✅ **`getToolParam` (54.5%)** in tool parsing utilities — used widely; partial branch coverage.
- ✅ **`ensureSecureConfigPermissions` (57.1%)** in `internal/config/config.go` — security-relevant file mode enforcement; chmod failure branch not exercised.
- ✅ **`EstimateToolDefinitionTokens` (28.6%)** in `internal/common/utils.go` — zero test coverage.
- ✅ **Session hot-path functions at 0%** in `internal/session/session.go`: `AddToolResultMessage`, `ExecuteTool`, `LogDebugToolResult`, `classifyToolResult`, `previewToolCallArgs`.

### Correctness Issues

#### Signal / Cancellation

- ✅ **`stopCh` unbuffered in `internal/orchestrator/base.go:53`** — `Cancel()` does a non-blocking send on an unbuffered channel; the signal is always silently dropped and `IsStopRequested()` can never return `true`. Fixed: `make(chan struct{}, 1)`.
- ✅ **Context reset to `context.Background()` in `internal/orchestrator/base.go`** (lines 156, 231, 322) — resets caller-injected values (`SkipConfirmationKey`, `ToolApprovalKey`) after any cancellation; confirmation middleware stops being skipped on re-submission. Fixed: `rootCtx` field stores caller context; all three reset points use `o.rootCtx`.
- ✅ **`http.Get` without context + unbounded `io.Copy` in `cmd/late-sast/main.go`** — download could hang indefinitely; corrupted archive could write unlimited data to `~/.local/bin/`. Fixed: `http.NewRequestWithContext` with a 2-minute timeout; `io.LimitReader(tr, 50<<20)` caps extraction.
- ✅ **`exec.Command` without context in `internal/git/worktree.go`** — all five git calls can hang indefinitely on a slow/network filesystem. Fixed: `ctx context.Context` threaded through all four functions; `exec.CommandContext` used throughout. Also: swallowed `_ = output` errors now surface git stderr in the error message; symlink comparison in `GetActiveWorktree` uses `filepath.EvalSymlinks` on both sides.
- ✅ **`ConsumeStream` drops stream error on context cancellation** (`internal/executor/executor.go:497`) — the `ctx.Done()` path returns `nil` without draining `errCh`; network errors are silently lost. Fix: non-blocking drain of `errCh` before returning.

#### Security / Resource Safety

- ✅ **Unbounded `io.Copy` in tar extraction** — fixed above.
- ✅ **Unsafe `atomicWrite` temp file pattern** (`internal/rescan/file_store.go`) — `os.CreateTemp` + rename replaces fixed `.tmp` suffix; `SaveRunSummary` race eliminated.

#### Correctness (Parsing / Classification)

- ✅ **Parallel batch timeout misclassification in `internal/executor/executor.go:206`** — after all goroutines finish, every failure is checked against `turnCtx.Err()`; a deadline expiry on one tool mismarks all concurrent failures as `TimedOut`. Fixed: added `callCtxErr error` to `parallelToolResult`, captured inside the goroutine, checked with `errors.Is(pr.callCtxErr, context.DeadlineExceeded)` per-result.
- ✅ **`io.ReadAll` error discarded in `internal/tool/run_exploit_replay.go:265`** — `b, _ := io.ReadAll(...)` silently truncates the body; indicators in the unread portion cause incorrect `inconclusive` verdicts. Fixed: error is checked and returned from `doReplayRequest`.
- ✅ **Swallowed errors** in `internal/git/worktree.go` — fixed above (git stderr now propagated).
- ✅ **Symlink path comparison in `internal/git/worktree.go:112`** — fixed above (`filepath.EvalSymlinks` on both sides).
- ✅ **Context file read errors swallowed in `internal/agent/agent.go`** — failed reads now log to stderr with filename and error; subagent prompt construction continues with available files.

#### Test Brittleness

- ✅ **Flaky heartbeat test in `internal/tool/sast_tools_test.go`** — replaced sleep+counter with channel synchronisation: runner blocks on channel, callback sends to it; `HeartbeatThrottle: 1` ensures every tick fires.
- ✅ **Sleep-based GUI synchronization in `internal/gui/sast_picker.go:85`** — replaced `time.Sleep(300ms)` with a second `fyne.Do` callback issued from a goroutine; channel closes only after all layout/render work queued by `SetContent` has drained from Fyne's event queue.

#### Performance

- **Rescan performance is unmeasured** — Phase 3 lineage/retest completed but churn ratio before/after was never benchmarked. Add a benchmark or log line reporting delta scope size vs total findings on each run.
