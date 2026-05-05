# Idea: Incremental Rescan Architecture for late-sast

## Problem
Current rescans can re-run too much work, produce noisy report churn, and spend time in repeated tool/subagent loops even when only a small part of the code changed.

## Proposal
Introduce an incremental, lineage-aware rescan pipeline where:

1. Only changed source inputs are reprocessed.
2. Expensive transform outputs are memoized by deterministic keys.
3. Findings are reconciled (insert/update/remove) instead of regenerated wholesale.
4. Reports become diff-first (new/changed/resolved/unchanged).
5. Every finding has stable identity + source lineage.

## Core Concepts

### 1) Deterministic Keys
- Source key: repo + path + content hash
- Transform key: stage name + transform version hash + input hash
- Artifact key: finding identity key (rule + location + normalized evidence)

### 2) Incremental Levels
- Source-level: only changed files/items enter pipeline.
- Function-level: skip expensive transforms when key is unchanged.
- Target-level: reconcile output state using minimal DB/object mutations.

### 3) Lineage
Attach provenance for each finding:
- Source file and line/span
- Transform and version used
- Run ID and timestamps
- Previous finding state for diff tracking

## Candidate Implementation (Go)

### New package
- internal/rescan/models.go
- internal/rescan/store.go
- internal/rescan/sqlite_store.go
- internal/rescan/hash.go
- internal/rescan/scope.go
- internal/rescan/reconcile.go
- internal/rescan/lineage.go

### Existing files likely to evolve
- cmd/late-sast/main.go
- internal/orchestrator/state_machine.go
- internal/orchestrator/blackboard.go
- internal/tool/run_semgrep_scan.go
- internal/tool/write_sast_report.go
- internal/session/session.go
- internal/debug/logger.go

## Data Model Sketch

### SourceItem
- repo
- path
- content_hash
- commit
- last_seen_at

### TransformRecord
- run_id
- transform_name
- transform_version_hash
- input_hash
- output_hash
- status
- duration_ms

### ArtifactRecord
- artifact_id
- kind
- severity
- payload_hash
- status
- first_seen_run
- last_seen_run

### LineageEdge
- artifact_id
- source_path
- start_line
- end_line
- transform_name
- run_id

### ReconcileResult
- inserted
- updated
- removed
- unchanged

## Runtime Flow
1. Build source inventory + hashes.
2. Compute delta scope from prior state.
3. Execute only impacted transforms.
4. Produce artifact set for current run.
5. Reconcile current artifacts vs prior artifacts.
6. Persist lineage + run summary.
7. Generate diff-first report output.

## Expected Improvements
- Faster rescans on small diffs.
- Lower tool/LLM usage on repeat runs.
- Stable findings with less report churn.
- Better reliability (fewer long no-progress loops).
- Better explainability and auditability.

## Suggested Phased Rollout

### Phase 1 (small + safe)
- Introduce store + deterministic keys.
- Add source/transform memoization for one scan stage.
- Emit delta summary metrics.

### Phase 2
- Add artifact reconcile and stable finding IDs.
- Update report writer to show new/changed/resolved/unchanged.

### Phase 3
- Add full lineage edges and scope-aware retest mode.
- Optional live mode for continuous incremental updates.

## Risks / Tradeoffs
- More state to manage and migrate.
- Requires careful key design to avoid false cache hits/misses.
- Initial complexity increase before performance payoff is realized.

## Success Metrics
- Rescan duration reduction (%)
- Number of skipped transforms per run
- Findings churn rate between nearby commits
- Tool/subagent call count per rescan
- Timeout/failure rate in rescans
