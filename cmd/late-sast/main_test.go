package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"late/internal/client"
	appconfig "late/internal/config"
	"late/internal/orchestrator"
	"late/internal/tool"
)

func testScanBuildConfig(t *testing.T) scanBuildConfig {
	t.Helper()
	return scanBuildConfig{
		pickedTarget:     "https://github.com/example/app",
		pickedOutputDir:  t.TempDir(),
		defaultOutputDir: t.TempDir(),
		cwd:              "/workspace",
		containerName:    "sast-test",
		workDir:          "/tmp/sast-test",
		networkName:      "sast-test-net",
		composeProject:   "sast-test",
		historyPath:      filepath.Join(t.TempDir(), "history.json"),
		sastCfgDir:       t.TempDir(),
		mainClient:       client.NewClient(client.Config{}),
	}
}

func testScanBuildDeps(t *testing.T) scanBuildDeps {
	t.Helper()
	return scanBuildDeps{
		readPromptFile: func(name string) ([]byte, error) {
			return []byte("prompt ${{REPO_NAME}} ${{OUTPUT_DIR}} ${{VERSION}}"), nil
		},
		readFile:          os.ReadFile,
		mkdirAll:          os.MkdirAll,
		loadConfigFromDir: func(string) (*appconfig.Config, error) { return nil, nil },
		newProContextClient: func() (*tool.ProContextClient, error) {
			return nil, errors.New("docs unavailable in test")
		},
		fetchAndIndexSemgrepRef: func(context.Context, *tool.ContextIndex, string) error {
			return nil
		},
	}
}

func TestParseReportHeader_RoundTripFromWrittenReport(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "sast_report_app.md")
	var notifiedPath string

	rawArgs, err := json.Marshal(map[string]any{
		"output_path": outPath,
		"target":      "https://github.com/example/app",
		"repo_name":   "app",
		"findings": []tool.ReportFinding{
			{
				ID:             "H1",
				Title:          "SSRF in image fetch",
				Location:       "Api.cs:42",
				CWE:            918,
				AuditorVerdict: "CONFIRMED",
				Severity:       "HIGH",
				ExploitStatus:  "EXPLOITED",
				Impact:         "Attacker can reach internal services",
				Fix:            "Validate outbound destinations against an allowlist",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal report args: %v", err)
	}

	_, err = (tool.WriteSASTReportTool{
		OnWritten: func(path string) {
			notifiedPath = path
		},
	}).Execute(context.Background(), json.RawMessage(rawArgs))
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	if notifiedPath != outPath {
		t.Fatalf("expected OnWritten path %q, got %q", outPath, notifiedPath)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	target, repoName := parseReportHeader(string(content))
	if target != "https://github.com/example/app" {
		t.Fatalf("expected parsed target to round-trip, got %q", target)
	}
	if repoName != "app" {
		t.Fatalf("expected parsed repo name to round-trip, got %q", repoName)
	}
	if !strings.Contains(string(content), "Target: https://github.com/example/app") {
		t.Fatal("expected report header to include plain Target line consumed by retest path")
	}
}

func TestReservedPortsFromBaseURLs_SortsAndNormalizes(t *testing.T) {
	ports := reservedPortsFromBaseURLs(
		"https://api.example.com",
		"http://localhost:8080/v1",
		"http://127.0.0.1",
		"https://custom.example.com:8443",
		"not-a-url",
		"http://localhost:8080/duplicate",
	)

	want := []int{80, 443, 8080, 8443}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("unexpected reserved ports: got %v want %v", ports, want)
	}
}

func TestBuildMissionTurnGoal_InjectsBlackboardState(t *testing.T) {
	orchestrator.GlobalBlackboard.ResetExploitState()
	t.Cleanup(orchestrator.GlobalBlackboard.ResetExploitState)

	orchestrator.GlobalBlackboard.SetCurrentHypothesis("SSRF via image proxy")
	orchestrator.GlobalBlackboard.AddStrategistConstraint("avoid repeating blocked payload family")
	orchestrator.GlobalBlackboard.SetExplorerEvidence(`{"path":"/fetch","verdict":"reachable"}`)
	orchestrator.GlobalBlackboard.AppendExploitHistory(orchestrator.ExploitHistoryEntry{
		Turn:      1,
		AttemptID: "attempt-1",
		Outcome:   "FAILED",
		Reason:    "connection reset",
	})

	strategistGoal := buildMissionTurnGoal("strategist", "Plan next attempt")
	for _, snippet := range []string{
		"Plan next attempt",
		"current_hypothesis: SSRF via image proxy",
		"avoid repeating blocked payload family",
		"attempt-1",
		`latest_explorer_evidence: {"path":"/fetch","verdict":"reachable"}`,
	} {
		if !strings.Contains(strategistGoal, snippet) {
			t.Fatalf("strategist goal missing %q:\n%s", snippet, strategistGoal)
		}
	}

	executorGoal := buildMissionTurnGoal("executor", "Try exploit")
	for _, snippet := range []string{
		"Try exploit",
		"current_hypothesis: SSRF via image proxy",
		"avoid repeating blocked payload family",
		`explorer_evidence: {"path":"/fetch","verdict":"reachable"}`,
	} {
		if !strings.Contains(executorGoal, snippet) {
			t.Fatalf("executor goal missing %q:\n%s", snippet, executorGoal)
		}
	}
}

func TestPersistMissionTurnResult_UpdatesSharedMissionState(t *testing.T) {
	orchestrator.GlobalBlackboard.ResetExploitState()
	t.Cleanup(orchestrator.GlobalBlackboard.ResetExploitState)

	persistMissionTurnResult("strategist", `preface {"attempt_id":"s-1","hypothesis":"SQLi via filter","constraints":["avoid login path","use read-only probe first"]} suffix`)
	if got := orchestrator.GlobalBlackboard.CurrentHypothesis(); got != "SQLi via filter" {
		t.Fatalf("unexpected hypothesis: %q", got)
	}
	constraints := orchestrator.GlobalBlackboard.StrategistConstraints()
	if !reflect.DeepEqual(constraints, []string{"avoid login path", "use read-only probe first"}) {
		t.Fatalf("unexpected strategist constraints: %v", constraints)
	}

	persistMissionTurnResult("explorer", `{"path":"/search","observation":"input reflected"}`)
	if got := orchestrator.GlobalBlackboard.ExplorerEvidence(); got != `{"path":"/search","observation":"input reflected"}` {
		t.Fatalf("unexpected explorer evidence: %q", got)
	}

	persistMissionTurnResult("executor", `{"turn":2,"attempt_id":"e-2","outcome":"SUCCESS","reason":"retrieved internal metadata","sandbox_logs":"ok","strategist_constraint":"avoid login path"}`)
	history := orchestrator.GlobalBlackboard.ExploitHistory()
	if len(history) != 1 {
		t.Fatalf("expected 1 exploit history entry, got %d", len(history))
	}
	if history[0].Outcome != "SUCCESS" || history[0].AttemptID != "e-2" {
		t.Fatalf("unexpected exploit history entry: %+v", history[0])
	}

	latest, ok := orchestrator.GlobalBlackboard.LatestExecutorAttempt()
	if !ok {
		t.Fatal("expected latest executor attempt to be recorded")
	}
	if latest.Reason != "retrieved internal metadata" {
		t.Fatalf("unexpected latest executor attempt: %+v", latest)
	}
}

func TestPersistMissionTurnResult_ExecutorInvalidJSONRecordsFailure(t *testing.T) {
	orchestrator.GlobalBlackboard.ResetExploitState()
	t.Cleanup(orchestrator.GlobalBlackboard.ResetExploitState)

	persistMissionTurnResult("executor", "executor returned no json here")

	history := orchestrator.GlobalBlackboard.ExploitHistory()
	if len(history) != 1 {
		t.Fatalf("expected one failure history entry, got %d", len(history))
	}
	if history[0].Outcome != "FAILED" {
		t.Fatalf("expected FAILED outcome, got %+v", history[0])
	}
	if history[0].Reason != "executor response was not valid JSON" {
		t.Fatalf("unexpected failure reason: %+v", history[0])
	}
}

func TestBuildScanSession_RegistersCoreToolsAndReportNotifications(t *testing.T) {
	cfg := testScanBuildConfig(t)
	deps := testScanBuildDeps(t)

	sr, err := buildScanSessionWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("build scan session: %v", err)
	}
	if sr.rootAgent == nil || sr.scanCache == nil {
		t.Fatal("expected root agent and shared cache to be initialized")
	}
	if got := sr.initialMsg; got != "Perform a complete security audit of: https://github.com/example/app" {
		t.Fatalf("unexpected initial message: %q", got)
	}

	for _, toolName := range []string{
		"bash",
		"read_file",
		"write_file",
		"setup_container",
		"launch_docker",
		"wait_for_target_ready",
		"bootstrap_scan_toolchain",
		"write_sast_report",
		"ctx_index",
		"ctx_search",
		"ctx_fetch_and_index",
		"ctx_index_file",
	} {
		if sr.sess.Registry.Get(toolName) == nil {
			t.Fatalf("expected tool %q to be registered", toolName)
		}
	}
	if sr.sess.Registry.Get("docs_resolve") != nil {
		t.Fatal("expected docs tools to be skipped when docs client setup fails")
	}

	outPath := filepath.Join(cfg.pickedOutputDir, "report.md")
	rawArgs, err := json.Marshal(map[string]any{
		"output_path": outPath,
		"target":      cfg.pickedTarget,
		"repo_name":   "app",
		"findings": []tool.ReportFinding{{
			ID:             "H1",
			Title:          "SSRF in image fetch",
			Location:       "Api.cs:42",
			CWE:            918,
			AuditorVerdict: "CONFIRMED",
			Severity:       "HIGH",
			ExploitStatus:  "EXPLOITED",
			Impact:         "Attacker can reach internal services",
			Fix:            "Validate outbound destinations against an allowlist",
		}},
	})
	if err != nil {
		t.Fatalf("marshal report args: %v", err)
	}

	result, err := sr.sess.Registry.Get("write_sast_report").Execute(context.Background(), json.RawMessage(rawArgs))
	if err != nil {
		t.Fatalf("execute write_sast_report: %v", err)
	}
	if !strings.Contains(result, `"status":"ok"`) {
		t.Fatalf("unexpected report result: %s", result)
	}

	select {
	case got := <-sr.reportWrittenCh:
		if got != outPath {
			t.Fatalf("unexpected report callback path: %q", got)
		}
	default:
		t.Fatal("expected report-written notification to be emitted")
	}
}

func TestBuildScanSession_RetestUsesRetestPromptAndParsedTarget(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "previous_report.md")
	reportBody := strings.Join([]string{
		"# SAST Security Report — demo-repo",
		"Date: 2026-05-05",
		"Target: https://github.com/example/retested",
	}, "\n")
	if err := os.WriteFile(reportPath, []byte(reportBody), 0644); err != nil {
		t.Fatalf("write retest report: %v", err)
	}

	cfg := testScanBuildConfig(t)
	cfg.pickedTarget = ""
	cfg.pickedRetestPath = reportPath
	deps := testScanBuildDeps(t)
	var requestedPrompt string
	deps.readPromptFile = func(name string) ([]byte, error) {
		requestedPrompt = name
		return []byte("prompt"), nil
	}

	sr, err := buildScanSessionWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("build retest session: %v", err)
	}
	if requestedPrompt != "prompts/instruction-sast-retest.md" {
		t.Fatalf("expected retest prompt, got %q", requestedPrompt)
	}
	if !strings.Contains(sr.initialMsg, reportPath) {
		t.Fatalf("expected initial message to mention previous report, got %q", sr.initialMsg)
	}
	if !strings.Contains(sr.initialMsg, "https://github.com/example/retested") {
		t.Fatalf("expected initial message to mention parsed target, got %q", sr.initialMsg)
	}
}

func TestBuildScanSession_InvalidRetestReportFails(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "bad_report.md")
	if err := os.WriteFile(reportPath, []byte("# Not a real report\nNo target here"), 0644); err != nil {
		t.Fatalf("write invalid report: %v", err)
	}

	cfg := testScanBuildConfig(t)
	cfg.pickedTarget = ""
	cfg.pickedRetestPath = reportPath

	_, err := buildScanSessionWithDeps(cfg, testScanBuildDeps(t))
	if err == nil {
		t.Fatal("expected invalid retest report to fail")
	}
	if !strings.Contains(err.Error(), "could not find a 'Target:' line") {
		t.Fatalf("unexpected retest error: %v", err)
	}
}
