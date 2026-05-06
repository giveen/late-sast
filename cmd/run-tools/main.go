package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"late/internal/tool/docker"
	"late/internal/tool/exploit"
	"late/internal/tool/sast"
)

func main() {
	toolName := flag.String("tool", "", "Tool to run: assess_disclosure_context | cleanup_scan_environment | write_sast_report")
	argsJSON := flag.String("args", "", "JSON object of tool arguments")
	flag.Parse()

	if *toolName == "" || *argsJSON == "" {
		fmt.Println("Usage: run-tools --tool <assess_disclosure_context|cleanup_scan_environment|write_sast_report> --args '<json>'")
		return
	}

	ctx := context.Background()
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(*argsJSON), &raw); err != nil {
		fmt.Printf("ERROR: --args must be valid JSON: %v\n", err)
		return
	}

	var (
		result string
		err    error
	)

	switch *toolName {
	case "assess_disclosure_context":
		result, err = exploit.AssessDisclosureContextTool{}.Execute(ctx, raw)
	case "cleanup_scan_environment":
		result, err = docker.CleanupScanEnvironmentTool{}.Execute(ctx, raw)
	case "write_sast_report":
		result, err = sast.WriteSASTReportTool{}.Execute(ctx, raw)
	default:
		fmt.Printf("ERROR: unsupported --tool %q\n", *toolName)
		return
	}

	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	fmt.Println(result)
}
