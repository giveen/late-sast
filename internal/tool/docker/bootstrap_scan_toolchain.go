package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"late/internal/tool"
	"strings"
)

// BootstrapScanToolchainTool installs scan/build essentials in an existing
// container and returns a structured availability summary.
type BootstrapScanToolchainTool struct {
	Runner tool.CommandRunner
}

func (t BootstrapScanToolchainTool) Name() string { return "bootstrap_scan_toolchain" }

func (t BootstrapScanToolchainTool) Description() string {
	return "Bootstrap scan toolchain in an existing container (core utils, conditional JDK/Node, Trivy, Semgrep, Checksec, Gosec, Cargo Audit)."
}

func (t BootstrapScanToolchainTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_name": {"type": "string", "description": "Target container name"},
			"repo_path": {"type": "string", "description": "Repository path inside container for language marker detection (default: /repo)"},
			"install_java_if_detected": {"type": "boolean", "description": "Install JDK when Java markers are detected (default: true)"},
			"install_node_if_detected": {"type": "boolean", "description": "Install Node/npm when JS/TS markers are detected and node is missing (default: true)"},
			"install_trivy": {"type": "boolean", "description": "Install Trivy if missing (default: true)"},
			"install_semgrep": {"type": "boolean", "description": "Install Semgrep if missing (default: true)"},
			"install_checksec": {"type": "boolean", "description": "Install Checksec if missing (default: true)"},
			"install_gosec": {"type": "boolean", "description": "Install Gosec when Go is present (default: true)"},
			"install_cargo_audit": {"type": "boolean", "description": "Install cargo-audit when cargo is present (default: true)"}
		},
		"required": ["container_name"]
	}`)
}

func (t BootstrapScanToolchainTool) RequiresConfirmation(_ json.RawMessage) bool { return false }

func (t BootstrapScanToolchainTool) CallString(args json.RawMessage) string {
	var p struct {
		ContainerName string `json:"container_name"`
		RepoPath      string `json:"repo_path"`
	}
	_ = json.Unmarshal(args, &p)
	repoPath := strings.TrimSpace(p.RepoPath)
	if repoPath == "" {
		repoPath = "/repo"
	}
	return fmt.Sprintf("bootstrap_scan_toolchain(container=%q, repo_path=%q)", p.ContainerName, repoPath)
}

func (t BootstrapScanToolchainTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	var p struct {
		ContainerName       string `json:"container_name"`
		RepoPath            string `json:"repo_path"`
		InstallJavaDetected *bool  `json:"install_java_if_detected"`
		InstallNodeDetected *bool  `json:"install_node_if_detected"`
		InstallTrivy        *bool  `json:"install_trivy"`
		InstallSemgrep      *bool  `json:"install_semgrep"`
		InstallChecksec     *bool  `json:"install_checksec"`
		InstallGosec        *bool  `json:"install_gosec"`
		InstallCargoAudit   *bool  `json:"install_cargo_audit"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}
	if strings.TrimSpace(p.ContainerName) == "" {
		return "", fmt.Errorf("container_name is required")
	}
	if strings.TrimSpace(p.RepoPath) == "" {
		p.RepoPath = "/repo"
	}

	installJavaDetected := boolDefault(p.InstallJavaDetected, true)
	installNodeDetected := boolDefault(p.InstallNodeDetected, true)
	installTrivy := boolDefault(p.InstallTrivy, true)
	installSemgrep := boolDefault(p.InstallSemgrep, true)
	installChecksec := boolDefault(p.InstallChecksec, true)
	installGosec := boolDefault(p.InstallGosec, true)
	installCargoAudit := boolDefault(p.InstallCargoAudit, true)

	runner := t.Runner
	if runner == nil {
		runner = tool.RunSetupCommand
	}

	logs := make([]string, 0, 16)
	appendLog := func(label, out string) {
		out = strings.TrimSpace(out)
		if out == "" {
			return
		}
		logs = append(logs, label+": "+tool.Truncate(out, 700))
	}

	// Single exec: detect package manager + command availability + repo markers.
	probeOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", batchProbeCmd(p.RepoPath))
	probe := parseBatchProbe(probeOut)

	coreOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", coreBootstrapCmd(probe.pm))
	appendLog("core", coreOut)

	hasJavaProject := probe.javaProject
	if installJavaDetected && hasJavaProject {
		jInstallOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installJavaCmd(probe.pm))
		appendLog("java", jInstallOut)
	}

	hasNodeProject := probe.nodeProject
	if installNodeDetected && !probe.nodeCmd && hasNodeProject {
		nInstallOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installNodeCmd(probe.pm))
		appendLog("node", nInstallOut)
	}

	if installTrivy {
		tOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installTrivyCmd())
		appendLog("trivy", tOut)
	}
	if installSemgrep || installChecksec {
		pipxOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", ensurePipxCmd())
		appendLog("pipx", pipxOut)
	}
	if installSemgrep {
		sOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installSemgrepCmd())
		appendLog("semgrep", sOut)
	}
	if installChecksec {
		cOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installChecksecCmd())
		appendLog("checksec", cOut)
	}
	if installGosec && probe.goCmd {
		gOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installGosecCmd())
		appendLog("gosec", gOut)
	}
	if installCargoAudit && probe.cargoCmd {
		caOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installCargoAuditCmd())
		appendLog("cargo-audit", caOut)
	}

	// Single exec: check availability of all tools at once.
	availOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", batchAvailabilityCmd())
	availability := parseBatchAvailability(availOut)

	status := "ok"
	reason := ""
	if probe.pm == "unknown" {
		status = "partial"
		reason = "unknown package manager; attempted best-effort tool bootstrap"
	}

	result := map[string]any{
		"status":                status,
		"reason":                reason,
		"container_name":        p.ContainerName,
		"repo_path":             p.RepoPath,
		"package_manager":       probe.pm,
		"detected_java_project": hasJavaProject,
		"detected_node_project": hasNodeProject,
		"availability":          availability,
		"logs":                  strings.Join(logs, "\n"),
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

func boolDefault(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}

func boolStatus(v bool) string {
	if v {
		return "available"
	}
	return "missing"
}

// commandAvailable is kept for callers outside bootstrap (e.g. tests).
func commandAvailable(ctx context.Context, runner tool.CommandRunner, container, name string) bool {
	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v "+name+" >/dev/null 2>&1 && echo ok || echo missing")
	return strings.TrimSpace(out) == "ok"
}

// batchProbeCmd returns a shell one-liner that detects the package manager,
// presence of node/go/cargo commands, and Java/Node project markers in one exec.
// Output format: one "key=value" pair per line.
func batchProbeCmd(repoPath string) string {
	rp := tool.ShQuote(repoPath)
	return fmt.Sprintf(
		`if command -v apt-get >/dev/null 2>&1; then echo pm=apt;`+
			` elif command -v apk >/dev/null 2>&1; then echo pm=apk;`+
			` elif command -v yum >/dev/null 2>&1; then echo pm=yum;`+
			` elif command -v dnf >/dev/null 2>&1; then echo pm=dnf;`+
			` else echo pm=unknown; fi;`+
			` command -v node >/dev/null 2>&1 && echo node=ok || echo node=missing;`+
			` command -v go >/dev/null 2>&1 && echo go=ok || echo go=missing;`+
			` command -v cargo >/dev/null 2>&1 && echo cargo=ok || echo cargo=missing;`+
			` { find %s -maxdepth 4 \( -name '*.java' -o -name '*.kt' -o -name '*.kts' -o -name 'pom.xml' -o -name '*.gradle' \) -print -quit 2>/dev/null | grep -q . && echo java_project=yes || echo java_project=no; };`+
			` { find %s -maxdepth 3 \( -name 'package.json' -o -name '*.ts' -o -name '*.js' \) -print -quit 2>/dev/null | grep -q . && echo node_project=yes || echo node_project=no; }`,
		rp, rp,
	)
}

type batchProbeResult struct {
	pm          string
	nodeCmd     bool
	goCmd       bool
	cargoCmd    bool
	javaProject bool
	nodeProject bool
}

func parseBatchProbe(output string) batchProbeResult {
	r := batchProbeResult{pm: "unknown"}
	for _, line := range strings.Split(output, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "pm":
			r.pm = v
		case "node":
			r.nodeCmd = v == "ok"
		case "go":
			r.goCmd = v == "ok"
		case "cargo":
			r.cargoCmd = v == "ok"
		case "java_project":
			r.javaProject = v == "yes"
		case "node_project":
			r.nodeProject = v == "yes"
		}
	}
	return r
}

// batchAvailabilityCmd returns a shell one-liner that checks all scan tool
// availability in a single docker exec. Output: "tool=available/missing" per line.
func batchAvailabilityCmd() string {
	tools := []struct{ cmd, key string }{
		{"curl", "curl"}, {"git", "git"}, {"jq", "jq"},
		{"python3", "python3"}, {"pipx", "pipx"}, {"java", "java"},
		{"node", "node"}, {"trivy", "trivy"}, {"semgrep", "semgrep"},
		{"checksec", "checksec"}, {"gosec", "gosec"}, {"cargo-audit", "cargo_audit"},
	}
	var sb strings.Builder
	for _, t := range tools {
		fmt.Fprintf(&sb, "command -v %s >/dev/null 2>&1 && echo %s=available || echo %s=missing; ", t.cmd, t.key, t.key)
	}
	return strings.TrimRight(sb.String(), " ")
}

func parseBatchAvailability(output string) map[string]string {
	result := make(map[string]string, 12)
	for _, line := range strings.Split(output, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

func detectPackageManagerCmd() string {
	return "if command -v apt-get >/dev/null 2>&1; then echo apt; " +
		"elif command -v apk >/dev/null 2>&1; then echo apk; " +
		"elif command -v yum >/dev/null 2>&1; then echo yum; " +
		"elif command -v dnf >/dev/null 2>&1; then echo dnf; " +
		"else echo unknown; fi"
}

func coreBootstrapCmd(pm string) string {
	switch pm {
	case "apt":
		return "apt-get update -qq 2>/dev/null && apt-get install -y -qq curl wget bash procps git jq build-essential gcc g++ make python3 python3-pip python3-venv pipx 2>/dev/null || true"
	case "apk":
		return "apk add --no-cache curl wget bash procps git jq build-base gcc g++ make python3 py3-pip pipx 2>/dev/null || true"
	case "yum":
		return "yum install -y -q curl wget bash procps git jq gcc gcc-c++ make python3 python3-pip 2>/dev/null || true"
	case "dnf":
		return "dnf install -y -q curl wget bash procps git jq gcc gcc-c++ make python3 python3-pip 2>/dev/null || true"
	default:
		return "echo 'no known package manager'"
	}
}

func installJavaCmd(pm string) string {
	switch pm {
	case "apt":
		return "apt-get install -y -qq default-jdk-headless 2>/dev/null || true"
	case "apk":
		return "apk add --no-cache openjdk17-jre-headless 2>/dev/null || true"
	case "yum":
		return "yum install -y -q java-17-openjdk-headless 2>/dev/null || true"
	case "dnf":
		return "dnf install -y -q java-17-openjdk-headless 2>/dev/null || true"
	default:
		return "echo 'skip java install: unknown package manager'"
	}
}

func installNodeCmd(pm string) string {
	switch pm {
	case "apt":
		return "apt-get install -y -qq nodejs npm 2>/dev/null || true"
	case "apk":
		return "apk add --no-cache nodejs npm 2>/dev/null || true"
	case "yum":
		return "yum install -y -q nodejs npm 2>/dev/null || true"
	case "dnf":
		return "dnf install -y -q nodejs npm 2>/dev/null || true"
	default:
		return "echo 'skip node install: unknown package manager'"
	}
}

func installTrivyCmd() string {
	return "command -v trivy >/dev/null 2>&1 || (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true)"
}

func ensurePipxCmd() string {
	return "if ! command -v pipx >/dev/null 2>&1; then python3 -m pip install --quiet --break-system-packages pipx 2>/dev/null || python3 -m pip install --quiet pipx 2>/dev/null || true; fi"
}

func installSemgrepCmd() string {
	return "export PIPX_BIN_DIR=/usr/local/bin; command -v semgrep >/dev/null 2>&1 || (pipx install semgrep 2>/dev/null || pip install --quiet --break-system-packages semgrep 2>/dev/null || python3 -m pip install --quiet --break-system-packages semgrep 2>/dev/null || true)"
}

func installChecksecCmd() string {
	return "export PIPX_BIN_DIR=/usr/local/bin; command -v checksec >/dev/null 2>&1 || (pipx install checksec 2>/dev/null || pip install --quiet --break-system-packages checksec 2>/dev/null || python3 -m pip install --quiet --break-system-packages checksec 2>/dev/null || true)"
}

func installGosecCmd() string {
	return "command -v go >/dev/null 2>&1 && go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null || true"
}

func installCargoAuditCmd() string {
	return "command -v cargo >/dev/null 2>&1 && cargo install cargo-audit --quiet 2>/dev/null || true"
}
