package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// BootstrapScanToolchainTool installs scan/build essentials in an existing
// container and returns a structured availability summary.
type BootstrapScanToolchainTool struct {
	Runner setupCommandRunner
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
		runner = runSetupCommand
	}

	logs := make([]string, 0, 16)
	appendLog := func(label, out string) {
		out = strings.TrimSpace(out)
		if out == "" {
			return
		}
		logs = append(logs, label+": "+truncate(out, 700))
	}

	pmOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", detectPackageManagerCmd())
	pm := strings.TrimSpace(pmOut)
	if pm == "" {
		pm = "unknown"
	}

	coreOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", coreBootstrapCmd(pm))
	appendLog("core", coreOut)

	hasJavaProject := false
	if installJavaDetected {
		jOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", javaMarkerCmd(p.RepoPath))
		hasJavaProject = strings.TrimSpace(jOut) != ""
		if hasJavaProject {
			jInstallOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installJavaCmd(pm))
			appendLog("java", jInstallOut)
		}
	}

	hasNodeProject := false
	nodePresent := commandAvailable(ctx, runner, p.ContainerName, "node")
	if installNodeDetected && !nodePresent {
		nOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", nodeMarkerCmd(p.RepoPath))
		hasNodeProject = strings.TrimSpace(nOut) != ""
		if hasNodeProject {
			nInstallOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installNodeCmd(pm))
			appendLog("node", nInstallOut)
		}
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
	if installGosec && commandAvailable(ctx, runner, p.ContainerName, "go") {
		gOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installGosecCmd())
		appendLog("gosec", gOut)
	}
	if installCargoAudit && commandAvailable(ctx, runner, p.ContainerName, "cargo") {
		caOut, _ := runner(ctx, "docker", "exec", p.ContainerName, "sh", "-c", installCargoAuditCmd())
		appendLog("cargo-audit", caOut)
	}

	availability := map[string]string{
		"curl":        boolStatus(commandAvailable(ctx, runner, p.ContainerName, "curl")),
		"git":         boolStatus(commandAvailable(ctx, runner, p.ContainerName, "git")),
		"jq":          boolStatus(commandAvailable(ctx, runner, p.ContainerName, "jq")),
		"python3":     boolStatus(commandAvailable(ctx, runner, p.ContainerName, "python3")),
		"pipx":        boolStatus(commandAvailable(ctx, runner, p.ContainerName, "pipx")),
		"java":        boolStatus(commandAvailable(ctx, runner, p.ContainerName, "java")),
		"node":        boolStatus(commandAvailable(ctx, runner, p.ContainerName, "node")),
		"trivy":       boolStatus(commandAvailable(ctx, runner, p.ContainerName, "trivy")),
		"semgrep":     boolStatus(commandAvailable(ctx, runner, p.ContainerName, "semgrep")),
		"checksec":    boolStatus(commandAvailable(ctx, runner, p.ContainerName, "checksec")),
		"gosec":       boolStatus(commandAvailable(ctx, runner, p.ContainerName, "gosec")),
		"cargo_audit": boolStatus(commandAvailable(ctx, runner, p.ContainerName, "cargo-audit")),
	}

	status := "ok"
	reason := ""
	if pm == "unknown" {
		status = "partial"
		reason = "unknown package manager; attempted best-effort tool bootstrap"
	}

	result := map[string]any{
		"status":                status,
		"reason":                reason,
		"container_name":        p.ContainerName,
		"repo_path":             p.RepoPath,
		"package_manager":       pm,
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

func commandAvailable(ctx context.Context, runner setupCommandRunner, container, name string) bool {
	out, _ := runner(ctx, "docker", "exec", container, "sh", "-c", "command -v "+name+" >/dev/null 2>&1 && echo ok || echo missing")
	return strings.TrimSpace(out) == "ok"
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

func javaMarkerCmd(repoPath string) string {
	rp := shQuote(repoPath)
	return fmt.Sprintf("find %s -maxdepth 4 \\( -name '*.java' -o -name '*.kt' -o -name '*.kts' -o -name 'pom.xml' -o -name '*.gradle' \\) -print -quit 2>/dev/null", rp)
}

func nodeMarkerCmd(repoPath string) string {
	rp := shQuote(repoPath)
	return fmt.Sprintf("find %s -maxdepth 3 \\( -name 'package.json' -o -name '*.ts' -o -name '*.js' \\) -print -quit 2>/dev/null", rp)
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

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
