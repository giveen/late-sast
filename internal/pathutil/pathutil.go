package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
)

func LateConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "late"), nil
}

func LateSessionDir() (string, error) {
	if runtime.GOOS == "windows" {
		// Use UserConfigDir on Windows to keep all app state under AppData.
		lateConfigDir, err := LateConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(lateConfigDir, "sessions"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".local", "share", "late", "sessions"), nil
}

// LateProjectMCPConfigPath returns the relative project-local MCP config
// location (".late/mcp_config.json"), resolved relative to process CWD.
func LateProjectMCPConfigPath() string {
	return filepath.Join(".late", "mcp_config.json")
}

func LateUserMCPConfigPath() (string, error) {
	lateConfigDir, err := LateConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(lateConfigDir, "mcp_config.json"), nil
}

func LateSkillsDir() (string, error) {
	lateConfigDir, err := LateConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(lateConfigDir, "skills"), nil
}

func LateProjectSkillsDir() string {
	return filepath.Join(".late", "skills")
}

// LateSASTCacheDir returns the cache directory for late-sast
// (~/.cache/late-sast on Linux/macOS, %LocalAppData%\late-sast\cache on Windows).
// Files here persist across runs and are safe to delete manually.
func LateSASTCacheDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "late-sast"), nil
}

// LateSASTConfigDir returns the config directory for late-sast.
// It prefers ~/.config/late-sast/ when that directory already contains a
// config.json (i.e. the user has explicitly set it up), and falls back to
// ~/.config/late/ for seamless compatibility with an existing late installation.
func LateSASTConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	sastDir := filepath.Join(configDir, "late-sast")
	if _, err := os.Stat(filepath.Join(sastDir, "config.json")); err == nil {
		return sastDir, nil
	}
	return filepath.Join(configDir, "late"), nil
}
