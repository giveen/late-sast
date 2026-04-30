package mcp

import (
	"encoding/json"
	"fmt"
	"late/internal/common"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MCPConfig represents the top-level configuration structure
type MCPConfig struct {
	McpServers map[string]MCPServer `json:"mcpServers"`
}

// MCPServer represents a single MCP server configuration
type MCPServer struct {
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env"`
	Disabled bool              `json:"disabled,omitempty"`
}

// LoadMCPConfig loads the MCP configuration from the first available config file
func LoadMCPConfig() (*MCPConfig, error) {
	return LoadMCPConfigFromDir("")
}

// LoadMCPConfigFromDir loads MCP config preferring userConfigDir, then project-local.
// Pass an empty string to use the default late config directory.
func LoadMCPConfigFromDir(userConfigDir string) (*MCPConfig, error) {
	configPath, err := findConfigPathWithDir(userConfigDir)
	if err != nil {
		return nil, err
	}

	if configPath == "" {
		// Resolve the target dir for pre-population
		var targetDir string
		if userConfigDir != "" {
			targetDir = userConfigDir
		} else {
			d, err := common.LateConfigDir()
			if err != nil {
				return &MCPConfig{McpServers: make(map[string]MCPServer)}, nil
			}
			targetDir = d
		}

		defaultUserPath := filepath.Join(targetDir, "mcp_config.json")

		// Pre-populate with a default config
		emptyConfig := MCPConfig{McpServers: make(map[string]MCPServer)}
		defaultData, _ := json.MarshalIndent(emptyConfig, "", "  ")

		if err := os.MkdirAll(targetDir, 0700); err == nil {
			_ = os.WriteFile(defaultUserPath, defaultData, 0600)
		}

		return &emptyConfig, nil
	}

	return loadConfigFromFile(configPath)
}

// findConfigPath searches for config files in order of precedence
func findConfigPath() (string, error) {
	return findConfigPathWithDir("")
}

// findConfigPathWithDir searches config files, using userConfigDir for the user-level path.
func findConfigPathWithDir(userConfigDir string) (string, error) {
	// 1. Project-level: .late/mcp_config.json in current directory
	projectPath := common.LateProjectMCPConfigPath()
	if _, err := os.Stat(projectPath); err == nil {
		return projectPath, nil
	}

	// 2. User-level config path — prefer provided dir, else default late dir
	var userPath string
	if userConfigDir != "" {
		userPath = filepath.Join(userConfigDir, "mcp_config.json")
	} else {
		var err error
		userPath, err = common.LateUserMCPConfigPath()
		if err != nil {
			return "", fmt.Errorf("failed to get config directory: %w", err)
		}
	}

	if _, err := os.Stat(userPath); err == nil {
		return userPath, nil
	}

	// No config file found
	return "", nil
}

// loadConfigFromFile loads configuration from a specific file
func loadConfigFromFile(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var config MCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Ensure McpServers is not nil
	if config.McpServers == nil {
		config.McpServers = make(map[string]MCPServer)
	}

	return &config, nil
}

// ExpandEnvVars replaces ${VARIABLE} patterns with environment variable values
func ExpandEnvVars(value string) string {
	// Pattern to match ${VARIABLE_NAME}
	re := regexp.MustCompile(`\$\{([^}]+)\}`)

	return re.ReplaceAllStringFunc(value, func(match string) string {
		// Extract variable name from ${VARIABLE_NAME}
		varName := strings.TrimPrefix(strings.TrimSuffix(match, "}"), "${")
		return os.Getenv(varName)
	})
}

// ExpandServerEnvVars expands environment variables in server configuration
func ExpandServerEnvVars(server *MCPServer) {
	// Expand command
	server.Command = ExpandEnvVars(server.Command)

	// Expand args
	for i := range server.Args {
		server.Args[i] = ExpandEnvVars(server.Args[i])
	}

	// Expand env values
	for key, value := range server.Env {
		server.Env[key] = ExpandEnvVars(value)
	}
}
