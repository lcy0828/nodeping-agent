package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runAgentUpgrade(ctx context.Context, cfg config, payload map[string]any, options map[string]any) (map[string]any, error) {
	versionValue := firstNonEmptyStringAgent(
		stringFromMap(payload, "version"),
		stringFromMap(payload, "agent_upgrade"),
		stringOptionAny(options, "version"),
	)
	versionValue = normalizeRequestedUpgradeVersion(versionValue)
	if versionValue == "" {
		versionValue = "latest"
	}
	if !validRequestedUpgradeVersion(versionValue) {
		return nil, fmt.Errorf("invalid upgrade version: %s", versionValue)
	}
	releaseBaseURL := strings.TrimSpace(stringOptionAny(options, "release_base_url"))
	if releaseBaseURL != "" {
		if parsed, err := url.Parse(releaseBaseURL); err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, errors.New("invalid release_base_url")
		}
	}
	mode := normalizeUpgradeMode(cfg.UpgradeMode)
	started := time.Now()
	switch mode {
	case "disabled":
		return nil, errors.New("remote upgrade is disabled on this agent")
	case "request_file":
		result, err := requestFileUpgrade(cfg, versionValue, releaseBaseURL)
		result["agent_upgrade"] = elapsedMS(started)
		return result, err
	case "systemd":
		result, err := systemdUpgrade(ctx, cfg, versionValue, releaseBaseURL)
		result["agent_upgrade"] = elapsedMS(started)
		return result, err
	case "script":
		result, err := scriptUpgrade(ctx, cfg, versionValue, releaseBaseURL)
		result["agent_upgrade"] = elapsedMS(started)
		return result, err
	default:
		if cfg.UpgradeRequestFile != "" && systemdUnitIsActive(upgradePathUnitName(cfg.UpgradeUnit)) {
			result, err := requestFileUpgrade(cfg, versionValue, releaseBaseURL)
			result["agent_upgrade"] = elapsedMS(started)
			return result, err
		}
		if _, err := exec.LookPath("systemctl"); err == nil {
			result, err := systemdUpgrade(ctx, cfg, versionValue, releaseBaseURL)
			result["agent_upgrade"] = elapsedMS(started)
			return result, err
		}
		result, err := scriptUpgrade(ctx, cfg, versionValue, releaseBaseURL)
		result["agent_upgrade"] = elapsedMS(started)
		return result, err
	}
}

func upgradePathUnitName(serviceUnit string) string {
	serviceUnit = strings.TrimSpace(serviceUnit)
	if serviceUnit == "" {
		return "nodeping-agent-update.path"
	}
	if strings.HasSuffix(serviceUnit, ".path") {
		return serviceUnit
	}
	if strings.HasSuffix(serviceUnit, ".service") {
		return strings.TrimSuffix(serviceUnit, ".service") + ".path"
	}
	return serviceUnit + ".path"
}

func systemdUnitIsActive(unit string) bool {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	cmd := exec.Command("systemctl", "is-active", "--quiet", unit)
	return cmd.Run() == nil
}

func normalizeUpgradeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto"
	case "request_file", "request-file", "path":
		return "request_file"
	case "systemd":
		return "systemd"
	case "script":
		return "script"
	case "disabled", "off", "false", "0":
		return "disabled"
	default:
		return "auto"
	}
}

func normalizeRequestedUpgradeVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "nodeping-agent/")
	value = strings.TrimPrefix(value, "v")
	return value
}

func validRequestedUpgradeVersion(value string) bool {
	if value == "latest" {
		return true
	}
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func requestFileUpgrade(cfg config, versionValue string, releaseBaseURL string) (map[string]any, error) {
	path := strings.TrimSpace(cfg.UpgradeRequestFile)
	if path == "" {
		return nil, errors.New("NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	request := map[string]any{
		"version":      versionValue,
		"requested_at": time.Now().UTC(),
		"agent_id":     cfg.AgentID,
	}
	if releaseBaseURL != "" {
		request["release_base_url"] = releaseBaseURL
	}
	raw, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".nodeping-agent-update-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(append(raw, '\n'))
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return nil, writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return nil, closeErr
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	return map[string]any{
		"mode":         "request_file",
		"queued":       true,
		"request_file": path,
		"version":      versionValue,
	}, nil
}

func systemdUpgrade(ctx context.Context, cfg config, versionValue string, releaseBaseURL string) (map[string]any, error) {
	if cfg.UpgradeUnit == "" {
		return nil, errors.New("NODEPING_AGENT_UPGRADE_UNIT is empty")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, errors.New("systemctl not found")
	}
	requestFile := strings.TrimSpace(cfg.UpgradeRequestFile)
	if requestFile == "" {
		requestFile = defaultUpgradeRequestFile()
	}
	requestCfg := cfg
	requestCfg.UpgradeRequestFile = requestFile
	if _, err := requestFileUpgrade(requestCfg, versionValue, releaseBaseURL); err != nil {
		return nil, err
	}
	args := []string{"start", cfg.UpgradeUnit}
	started := time.Now()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	result := map[string]any{
		"mode":         "systemd",
		"unit":         cfg.UpgradeUnit,
		"request_file": requestFile,
		"version":      versionValue,
		"duration":     elapsedMS(started),
		"stdout":       truncateOutput(string(out), 16*1024),
	}
	if releaseBaseURL != "" {
		result["release_base_url"] = releaseBaseURL
	}
	if err != nil {
		result["exit_error"] = err.Error()
		return result, fmt.Errorf("systemd upgrade trigger failed: %s", strings.TrimSpace(string(out)))
	}
	result["triggered"] = true
	return result, nil
}

func scriptUpgrade(ctx context.Context, cfg config, versionValue string, releaseBaseURL string) (map[string]any, error) {
	path, err := fixedUpgradeScriptPath(cfg.UpgradeScript)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return nil, errors.New("upgrade script is not executable")
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = upgradeEnv(cfg, versionValue, releaseBaseURL)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	result := map[string]any{
		"mode":      "script",
		"script":    path,
		"version":   versionValue,
		"duration":  elapsedMS(started),
		"stdout":    truncateOutput(stdout.String(), 16*1024),
		"stderr":    truncateOutput(stderr.String(), 16*1024),
		"exit_code": 0,
		"completed": err == nil,
	}
	if releaseBaseURL != "" {
		result["release_base_url"] = releaseBaseURL
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result["exit_code"] = exitErr.ExitCode()
		}
		return result, fmt.Errorf("upgrade script failed: %w", err)
	}
	return result, nil
}

func fixedUpgradeScriptPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("NODEPING_AGENT_UPGRADE_SCRIPT is empty")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("NODEPING_AGENT_UPGRADE_SCRIPT must be an absolute path")
	}
	clean := filepath.Clean(path)
	switch clean {
	case "/opt/nodeping-agent/nodeping-agent-update", "/usr/local/bin/nodeping-agent-update", "/usr/bin/nodeping-agent-update", "/opt/nodeping-agent/update-nodeping-agent.sh":
		return clean, nil
	default:
		if strings.HasSuffix(clean, string(filepath.Separator)+"nodeping-agent-update") ||
			strings.HasSuffix(clean, string(filepath.Separator)+"update-nodeping-agent.sh") {
			return clean, nil
		}
		return "", errors.New("upgrade script path is not in the fixed allowlist")
	}
}

func upgradeEnv(cfg config, versionValue string, releaseBaseURL string) []string {
	envs := os.Environ()
	set := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		prefix := key + "="
		for i, item := range envs {
			if strings.HasPrefix(item, prefix) {
				envs[i] = prefix + value
				return
			}
		}
		envs = append(envs, prefix+value)
	}
	set("NODEPING_AGENT_VERSION", versionValue)
	set("NODEPING_AGENT_RELEASE_BASE_URL", releaseBaseURL)
	set("NODEPING_SERVER_URL", cfg.ServerURL)
	set("NODEPING_AGENT_ID", cfg.AgentID)
	set("NODEPING_AGENT_TOKEN", cfg.AgentToken)
	set("NODEPING_AGENT_TOKEN_FILE", cfg.AgentTokenFile)
	return envs
}

func truncateOutput(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "...<truncated>"
}
