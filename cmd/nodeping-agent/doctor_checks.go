package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func checkConfig(cfg config) doctorCheck {
	missing := []string{}
	if cfg.ServerURL == "" {
		missing = append(missing, "NODEPING_SERVER_URL")
	} else if parsed, err := url.Parse(cfg.ServerURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return doctorCheck{Key: "config", Name: "config", Status: "fail", Severity: "required", Message: "NODEPING_SERVER_URL is not a valid URL", Required: true}
	}
	if cfg.Token == "" {
		missing = append(missing, "NODEPING_TOKEN")
	}
	if len(missing) > 0 {
		return doctorCheck{Key: "config", Name: "config", Status: "fail", Severity: "required", Message: "missing " + strings.Join(missing, ", "), Required: true}
	}
	return doctorCheck{Key: "config", Name: "config", Status: "ok", Severity: "required", Message: "agent_id=" + cfg.AgentID + " version=" + cfg.Version, Required: true}
}

func checkUpgradeControl(cfg config) doctorCheck {
	mode := normalizeUpgradeMode(cfg.UpgradeMode)
	switch mode {
	case "disabled":
		return doctorCheck{Name: "upgrade control", Status: "warn", Message: "remote upgrade is disabled"}
	case "request_file":
		if cfg.UpgradeRequestFile == "" {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: "NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty"}
		}
		dir := filepath.Dir(cfg.UpgradeRequestFile)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: err.Error()}
		}
		testPath := cfg.UpgradeRequestFile + ".doctor"
		if err := os.WriteFile(testPath, []byte("ok\n"), 0o600); err != nil {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: err.Error()}
		}
		_ = os.Remove(testPath)
		return doctorCheck{Name: "upgrade control", Status: "ok", Message: "request file " + cfg.UpgradeRequestFile}
	case "systemd":
		if cfg.UpgradeUnit == "" {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: "NODEPING_AGENT_UPGRADE_UNIT is empty"}
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: "systemctl not found"}
		}
		return doctorCheck{Name: "upgrade control", Status: "ok", Message: "systemd unit " + cfg.UpgradeUnit}
	case "script":
		path, err := fixedUpgradeScriptPath(cfg.UpgradeScript)
		if err != nil {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: err.Error()}
		}
		if info, err := os.Stat(path); err != nil {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: err.Error()}
		} else if info.IsDir() || info.Mode()&0o111 == 0 {
			return doctorCheck{Name: "upgrade control", Status: "fail", Message: "upgrade script is not executable"}
		}
		return doctorCheck{Name: "upgrade control", Status: "ok", Message: path}
	default:
		if cfg.UpgradeRequestFile != "" && systemdUnitIsActive(upgradePathUnitName(cfg.UpgradeUnit)) {
			return doctorCheck{Name: "upgrade control", Status: "ok", Message: "auto request file " + cfg.UpgradeRequestFile}
		}
		if _, err := exec.LookPath("systemctl"); err == nil && cfg.UpgradeUnit != "" {
			return doctorCheck{Name: "upgrade control", Status: "ok", Message: "auto systemd unit " + cfg.UpgradeUnit}
		}
		if cfg.UpgradeScript != "" {
			if path, err := fixedUpgradeScriptPath(cfg.UpgradeScript); err == nil {
				if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
					return doctorCheck{Name: "upgrade control", Status: "ok", Message: "auto script " + path}
				}
			}
		}
		return doctorCheck{Name: "upgrade control", Status: "warn", Message: "remote upgrade is not configured; set NODEPING_AGENT_UPGRADE_MODE=request_file for systemd installs"}
	}
}

func checkPingCommand(ctx context.Context) doctorCheck {
	path, err := exec.LookPath("ping")
	if err != nil {
		return doctorCheck{Key: "ping_command", Name: "ping command", Status: "fail", Severity: "required_for_capability", Message: "ping command not found", Remediation: installHint("ping"), Capabilities: []string{"ping", "long_ping"}, Required: true}
	}
	pingCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	_, err = runPing(pingCtx, "127.0.0.1")
	if err != nil {
		return doctorCheck{Key: "ping_command", Name: "ping command", Status: "fail", Severity: "required_for_capability", Message: err.Error(), Path: path, Remediation: rawSocketPermissionRemediation(), Capabilities: []string{"ping", "long_ping"}, Required: true}
	}
	return doctorCheck{Key: "ping_command", Name: "ping command", Status: "ok", Severity: "required_for_capability", Message: path, Path: path, Version: commandVersion(ctx, path, "-V"), Capabilities: []string{"ping", "long_ping"}, Required: true}
}

func checkTracerouteCommand(ctx context.Context) doctorCheck {
	path, err := exec.LookPath("traceroute")
	if err != nil {
		return doctorCheck{Key: "traceroute_command", Name: "traceroute command", Status: "warn", Severity: "required_for_capability", Message: "traceroute not found; related diagnostic task will fail until installed", Remediation: installHint("traceroute"), Capabilities: []string{"traceroute"}}
	}
	return doctorCheck{Key: "traceroute_command", Name: "traceroute command", Status: "ok", Severity: "required_for_capability", Message: path, Path: path, Version: commandVersion(ctx, path, "--version"), Capabilities: []string{"traceroute"}}
}

func checkMTRCommand(ctx context.Context) doctorCheck {
	path, err := exec.LookPath("mtr")
	if err != nil {
		return doctorCheck{Key: "mtr_command", Name: "mtr command", Status: "warn", Severity: "required_for_capability", Message: "mtr not found; related diagnostic task will fail until installed", Remediation: installHint("mtr"), Capabilities: []string{"mtr"}}
	}
	check := doctorCheck{Key: "mtr_command", Name: "mtr command", Status: "ok", Severity: "required_for_capability", Message: path, Path: path, Version: commandVersion(ctx, path, "--version"), Capabilities: []string{"mtr"}}
	probe := probeMTRJSON(ctx, path)
	if probe.Unsupported {
		check.Status = "warn"
		check.Message = path + " does not support -j; text fallback will be used"
		check.Remediation = upgradeHint("mtr")
	} else if !probe.Supported {
		check.Status = "fail"
		if probe.TimedOut {
			check.Message = path + " runtime check timed out"
		} else {
			check.Message = path + " runtime check failed"
		}
		if diagnostic := mtrProbeDiagnostic(probe); diagnostic != "" {
			check.Message += ": " + diagnostic
		}
		check.Remediation = rawSocketPermissionRemediation()
	}
	return check
}

func rawSocketPermissionRemediation() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NODEPING_INSTALL_MODE")), "docker") {
		return "refresh the Docker Compose deployment and recreate the container with user 0:0 and NET_RAW"
	}
	return "grant CAP_NET_RAW to the Agent service user and verify ping/mtr packet helper permissions"
}

func checkDNS(ctx context.Context) doctorCheck {
	dnsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", "example.com")
	if err != nil {
		return doctorCheck{Key: "dns_lookup", Name: "dns lookup", Status: "fail", Severity: "required", Message: err.Error(), Remediation: "check /etc/resolv.conf or container DNS settings", Required: true}
	}
	return doctorCheck{Key: "dns_lookup", Name: "dns lookup", Status: "ok", Severity: "required", Message: fmt.Sprintf("%d answers", len(ips)), Required: true}
}

func checkPublicIP(ctx context.Context) doctorCheck {
	ipCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ip := discoverPublicIP(ipCtx)
	if ip == "" {
		return doctorCheck{Key: "public_ip", Name: "public ip", Status: "warn", Severity: "recommended", Message: "public IP discovery failed", Remediation: "allow outbound HTTPS to public IP echo endpoints"}
	}
	return doctorCheck{Key: "public_ip", Name: "public ip", Status: "ok", Severity: "recommended", Message: ip}
}

func checkAgentTokenFile(cfg config) doctorCheck {
	if cfg.AgentTokenFile == "" {
		return doctorCheck{Key: "token_file", Name: "token file", Status: "fail", Severity: "required", Message: "NODEPING_AGENT_TOKEN_FILE is empty", Required: true}
	}
	if token := readAgentTokenFile(cfg.AgentTokenFile); token != "" {
		return doctorCheck{Key: "token_file", Name: "token file", Status: "ok", Severity: "required", Message: "readable", Path: cfg.AgentTokenFile, Required: true}
	}
	dir := cfg.AgentTokenFile
	if index := strings.LastIndex(dir, string(os.PathSeparator)); index > 0 {
		dir = dir[:index]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return doctorCheck{Key: "token_file", Name: "token file", Status: "fail", Severity: "required", Message: err.Error(), Path: cfg.AgentTokenFile, Required: true}
	}
	testPath := cfg.AgentTokenFile + ".doctor"
	if err := os.WriteFile(testPath, []byte("ok\n"), 0o600); err != nil {
		return doctorCheck{Key: "token_file", Name: "token file", Status: "fail", Severity: "required", Message: err.Error(), Path: cfg.AgentTokenFile, Required: true}
	}
	_ = os.Remove(testPath)
	return doctorCheck{Key: "token_file", Name: "token file", Status: "ok", Severity: "required", Message: "writable", Path: cfg.AgentTokenFile, Required: true}
}

func checkBackendHealth(ctx context.Context, cfg config) doctorCheck {
	if cfg.ServerURL == "" {
		return doctorCheck{Key: "backend_health", Name: "backend health", Status: "fail", Severity: "required", Message: "server URL is empty", Required: true}
	}
	healthCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, cfg.ServerURL+"/healthz", nil)
	if err != nil {
		return doctorCheck{Key: "backend_health", Name: "backend health", Status: "fail", Severity: "required", Message: err.Error(), Required: true}
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return doctorCheck{Key: "backend_health", Name: "backend health", Status: "fail", Severity: "required", Message: err.Error(), Remediation: "check NODEPING_SERVER_URL and outbound HTTPS connectivity", Required: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return doctorCheck{Key: "backend_health", Name: "backend health", Status: "fail", Severity: "required", Message: fmt.Sprintf("status %d", resp.StatusCode), Required: true}
	}
	return doctorCheck{Key: "backend_health", Name: "backend health", Status: "ok", Severity: "required", Message: cfg.ServerURL, Required: true}
}

func checkAgentRegistration(ctx context.Context, cfg config) doctorCheck {
	if cfg.ServerURL == "" || cfg.Token == "" || cfg.AgentID == "" {
		return doctorCheck{Name: "agent registration", Status: "fail", Message: "missing NODEPING_SERVER_URL, NODEPING_TOKEN, or NODEPING_AGENT_ID"}
	}
	statusCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var status agentStatusResponse
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-statusCtx.Done():
				return doctorCheck{Name: "agent registration", Status: "fail", Message: statusCtx.Err().Error()}
			case <-time.After(2 * time.Second):
			}
		}
		status, lastErr = getAgentStatus(statusCtx, cfg)
		if lastErr != nil && cfg.AgentToken != "" {
			status, lastErr = getAgentStatusWithToken(statusCtx, cfg, cfg.AgentToken)
		}
		if lastErr != nil {
			continue
		}
		if status.Registered {
			message := fmt.Sprintf("registered node %d status=%s agent_status=%s stream=%t", status.NodeID, status.NodeStatus, status.AgentStatus, status.StreamOnline)
			if !status.StreamOnline {
				return doctorCheck{Name: "agent registration", Status: "warn", Message: message}
			}
			return doctorCheck{Name: "agent registration", Status: "ok", Message: message}
		}
		lastErr = errors.New(status.Message)
	}
	if lastErr == nil {
		lastErr = errors.New("agent is not registered on this endpoint")
	}
	return doctorCheck{Name: "agent registration", Status: "fail", Message: lastErr.Error()}
}
