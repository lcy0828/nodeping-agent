package main

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func effectiveCapabilities(ctx context.Context, cfg config) []string {
	return collectDoctorSnapshot(ctx, cfg).Capabilities
}

func effectiveCapabilitiesFromChecks(checks []doctorCheck) []string {
	caps := []string{"tcp_ping", "long_tcp_ping", "udp_probe", "http_ping", "http_request", "http3_check", "dns_lookup", "dns_compare", "tls_check", "node_status", "ip"}
	if doctorCheckCapabilityAvailable(checks, "ping_command") {
		caps = append(caps, "ping", "long_ping")
	}
	if doctorCheckCapabilityAvailable(checks, "traceroute_command") {
		caps = append(caps, "traceroute")
	}
	if doctorCheckCapabilityAvailable(checks, "mtr_command") {
		caps = append(caps, "mtr")
	}
	return normalizeStringCapabilities(caps)
}

func doctorCheckCapabilityAvailable(checks []doctorCheck, key string) bool {
	for _, check := range checks {
		if check.Key == key {
			if check.Status == "ok" {
				return true
			}
			return check.Status == "warn" && strings.TrimSpace(check.Path) != ""
		}
	}
	return false
}

func normalizeStringCapabilities(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func detectInstallMode() string {
	if strings.TrimSpace(os.Getenv("NODEPING_INSTALL_MODE")) != "" {
		return strings.ToLower(strings.TrimSpace(os.Getenv("NODEPING_INSTALL_MODE")))
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
		return "docker"
	}
	if strings.HasPrefix(defaultAgentTokenFile(), "/var/lib/") || strings.HasPrefix(defaultAgentTokenFile(), "/etc/") {
		return "binary"
	}
	return "unknown"
}

func commandVersion(ctx context.Context, path string, args ...string) string {
	if path == "" {
		return ""
	}
	versionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(versionCtx, path, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func mtrSupportsJSON(ctx context.Context, path string) bool {
	if path == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-r", "-c", "1", "-n", "-j", "127.0.0.1").CombinedOutput()
	if err != nil && mtrShouldFallbackToText(out, err) {
		return false
	}
	if mtrShouldFallbackToText(out, err) {
		return false
	}
	text := strings.TrimLeft(string(out), " \t\r\n")
	return strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[")
}

func installHint(binary string) string {
	switch binary {
	case "ping":
		return "Debian/Ubuntu: sudo apt install iputils-ping; Alpine: apk add iputils; RHEL 8+/Rocky/Alma: sudo dnf install iputils; CentOS/RHEL 7: sudo yum install iputils"
	case "traceroute":
		return "Debian/Ubuntu: sudo apt install traceroute; Alpine: apk add traceroute; RHEL 8+/Rocky/Alma: sudo dnf install traceroute; CentOS/RHEL 7: sudo yum install traceroute"
	case "mtr":
		return "Debian/Ubuntu: sudo apt install mtr-tiny; Alpine: apk add mtr; RHEL 8+/Rocky/Alma: sudo dnf install mtr; CentOS/RHEL 7: sudo yum install mtr"
	default:
		return "install " + binary + " with your system package manager"
	}
}

func upgradeHint(binary string) string {
	switch binary {
	case "mtr":
		return "mtr does not support JSON output; the Agent will use text fallback. CentOS/RHEL 7 repositories commonly ship mtr 0.85, so yum update may not help; use Docker Agent, upgrade to a newer RHEL-compatible OS, or manually install a newer mtr if JSON output is required"
	default:
		return "upgrade " + binary
	}
}
