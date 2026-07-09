package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func loadConfig() config {
	var cfg config
	flag.StringVar(&cfg.ServerURL, "server", env("NODEPING_SERVER_URL", ""), "NodePing backend base URL")
	flag.StringVar(&cfg.Token, "token", env("NODEPING_TOKEN", ""), "NodePing binding token")
	flag.StringVar(&cfg.AgentToken, "agent-token", env("NODEPING_AGENT_TOKEN", ""), "NodePing agent token")
	flag.StringVar(&cfg.AgentTokenFile, "agent-token-file", env("NODEPING_AGENT_TOKEN_FILE", defaultAgentTokenFile()), "NodePing agent token file")
	flag.StringVar(&cfg.AgentID, "agent-id", env("NODEPING_AGENT_ID", ""), "stable agent id")
	flag.StringVar(&cfg.Name, "name", env("NODEPING_AGENT_NAME", hostname()), "agent display name")
	flag.StringVar(&cfg.UpgradeMode, "upgrade-mode", env("NODEPING_AGENT_UPGRADE_MODE", "auto"), "remote upgrade mode: auto, request_file, systemd, script, or disabled")
	flag.StringVar(&cfg.UpgradeUnit, "upgrade-unit", env("NODEPING_AGENT_UPGRADE_UNIT", "nodeping-agent-update.service"), "fixed systemd unit used for remote upgrades")
	flag.StringVar(&cfg.UpgradeScript, "upgrade-script", env("NODEPING_AGENT_UPGRADE_SCRIPT", "/opt/nodeping-agent/nodeping-agent-update"), "fixed script used for remote upgrades")
	flag.StringVar(&cfg.UpgradeRequestFile, "upgrade-request-file", env("NODEPING_AGENT_UPGRADE_REQUEST_FILE", defaultUpgradeRequestFile()), "fixed request file watched by the systemd upgrade path")
	flag.DurationVar(&cfg.HeartbeatInterval, "heartbeat", envDuration("NODEPING_HEARTBEAT_INTERVAL", 20*time.Second), "heartbeat interval")
	flag.DurationVar(&cfg.PublicIPInterval, "public-ip-interval", envDuration("NODEPING_PUBLIC_IP_INTERVAL", 10*time.Minute), "public IP report interval")
	flag.DurationVar(&cfg.StreamIdleTimeout, "stream-idle-timeout", envDuration("NODEPING_STREAM_IDLE_TIMEOUT", 90*time.Second), "task stream idle timeout before reconnect")
	flag.DurationVar(&cfg.StreamRetryMin, "stream-retry-min", envDuration("NODEPING_STREAM_RETRY_MIN", 2*time.Second), "minimum task stream reconnect delay")
	flag.DurationVar(&cfg.StreamRetryMax, "stream-retry-max", envDuration("NODEPING_STREAM_RETRY_MAX", 30*time.Second), "maximum task stream reconnect delay")
	flag.IntVar(&cfg.Concurrency, "concurrency", envInt("NODEPING_CONCURRENCY", 3), "max concurrent tasks")
	flag.BoolVar(&cfg.PrintVersion, "version", false, "print version and exit")
	flag.BoolVar(&cfg.Doctor, "doctor", false, "run diagnostics and exit")
	flag.BoolVar(&cfg.DoctorJSON, "json", false, "print doctor result as JSON")
	flag.Parse()
	for _, arg := range flag.Args() {
		switch arg {
		case "doctor":
			cfg.Doctor = true
		case "--json", "-json", "json":
			cfg.DoctorJSON = true
		}
	}
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	cfg.Token = strings.TrimSpace(cfg.Token)
	cfg.AgentToken = strings.TrimSpace(cfg.AgentToken)
	cfg.AgentTokenFile = strings.TrimSpace(cfg.AgentTokenFile)
	cfg.AgentID = strings.TrimSpace(cfg.AgentID)
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.UpgradeMode = strings.ToLower(strings.TrimSpace(cfg.UpgradeMode))
	cfg.UpgradeUnit = strings.TrimSpace(cfg.UpgradeUnit)
	cfg.UpgradeScript = strings.TrimSpace(cfg.UpgradeScript)
	cfg.UpgradeRequestFile = strings.TrimSpace(cfg.UpgradeRequestFile)
	cfg.Version = "nodeping-agent/" + version
	if cfg.PrintVersion {
		return cfg
	}
	if cfg.ServerURL == "" || (cfg.Token == "" && cfg.AgentToken == "" && strings.TrimSpace(readAgentTokenFile(cfg.AgentTokenFile)) == "") {
		if cfg.Doctor {
			cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
			return cfg
		}
		log.Fatal("NODEPING_SERVER_URL and either NODEPING_AGENT_TOKEN or NODEPING_TOKEN are required")
	}
	if cfg.AgentToken == "" {
		cfg.AgentToken = readAgentTokenFile(cfg.AgentTokenFile)
	}
	cfg.AgentID = resolveAgentIDForConfig(cfg.AgentID, cfg.AgentToken, defaultAgentIDFile())
	if cfg.Name == "" {
		cfg.Name = cfg.AgentID
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if cfg.StreamIdleTimeout <= 0 {
		cfg.StreamIdleTimeout = 90 * time.Second
	}
	if cfg.StreamRetryMin <= 0 {
		cfg.StreamRetryMin = 2 * time.Second
	}
	if cfg.StreamRetryMax < cfg.StreamRetryMin {
		cfg.StreamRetryMax = cfg.StreamRetryMin
	}
	cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	return cfg
}

func env(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err == nil {
		return parsed
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func defaultAgentTokenFile() string {
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return ""
	}
	return dir + string(os.PathSeparator) + "nodeping" + string(os.PathSeparator) + "agent-token"
}

func defaultAgentIDFile() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/nodeping-agent/agent-id"
	}
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return ""
	}
	return filepath.Join(dir, "nodeping", "agent-id")
}

func defaultAgentID() string {
	return defaultAgentIDFromFile(defaultAgentIDFile())
}

func defaultAgentIDFromFile(path string) string {
	if value := readAgentIDFile(path); value != "" {
		return value
	}
	value := randomLocalAgentID()
	_ = writeAgentIDFile(path, value)
	return value
}

func resolveAgentIDForConfig(configured string, agentToken string, path string) string {
	configured = strings.TrimSpace(configured)
	agentToken = strings.TrimSpace(agentToken)
	if configured == "" {
		if stored := readAgentIDFile(path); stored != "" {
			if agentIDIsUUIDV4(stored) || agentToken == "" {
				return stored
			}
		}
		if agentToken != "" {
			return randomLocalAgentID()
		}
		return defaultAgentIDFromFile(path)
	}
	if agentIDIsUUIDV4(configured) {
		return configured
	}
	if stored := readAgentIDFile(path); agentIDIsUUIDV4(stored) {
		return stored
	}
	if agentToken != "" {
		return randomLocalAgentID()
	}
	return configured
}

func randomLocalAgentID() string {
	if id, err := randomAgentUUID(); err == nil {
		return id
	}
	return "agent-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func randomAgentUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("agent-%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func agentIDIsUUIDV4(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len("agent-00000000-0000-4000-8000-000000000000") {
		return false
	}
	if !strings.HasPrefix(value, "agent-") {
		return false
	}
	for _, index := range []int{14, 19, 24, 29} {
		if value[index] != '-' {
			return false
		}
	}
	if value[20] != '4' {
		return false
	}
	switch value[25] {
	case '8', '9', 'a', 'b', 'A', 'B':
	default:
		return false
	}
	for i := 6; i < len(value); i++ {
		if value[i] == '-' {
			continue
		}
		if !isHexDigit(value[i]) {
			return false
		}
	}
	return true
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func defaultUpgradeRequestFile() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/nodeping-agent/update-request.json"
	}
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return ""
	}
	return filepath.Join(dir, "nodeping", "update-request.json")
}

func readAgentIDFile(path string) string {
	value := readAgentTokenFile(path)
	if strings.HasPrefix(value, "agent-") {
		return value
	}
	return ""
}

func writeAgentIDFile(path string, agentID string) error {
	return writeAgentTokenFile(path, agentID)
}

func readFirstExistingFile(paths ...string) string {
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw))
		}
	}
	return ""
}

func sanitizeAgentIDPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_'
		if ok {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func readAgentTokenFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func writeAgentTokenFile(path string, token string) error {
	path = strings.TrimSpace(path)
	token = strings.TrimSpace(token)
	if path == "" || token == "" {
		return nil
	}
	if index := strings.LastIndex(path, string(os.PathSeparator)); index > 0 {
		if err := os.MkdirAll(path[:index], 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(token+"\n"), 0o600)
}

func hostname() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "nodeping-agent"
	}
	return strings.TrimSpace(host)
}

func hostnameID() string {
	host := sanitizeAgentIDPart(hostname())
	if host == "" {
		host = "nodeping-agent"
	}
	return "agent-" + host
}
