package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type config struct {
	ServerURL          string
	Token              string
	AgentToken         string
	AgentTokenFile     string
	AgentID            string
	Name               string
	Version            string
	UpgradeMode        string
	UpgradeUnit        string
	UpgradeScript      string
	UpgradeRequestFile string
	HeartbeatInterval  time.Duration
	PublicIPInterval   time.Duration
	Concurrency        int
	HTTPClient         *http.Client
	PrintVersion       bool
	Doctor             bool
}

type taskRequest struct {
	ID        string          `json:"task_id"`
	NodeID    int64           `json:"node_id"`
	AgentID   string          `json:"agent_id"`
	TaskType  string          `json:"task_type"`
	Payload   json.RawMessage `json:"payload"`
	Options   map[string]any  `json:"options,omitempty"`
	TimeoutMS int             `json:"timeout_ms,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type taskResult struct {
	TaskID       string         `json:"task_id"`
	Status       string         `json:"status"`
	Success      bool           `json:"success"`
	LatencyMS    float64        `json:"latency_ms,omitempty"`
	ResponseIP   string         `json:"response_ip,omitempty"`
	Result       map[string]any `json:"result,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
	ErrorCode    string         `json:"error_code,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	FinishedAt   time.Time      `json:"finished_at"`
}

type taskEvent struct {
	TaskID    string         `json:"task_id"`
	Status    string         `json:"status"`
	Message   string         `json:"message,omitempty"`
	Progress  int            `json:"progress,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type registerResponse struct {
	AgentToken string `json:"agent_token"`
}

type agentStatusResponse struct {
	OK           bool      `json:"ok"`
	Registered   bool      `json:"registered"`
	StreamOnline bool      `json:"stream_online"`
	NodeID       int64     `json:"node_id"`
	NodeStatus   string    `json:"node_status"`
	AgentStatus  string    `json:"agent_status"`
	ServerTime   time.Time `json:"server_time"`
	Message      string    `json:"message"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

var capabilities = []string{"ping", "tcp_ping", "long_ping", "long_tcp_ping", "udp_probe", "http_ping", "http_request", "http3_check", "dns_lookup", "dns_compare", "tls_check", "traceroute", "mtr", "node_status", "ip"}

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cfg := loadConfig()
	if cfg.PrintVersion {
		fmt.Printf("nodeping-agent version=%s commit=%s date=%s\n", version, commit, buildDate)
		return
	}
	if cfg.Doctor {
		if err := runDoctor(context.Background(), cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

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
	flag.IntVar(&cfg.Concurrency, "concurrency", envInt("NODEPING_CONCURRENCY", 3), "max concurrent tasks")
	flag.BoolVar(&cfg.PrintVersion, "version", false, "print version and exit")
	flag.BoolVar(&cfg.Doctor, "doctor", false, "run diagnostics and exit")
	flag.Parse()
	if flag.NArg() > 0 && flag.Arg(0) == "doctor" {
		cfg.Doctor = true
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
	if cfg.AgentID == "" {
		cfg.AgentID = defaultAgentID()
	}
	if cfg.ServerURL == "" || cfg.Token == "" {
		if cfg.Doctor {
			cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
			return cfg
		}
		log.Fatal("NODEPING_SERVER_URL and NODEPING_TOKEN are required")
	}
	if cfg.Name == "" {
		cfg.Name = cfg.AgentID
	}
	if cfg.AgentToken == "" {
		cfg.AgentToken = readAgentTokenFile(cfg.AgentTokenFile)
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	return cfg
}

func run(ctx context.Context, cfg config) error {
	registerResp, err := registerAgent(ctx, cfg)
	if err != nil {
		if cfg.AgentToken == "" || !agentTokenCanContinue(ctx, cfg) {
			return err
		}
		log.Printf("binding token register failed, continuing with stored agent token: %v", err)
	} else {
		cfg.AgentToken = strings.TrimSpace(registerResp.AgentToken)
	}
	if cfg.AgentToken == "" {
		return errors.New("register response did not include agent_token")
	}
	if err := writeAgentTokenFile(cfg.AgentTokenFile, cfg.AgentToken); err != nil {
		log.Printf("store agent token failed: %v", err)
	}
	log.Printf("registered agent_id=%s server=%s", cfg.AgentID, cfg.ServerURL)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Add(3)
	go func() {
		defer wg.Done()
		heartbeatLoop(ctx, cfg)
	}()
	go func() {
		defer wg.Done()
		publicIPLoop(ctx, cfg)
	}()
	go func() {
		defer wg.Done()
		taskStreamLoop(ctx, cfg)
	}()
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

func runDoctor(ctx context.Context, cfg config) error {
	checks := collectDoctorChecks(ctx, cfg)
	failed := doctorHasFailures(checks)
	for _, check := range checks {
		fmt.Println(formatDoctorCheck(check))
	}
	if failed {
		return errors.New("自检发现失败项 / doctor found failed checks")
	}
	return nil
}

func formatDoctorCheck(check doctorCheck) string {
	return fmt.Sprintf("%-32s %-12s %s", doctorCheckName(check.Name), doctorCheckStatus(check.Status), doctorCheckMessage(check))
}

func doctorCheckName(name string) string {
	switch name {
	case "config":
		return "配置 / config"
	case "ping command":
		return "Ping 命令 / ping command"
	case "traceroute command":
		return "Traceroute 命令 / traceroute command"
	case "mtr command":
		return "MTR 命令 / mtr command"
	case "dns lookup":
		return "DNS 解析 / dns lookup"
	case "public ip":
		return "公网 IP / public ip"
	case "token file":
		return "Token 文件 / token file"
	case "backend health":
		return "后端健康 / backend health"
	case "agent registration":
		return "Agent 注册 / agent registration"
	case "upgrade control":
		return "升级控制 / upgrade control"
	default:
		return name
	}
}

func doctorCheckStatus(status string) string {
	switch status {
	case "ok":
		return "正常 / ok"
	case "warn":
		return "警告 / warn"
	case "fail":
		return "失败 / fail"
	default:
		return status
	}
}

func doctorCheckMessage(check doctorCheck) string {
	message := check.Message
	switch {
	case message == "":
		return ""
	case strings.HasPrefix(message, "agent_id="):
		return "标识与版本 / identity and version: " + message
	case message == "NODEPING_SERVER_URL is not a valid URL":
		return "NODEPING_SERVER_URL 不是有效 URL / NODEPING_SERVER_URL is not a valid URL"
	case strings.HasPrefix(message, "missing "):
		return "缺少 " + strings.TrimPrefix(message, "missing ") + " / " + message
	case message == "remote upgrade is disabled":
		return "远程升级已禁用 / remote upgrade is disabled"
	case message == "NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty":
		return "NODEPING_AGENT_UPGRADE_REQUEST_FILE 为空 / NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty"
	case message == "NODEPING_AGENT_UPGRADE_UNIT is empty":
		return "NODEPING_AGENT_UPGRADE_UNIT 为空 / NODEPING_AGENT_UPGRADE_UNIT is empty"
	case message == "systemctl not found":
		return "未找到 systemctl / systemctl not found"
	case message == "upgrade script is not executable":
		return "升级脚本不可执行 / upgrade script is not executable"
	case strings.HasPrefix(message, "request file "):
		return "请求文件 / request file " + strings.TrimPrefix(message, "request file ")
	case strings.HasPrefix(message, "systemd unit "):
		return "systemd 单元 / systemd unit " + strings.TrimPrefix(message, "systemd unit ")
	case strings.HasPrefix(message, "auto request file "):
		return "自动请求文件 / auto request file " + strings.TrimPrefix(message, "auto request file ")
	case strings.HasPrefix(message, "auto systemd unit "):
		return "自动 systemd 单元 / auto systemd unit " + strings.TrimPrefix(message, "auto systemd unit ")
	case strings.HasPrefix(message, "auto script "):
		return "自动脚本 / auto script " + strings.TrimPrefix(message, "auto script ")
	case message == "remote upgrade is not configured; set NODEPING_AGENT_UPGRADE_MODE=request_file for systemd installs":
		return "远程升级未配置；systemd 安装请设置 NODEPING_AGENT_UPGRADE_MODE=request_file / remote upgrade is not configured; set NODEPING_AGENT_UPGRADE_MODE=request_file for systemd installs"
	case message == "ping command not found":
		return "未找到 ping 命令 / ping command not found"
	case strings.HasSuffix(message, " not found; related diagnostic task will fail until installed"):
		binary := strings.TrimSuffix(message, " not found; related diagnostic task will fail until installed")
		return "未找到 " + binary + "；安装前相关诊断任务会失败 / " + message
	case strings.HasSuffix(message, " answers"):
		count := strings.TrimSuffix(message, " answers")
		return count + " 个结果 / " + message
	case message == "public IP discovery failed":
		return "公网 IP 发现失败 / public IP discovery failed"
	case message == "NODEPING_AGENT_TOKEN_FILE is empty":
		return "NODEPING_AGENT_TOKEN_FILE 为空 / NODEPING_AGENT_TOKEN_FILE is empty"
	case message == "readable":
		return "可读 / readable"
	case message == "writable":
		return "可写 / writable"
	case message == "server URL is empty":
		return "后端地址为空 / server URL is empty"
	case strings.HasPrefix(message, "status "):
		if strings.Contains(message, "invalid binding token") {
			return "安装 token 已失效；请在用户页重新获取 Agent 安装命令 / binding token is invalid; get a fresh Agent install command from the user page"
		}
		return "HTTP 状态 " + strings.TrimPrefix(message, "status ") + " / " + message
	case strings.HasPrefix(message, "registered node "):
		return "已注册节点 / registered node " + strings.TrimPrefix(message, "registered node ")
	case message == "agent is not registered on this endpoint":
		return "Agent 尚未注册到当前 Endpoint / agent is not registered on this endpoint"
	default:
		return message
	}
}

func collectDoctorChecks(ctx context.Context, cfg config) []doctorCheck {
	return []doctorCheck{
		checkConfig(cfg),
		checkPingCommand(ctx),
		checkOptionalCommand("traceroute", "traceroute command"),
		checkOptionalCommand("mtr", "mtr command"),
		checkDNS(ctx),
		checkPublicIP(ctx),
		checkAgentTokenFile(cfg),
		checkBackendHealth(ctx, cfg),
		checkAgentRegistration(ctx, cfg),
		checkUpgradeControl(cfg),
	}
}

func doctorHasFailures(checks []doctorCheck) bool {
	for _, check := range checks {
		if check.Status == "fail" {
			return true
		}
	}
	return false
}

func runAgentDoctor(ctx context.Context, cfg config) (map[string]any, error) {
	checks := collectDoctorChecks(ctx, cfg)
	failed := 0
	warnings := 0
	rows := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		if check.Status == "fail" {
			failed++
		}
		if check.Status == "warn" {
			warnings++
		}
		rows = append(rows, map[string]any{
			"name":    check.Name,
			"status":  check.Status,
			"message": check.Message,
		})
	}
	status := "ok"
	if failed > 0 {
		status = "fail"
	} else if warnings > 0 {
		status = "warn"
	}
	result := map[string]any{
		"agent_doctor":  status,
		"status":        status,
		"checks":        rows,
		"check_count":   len(checks),
		"failed_count":  failed,
		"warning_count": warnings,
		"version":       cfg.Version,
		"agent_id":      cfg.AgentID,
	}
	if failed > 0 {
		return result, fmt.Errorf("doctor found %d failed checks", failed)
	}
	return result, nil
}

func checkConfig(cfg config) doctorCheck {
	missing := []string{}
	if cfg.ServerURL == "" {
		missing = append(missing, "NODEPING_SERVER_URL")
	} else if parsed, err := url.Parse(cfg.ServerURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return doctorCheck{Name: "config", Status: "fail", Message: "NODEPING_SERVER_URL is not a valid URL"}
	}
	if cfg.Token == "" {
		missing = append(missing, "NODEPING_TOKEN")
	}
	if len(missing) > 0 {
		return doctorCheck{Name: "config", Status: "fail", Message: "missing " + strings.Join(missing, ", ")}
	}
	return doctorCheck{Name: "config", Status: "ok", Message: "agent_id=" + cfg.AgentID + " version=" + cfg.Version}
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
		return doctorCheck{Name: "ping command", Status: "fail", Message: "ping command not found"}
	}
	pingCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	_, err = runPing(pingCtx, "127.0.0.1")
	if err != nil {
		return doctorCheck{Name: "ping command", Status: "fail", Message: err.Error()}
	}
	return doctorCheck{Name: "ping command", Status: "ok", Message: path}
}

func checkOptionalCommand(binary string, label string) doctorCheck {
	path, err := exec.LookPath(binary)
	if err != nil {
		return doctorCheck{Name: label, Status: "warn", Message: binary + " not found; related diagnostic task will fail until installed"}
	}
	return doctorCheck{Name: label, Status: "ok", Message: path}
}

func checkDNS(ctx context.Context) doctorCheck {
	dnsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", "example.com")
	if err != nil {
		return doctorCheck{Name: "dns lookup", Status: "fail", Message: err.Error()}
	}
	return doctorCheck{Name: "dns lookup", Status: "ok", Message: fmt.Sprintf("%d answers", len(ips))}
}

func checkPublicIP(ctx context.Context) doctorCheck {
	ipCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ip := discoverPublicIP(ipCtx)
	if ip == "" {
		return doctorCheck{Name: "public ip", Status: "fail", Message: "public IP discovery failed"}
	}
	return doctorCheck{Name: "public ip", Status: "ok", Message: ip}
}

func checkAgentTokenFile(cfg config) doctorCheck {
	if cfg.AgentTokenFile == "" {
		return doctorCheck{Name: "token file", Status: "fail", Message: "NODEPING_AGENT_TOKEN_FILE is empty"}
	}
	if token := readAgentTokenFile(cfg.AgentTokenFile); token != "" {
		return doctorCheck{Name: "token file", Status: "ok", Message: "readable"}
	}
	dir := cfg.AgentTokenFile
	if index := strings.LastIndex(dir, string(os.PathSeparator)); index > 0 {
		dir = dir[:index]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return doctorCheck{Name: "token file", Status: "fail", Message: err.Error()}
	}
	testPath := cfg.AgentTokenFile + ".doctor"
	if err := os.WriteFile(testPath, []byte("ok\n"), 0o600); err != nil {
		return doctorCheck{Name: "token file", Status: "fail", Message: err.Error()}
	}
	_ = os.Remove(testPath)
	return doctorCheck{Name: "token file", Status: "ok", Message: "writable"}
}

func checkBackendHealth(ctx context.Context, cfg config) doctorCheck {
	if cfg.ServerURL == "" {
		return doctorCheck{Name: "backend health", Status: "fail", Message: "server URL is empty"}
	}
	healthCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, cfg.ServerURL+"/healthz", nil)
	if err != nil {
		return doctorCheck{Name: "backend health", Status: "fail", Message: err.Error()}
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return doctorCheck{Name: "backend health", Status: "fail", Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return doctorCheck{Name: "backend health", Status: "fail", Message: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	return doctorCheck{Name: "backend health", Status: "ok", Message: cfg.ServerURL}
}

func registerAgent(ctx context.Context, cfg config) (registerResponse, error) {
	var out registerResponse
	if err := postJSONWithToken(ctx, cfg, cfg.Token, "/api/agent/v1/register", map[string]any{
		"agent_id":     cfg.AgentID,
		"agent_token":  cfg.AgentToken,
		"server_url":   cfg.ServerURL,
		"name":         cfg.Name,
		"version":      cfg.Version,
		"hostname":     hostname(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"capabilities": capabilities,
	}, &out); err != nil {
		return registerResponse{}, fmt.Errorf("register: %w", err)
	}
	return out, nil
}

func agentTokenCanContinue(ctx context.Context, cfg config) bool {
	if cfg.AgentToken == "" || cfg.AgentID == "" {
		return false
	}
	statusCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err := getAgentStatusWithToken(statusCtx, cfg, cfg.AgentToken)
	if err != nil {
		log.Printf("stored agent token status check failed: %v", err)
		return false
	}
	return status.Registered
}

func heartbeatLoop(ctx context.Context, cfg config) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		if err := postAgentJSON(ctx, cfg, "/api/agent/v1/heartbeat", map[string]any{
			"agent_id":     cfg.AgentID,
			"agent_token":  cfg.AgentToken,
			"server_url":   cfg.ServerURL,
			"name":         cfg.Name,
			"version":      cfg.Version,
			"capabilities": capabilities,
		}, nil); err != nil {
			log.Printf("heartbeat failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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

func getAgentStatus(ctx context.Context, cfg config) (agentStatusResponse, error) {
	return getAgentStatusWithToken(ctx, cfg, cfg.Token)
}

func getAgentStatusWithToken(ctx context.Context, cfg config, token string) (agentStatusResponse, error) {
	var out agentStatusResponse
	path := "/api/agent/v1/status?agent_id=" + url.QueryEscape(cfg.AgentID)
	if err := getJSONWithToken(ctx, cfg, token, path, &out); err != nil {
		return agentStatusResponse{}, err
	}
	return out, nil
}

func publicIPLoop(ctx context.Context, cfg config) {
	reportPublicIP(ctx, cfg)
	ticker := time.NewTicker(cfg.PublicIPInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reportPublicIP(ctx, cfg)
		}
	}
}

func reportPublicIP(ctx context.Context, cfg config) {
	ip := discoverPublicIP(ctx)
	payload := map[string]any{"agent_id": cfg.AgentID, "source": "nodeping_agent"}
	if ip != "" {
		payload["public_ip"] = ip
	}
	if err := postAgentJSON(ctx, cfg, "/api/agent/v1/public-ip", payload, nil); err != nil {
		log.Printf("public IP report failed: %v", err)
	}
}

func taskStreamLoop(ctx context.Context, cfg config) {
	sem := make(chan struct{}, cfg.Concurrency)
	for {
		if err := consumeTaskStream(ctx, cfg, sem); err != nil && ctx.Err() == nil {
			log.Printf("task stream stopped: %v", err)
			time.Sleep(3 * time.Second)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func consumeTaskStream(ctx context.Context, cfg config, sem chan struct{}) error {
	endpoint := cfg.ServerURL + "/api/agent/v1/tasks/stream?agent_id=" + url.QueryEscape(cfg.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("stream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return readSSETasks(ctx, resp.Body, func(task taskRequest) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			executeAndReport(ctx, cfg, task)
		}()
	})
}

func readSSETasks(ctx context.Context, body io.Reader, handle func(taskRequest)) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var event string
	var data bytes.Buffer
	flush := func() {
		if event != "task" || data.Len() == 0 {
			event = ""
			data.Reset()
			return
		}
		var task taskRequest
		if err := json.Unmarshal(data.Bytes(), &task); err != nil {
			log.Printf("decode task failed: %v", err)
		} else {
			handle(task)
		}
		event = ""
		data.Reset()
	}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()
	return scanner.Err()
}

func executeAndReport(ctx context.Context, cfg config, task taskRequest) {
	timeout := time.Duration(task.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := executeTask(taskCtx, cfg, task)
	reportCtx, reportCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reportCancel()
	if err := postAgentJSON(reportCtx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/result", result, nil); err != nil {
		log.Printf("report task result failed task_id=%s: %v", task.ID, err)
	}
}

func executeTask(ctx context.Context, cfg config, task taskRequest) taskResult {
	started := time.Now()
	result := taskResult{TaskID: task.ID, Status: "running", FinishedAt: time.Now().UTC()}
	payload, err := payloadMap(task.Payload)
	if err != nil {
		return failTask(task.ID, "INVALID_PAYLOAD", err.Error())
	}
	var latency float64
	var response map[string]any
	var responseIP string
	targetSummary := ""
	switch task.TaskType {
	case "ping":
		target, _ := payloadString(payload, "ping")
		targetSummary = target
		latency, err = runPing(ctx, target)
		response = map[string]any{"ping": latency}
		responseIP = literalIP(target)
	case "tcp_ping":
		target, _ := payloadString(payload, "tcp_ping")
		targetSummary = target
		latency, err = runTCPPing(ctx, target)
		response = map[string]any{"tcp_ping": latency}
		responseIP = hostLiteralIP(target)
	case "long_ping":
		target, _ := payloadString(payload, "long_ping")
		targetSummary = target
		response, err = runLongPingWithProgress(ctx, cfg, task, target)
		latency = floatFromMap(response, "avg_latency_ms")
		responseIP = literalIP(target)
	case "long_tcp_ping":
		target, _ := payloadString(payload, "long_tcp_ping")
		targetSummary = target
		response, err = runLongTCPPingWithProgress(ctx, cfg, task, target)
		latency = floatFromMap(response, "avg_latency_ms")
		responseIP = hostLiteralIP(target)
	case "udp_probe":
		target, _ := payloadString(payload, "udp_probe")
		targetSummary = target
		response, err = runUDPProbe(ctx, target, task.Options)
		latency = floatFromMap(response, "udp_probe")
		responseIP = hostLiteralIP(target)
	case "http_ping":
		target, _ := payloadString(payload, "http_ping")
		targetSummary = target
		latency, responseIP, err = runHTTPPing(ctx, target)
		response = map[string]any{"http_ping": latency}
	case "http_request":
		target, method, headers, body := httpRequestPayload(payload)
		targetSummary = target
		latency, responseIP, response, err = runHTTPRequest(ctx, method, target, headers, body, task.Options)
	case "http3_check":
		target, _ := payloadString(payload, "http3_check")
		targetSummary = target
		response, err = runHTTP3Check(ctx, target, task.Options)
		latency = floatFromMap(response, "http3_check")
		responseIP = stringFromMap(response, "response_ip")
	case "dns_lookup":
		dnsPayload, _ := payload["dns"].(map[string]any)
		if dnsPayload == nil {
			dnsPayload, _ = payload["dns_lookup"].(map[string]any)
		}
		targetSummary = dnsTargetSummary(dnsPayload)
		response, err = runDNSLookup(ctx, dnsPayload)
	case "dns_compare":
		dnsPayload, _ := payload["dns_compare"].(map[string]any)
		if dnsPayload == nil {
			dnsPayload = payload
		}
		targetSummary = dnsTargetSummary(dnsPayload)
		response, err = runDNSCompare(ctx, dnsPayload, task.Options)
	case "tls_check":
		tlsPayload := map[string]any{}
		switch value := payload["tls_check"].(type) {
		case map[string]any:
			tlsPayload = value
		case string:
			tlsPayload["target"] = value
		default:
			tlsPayload = payload
		}
		targetSummary = strings.TrimSpace(fmt.Sprint(tlsPayload["target"]))
		response, err = runTLSCheck(ctx, tlsPayload)
		responseIP = stringFromMap(response, "response_ip")
	case "traceroute":
		target, _ := payloadString(payload, "traceroute")
		targetSummary = target
		response, err = runTraceroute(ctx, target, task.Options)
		responseIP = stringFromMap(response, "target_ip")
	case "mtr":
		target, _ := payloadString(payload, "mtr")
		targetSummary = target
		response, err = runMTR(ctx, target, task.Options)
		responseIP = stringFromMap(response, "target_ip")
	case "node_status":
		response, err = runNodeStatus()
	case "ip":
		ip := discoverPublicIP(ctx)
		if ip == "" {
			err = errors.New("public IP discovery failed")
		}
		responseIP = ip
		response = map[string]any{"ip": ip}
	case "agent_doctor":
		response, err = runAgentDoctor(ctx, cfg)
	case "agent_upgrade":
		response, err = runAgentUpgrade(ctx, cfg, payload, task.Options)
	default:
		return failTask(task.ID, "UNSUPPORTED_TASK", "unsupported task type: "+task.TaskType)
	}
	result.FinishedAt = time.Now().UTC()
	if err != nil {
		result.Status = "failed"
		result.Success = false
		result.ErrorCode = "TASK_FAILED"
		result.ErrorMessage = err.Error()
		result.LatencyMS = elapsedMS(started)
		result.Extra = taskResultExtra(task, targetSummary)
		return result
	}
	if latency <= 0 {
		latency = elapsedMS(started)
	}
	result.Status = "completed"
	result.Success = true
	result.LatencyMS = latency
	result.ResponseIP = responseIP
	result.Result = response
	result.Extra = taskResultExtra(task, targetSummary)
	return result
}

func taskResultExtra(task taskRequest, target string) map[string]any {
	extra := map[string]any{
		"agent_task_id": task.ID,
		"task_type":     task.TaskType,
	}
	if target = strings.TrimSpace(target); target != "" {
		extra["target"] = target
	}
	return extra
}

func dnsTargetSummary(payload map[string]any) string {
	if len(payload) == 0 {
		return ""
	}
	for _, key := range []string{"domain", "host", "target", "name"} {
		if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func failTask(taskID string, code string, message string) taskResult {
	return taskResult{TaskID: taskID, Status: "failed", Success: false, ErrorCode: code, ErrorMessage: message, FinishedAt: time.Now().UTC()}
}

func payloadMap(raw json.RawMessage) (map[string]any, error) {
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func payloadString(payload map[string]any, key string) (string, bool) {
	value, ok := payload[key]
	if !ok {
		return "", false
	}
	return strings.TrimSpace(fmt.Sprint(value)), true
}

func runPing(ctx context.Context, target string) (float64, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("ping target is required")
	}
	args := []string{"-c", "1", "-W", "2", target}
	if runtime.GOOS == "darwin" {
		args = []string{"-c", "1", "-W", "2000", target}
	}
	started := time.Now()
	out, err := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ping failed: %s", strings.TrimSpace(string(out)))
	}
	if latency := parsePingLatency(string(out)); latency > 0 {
		return latency, nil
	}
	return elapsedMS(started), nil
}

func runTCPPing(ctx context.Context, target string) (float64, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("tcp_ping target is required")
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return elapsedMS(started), nil
}

func runLongPing(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	return runLongProbe(ctx, "long_ping", target, options, runPing)
}

func runLongTCPPing(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	return runLongProbe(ctx, "long_tcp_ping", target, options, runTCPPing)
}

func runLongPingWithProgress(ctx context.Context, cfg config, task taskRequest, target string) (map[string]any, error) {
	return runLongProbe(ctx, "long_ping", target, task.Options, runPing, longProbeProgressReporter(ctx, cfg, task, "long_ping"))
}

func runLongTCPPingWithProgress(ctx context.Context, cfg config, task taskRequest, target string) (map[string]any, error) {
	return runLongProbe(ctx, "long_tcp_ping", target, task.Options, runTCPPing, longProbeProgressReporter(ctx, cfg, task, "long_tcp_ping"))
}

var waitLongProbeInterval = func(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func runLongProbe(ctx context.Context, taskKey string, target string, options map[string]any, probe func(context.Context, string) (float64, error), onProgress ...func(map[string]any)) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("%s target is required", taskKey)
	}
	count := intOption(options, "sample_count", 100)
	if count < 2 {
		count = 2
	}
	if count > 5000 {
		count = 5000
	}
	intervalMS := intOption(options, "interval_ms", 1000)
	if intervalMS < 200 {
		intervalMS = 200
	}
	if intervalMS > 10000 {
		intervalMS = 10000
	}
	started := time.Now()
	samples := make([]map[string]any, 0, count)
	latencies := make([]float64, 0, count)
	failures := 0
	for index := 0; index < count; index++ {
		if index > 0 {
			if err := waitLongProbeInterval(ctx, time.Duration(intervalMS)*time.Millisecond); err != nil {
				return longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, err), nil
			}
		}
		sampleStarted := time.Now()
		latency, err := probe(ctx, target)
		sample := map[string]any{
			"seq":        index + 1,
			"started_at": sampleStarted.UTC(),
		}
		if err != nil {
			failures++
			sample["success"] = false
			sample["error"] = err.Error()
		} else {
			sample["success"] = true
			sample["latency_ms"] = latency
			latencies = append(latencies, latency)
		}
		samples = append(samples, sample)
		if len(onProgress) > 0 && onProgress[0] != nil {
			onProgress[0](longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, nil))
		}
	}
	return longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, nil), nil
}

func longProbeProgressReporter(ctx context.Context, cfg config, task taskRequest, taskKey string) func(map[string]any) {
	return func(summary map[string]any) {
		completed := intFromAnyDefault(summary["completed_count"], 0)
		total := intFromAnyDefault(summary["sample_count"], 0)
		if completed <= 0 || total <= 0 {
			return
		}
		progress := int(math.Round(float64(completed) * 100 / float64(total)))
		if progress < 1 {
			progress = 1
		}
		if progress > 100 {
			progress = 100
		}
		extra := cloneAnyMap(summary)
		extra["event_kind"] = "long_probe_sample"
		extra["task_type"] = taskKey
		event := taskEvent{
			TaskID:    task.ID,
			Status:    "running",
			Message:   fmt.Sprintf("%s sample %d/%d", taskKey, completed, total),
			Progress:  progress,
			Extra:     extra,
			CreatedAt: time.Now().UTC(),
		}
		go func() {
			reportCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if err := postAgentJSON(reportCtx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/events", event, nil); err != nil {
				log.Printf("report task event failed task_id=%s: %v", task.ID, err)
			}
		}()
	}
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func longProbeSummary(taskKey string, started time.Time, requestedCount int, intervalMS int, samples []map[string]any, latencies []float64, failures int, stopErr error) map[string]any {
	successCount := len(latencies)
	result := map[string]any{
		taskKey:           avgFloat(latencies),
		"samples":         samples,
		"sample_count":    requestedCount,
		"completed_count": len(samples),
		"success_count":   successCount,
		"failure_count":   failures,
		"loss_percent":    lossPercent(len(samples), successCount),
		"interval_ms":     intervalMS,
		"duration_ms":     elapsedMS(started),
	}
	if successCount > 0 {
		result["min_latency_ms"] = minFloat(latencies)
		result["max_latency_ms"] = maxFloat(latencies)
		result["avg_latency_ms"] = avgFloat(latencies)
		result["p95_latency_ms"] = percentileFloat(latencies, 0.95)
		avgJitter, maxJitter := jitterStats(latencies)
		result["jitter_ms"] = avgJitter
		result["max_jitter_ms"] = maxJitter
	}
	if stopErr != nil {
		result["stopped_early"] = true
		result["stop_reason"] = stopErr.Error()
	}
	return result
}

func runHTTPPing(ctx context.Context, target string) (float64, string, error) {
	latency, responseIP, _, err := runHTTPRequest(ctx, http.MethodGet, target, nil, "", nil)
	return latency, responseIP, err
}

func runUDPProbe(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("udp_probe target is required")
	}
	payload := stringOptionAny(options, "payload")
	if payload == "" {
		payload = "nodeping"
	}
	if len(payload) > 1024 {
		payload = payload[:1024]
	}
	waitResponse := boolOptionDefault(options, "wait_response", true)
	readTimeoutMS := intOption(options, "read_timeout_ms", 1000)
	if readTimeoutMS < 200 {
		readTimeoutMS = 200
	}
	if readTimeoutMS > 5000 {
		readTimeoutMS = 5000
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(readTimeoutMS) * time.Millisecond))
	}
	sent, err := conn.Write([]byte(payload))
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"udp_probe":       elapsedMS(started),
		"target":          target,
		"sent_bytes":      sent,
		"wait_response":   waitResponse,
		"read_timeout_ms": readTimeoutMS,
	}
	if remote := conn.RemoteAddr(); remote != nil {
		result["remote_addr"] = remote.String()
		result["response_ip"] = remoteAddrIP(remote)
	}
	if !waitResponse {
		result["reachable"] = true
		return result, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutMS) * time.Millisecond))
	buf := make([]byte, 2048)
	received, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result["reachable"] = true
			result["response_received"] = false
			result["response_timeout"] = true
			result["udp_probe"] = elapsedMS(started)
			return result, nil
		}
		return nil, err
	}
	result["reachable"] = true
	result["response_received"] = true
	result["received_bytes"] = received
	result["udp_probe"] = elapsedMS(started)
	return result, nil
}

func runHTTPRequest(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any) (float64, string, map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, "", nil, errors.New("http target is required")
	}
	trace := &httpTimingTrace{}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace.clientTrace()), method, target, strings.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{Timeout: deadlineTimeout(ctx, 10*time.Second)}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	maxBodyBytes := intOption(options, "max_body_bytes", 1<<20)
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	if maxBodyBytes > 1<<20 {
		maxBodyBytes = 1 << 20
	}
	bodyLimit := int64(maxBodyBytes)
	readBody, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	latency := elapsedMS(started)
	responseIP := ""
	if parsed, err := url.Parse(target); err == nil {
		responseIP = literalIP(parsed.Hostname())
	}
	result := map[string]any{
		"status_code":  resp.StatusCode,
		"http_request": latency,
		"body_bytes":   len(readBody),
	}
	bodyForResult := readBody
	if len(readBody) > maxBodyBytes {
		bodyForResult = readBody[:maxBodyBytes]
	}
	if maxBodyBytes > 0 && len(readBody) > 0 {
		result["body"] = string(bodyForResult)
	}
	for key, value := range trace.timings(started) {
		result[key] = value
	}
	if altSvc := resp.Header.Get("Alt-Svc"); strings.TrimSpace(altSvc) != "" {
		result["alt_svc"] = altSvc
		result["http3_advertised"] = strings.Contains(strings.ToLower(altSvc), "h3")
	}
	if expectedStatus := intOption(options, "expected_status", 0); expectedStatus > 0 && resp.StatusCode != expectedStatus {
		return latency, responseIP, result, fmt.Errorf("unexpected HTTP status: got %d want %d", resp.StatusCode, expectedStatus)
	}
	if contains := strings.TrimSpace(stringOptionAny(options, "expect_body_contains")); contains != "" && !strings.Contains(string(readBody), contains) {
		return latency, responseIP, result, errors.New("HTTP body assertion failed")
	}
	if len(readBody) > maxBodyBytes {
		result["body_truncated"] = true
		result["body_bytes"] = maxBodyBytes
	}
	return latency, responseIP, result, nil
}

func httpRequestPayload(payload map[string]any) (string, string, map[string]string, string) {
	raw, _ := payload["http_request"].(map[string]any)
	if raw == nil {
		raw = payload
	}
	target := strings.TrimSpace(fmt.Sprint(raw["url"]))
	method := strings.ToUpper(strings.TrimSpace(fmt.Sprint(raw["method"])))
	headers := map[string]string{}
	if rawHeaders, ok := raw["headers"].(map[string]any); ok {
		for key, value := range rawHeaders {
			headers[key] = fmt.Sprint(value)
		}
	}
	body := ""
	if raw["body"] != nil {
		body = fmt.Sprint(raw["body"])
	}
	return target, method, headers, body
}

type httpTimingTrace struct {
	dnsStart     time.Time
	dnsDone      time.Time
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	gotConn      time.Time
	firstByte    time.Time
}

func (t *httpTimingTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.dnsStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.dnsDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			t.connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			t.connectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			t.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.tlsDone = time.Now()
		},
		GotConn: func(httptrace.GotConnInfo) {
			t.gotConn = time.Now()
		},
		GotFirstResponseByte: func() {
			t.firstByte = time.Now()
		},
	}
}

func (t *httpTimingTrace) timings(started time.Time) map[string]any {
	result := map[string]any{}
	if !t.dnsStart.IsZero() && !t.dnsDone.IsZero() {
		result["dns_ms"] = elapsedBetweenMS(t.dnsStart, t.dnsDone)
	}
	if !t.connectStart.IsZero() && !t.connectDone.IsZero() {
		result["connect_ms"] = elapsedBetweenMS(t.connectStart, t.connectDone)
	}
	if !t.tlsStart.IsZero() && !t.tlsDone.IsZero() {
		result["tls_ms"] = elapsedBetweenMS(t.tlsStart, t.tlsDone)
	}
	if !t.gotConn.IsZero() {
		result["time_to_connection_ms"] = elapsedBetweenMS(started, t.gotConn)
	}
	if !t.firstByte.IsZero() {
		result["ttfb_ms"] = elapsedBetweenMS(started, t.firstByte)
	}
	return result
}

func runDNSLookup(ctx context.Context, payload map[string]any) (map[string]any, error) {
	domain := strings.TrimSpace(fmt.Sprint(payload["domain"]))
	if domain == "" {
		return nil, errors.New("dns domain is required")
	}
	recordType := "A"
	if records, ok := payload["record_types"].([]any); ok && len(records) > 0 {
		recordType = strings.ToUpper(strings.TrimSpace(fmt.Sprint(records[0])))
	}
	resolver := net.DefaultResolver
	if server := strings.TrimSpace(fmt.Sprint(payload["dns_server"])); server != "" && server != "<nil>" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
				return dialer.DialContext(ctx, "udp", dnsServerAddress(server))
			},
		}
	}
	started := time.Now()
	var answers []map[string]any
	switch recordType {
	case "AAAA", "A":
		ips, err := resolver.LookupIP(ctx, "ip", domain)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if recordType == "A" && ip.To4() == nil {
				continue
			}
			if recordType == "AAAA" && ip.To4() != nil {
				continue
			}
			answers = append(answers, map[string]any{"type": recordType, "data": ip.String()})
		}
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		answers = append(answers, map[string]any{"type": "CNAME", "data": cname})
	case "MX":
		rows, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "MX", "data": row.Host, "preference": row.Pref})
		}
	case "TXT":
		rows, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "TXT", "data": row})
		}
	case "NS":
		rows, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "NS", "data": row.Host})
		}
	default:
		return nil, fmt.Errorf("unsupported dns record type: %s", recordType)
	}
	return map[string]any{"answers": answers, "dns_lookup": elapsedMS(started)}, nil
}

func runDNSCompare(ctx context.Context, payload map[string]any, options map[string]any) (map[string]any, error) {
	domain := strings.TrimSpace(fmt.Sprint(payload["domain"]))
	if domain == "" || domain == "<nil>" {
		domain = strings.TrimSpace(fmt.Sprint(payload["target"]))
	}
	if domain == "" || domain == "<nil>" {
		return nil, errors.New("dns_compare domain is required")
	}
	recordType := strings.ToUpper(strings.TrimSpace(fmt.Sprint(payload["record_type"])))
	if recordType == "" || recordType == "<NIL>" {
		recordType = strings.ToUpper(strings.TrimSpace(stringOptionAny(options, "record_type")))
	}
	if recordType == "" {
		recordType = "A"
	}
	resolvers := compareResolvers(payload["resolvers"])
	if len(resolvers) == 0 {
		resolvers = compareResolvers(options["compare_resolvers"])
	}
	if len(resolvers) == 0 {
		resolvers = []string{"system", "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"}
	}
	if len(resolvers) > 6 {
		resolvers = resolvers[:6]
	}
	started := time.Now()
	rows := make([]map[string]any, 0, len(resolvers))
	sets := map[string]int{}
	successes := 0
	for _, resolver := range resolvers {
		rowPayload := map[string]any{
			"domain":       domain,
			"record_types": []any{recordType},
		}
		if !strings.EqualFold(resolver, "system") {
			rowPayload["dns_server"] = resolver
		}
		rowStarted := time.Now()
		result, err := runDNSLookup(ctx, rowPayload)
		row := map[string]any{
			"resolver":   resolver,
			"latency_ms": elapsedMS(rowStarted),
			"success":    err == nil,
		}
		if err != nil {
			row["error"] = err.Error()
		} else {
			successes++
			answers, _ := result["answers"].([]map[string]any)
			row["answers"] = answers
			key := answerSetKey(answers)
			row["answer_set_key"] = key
			sets[key]++
		}
		rows = append(rows, row)
	}
	consistent := len(sets) <= 1 && successes == len(resolvers)
	return map[string]any{
		"dns_compare":    elapsedMS(started),
		"domain":         domain,
		"record_type":    recordType,
		"resolvers":      rows,
		"resolver_count": len(resolvers),
		"success_count":  successes,
		"mismatch_count": maxInt(0, len(sets)-1),
		"consistent":     consistent,
	}, nil
}

func runHTTP3Check(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	return runHTTP3CheckWithTLSConfig(ctx, target, options, nil)
}

func runHTTP3CheckWithTLSConfig(ctx context.Context, target string, options map[string]any, tlsConfig *tls.Config) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("http3_check target is required")
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("http3_check requires https URL")
	}
	started := time.Now()
	_, _, httpsResponse, _ := runHTTPRequest(ctx, http.MethodGet, target, nil, "", map[string]any{"max_body_bytes": 0})
	result := map[string]any{
		"http3_check": elapsedMS(started),
	}
	altSvc := strings.ToLower(strings.TrimSpace(fmt.Sprint(httpsResponse["alt_svc"])))
	if strings.TrimSpace(fmt.Sprint(httpsResponse["alt_svc"])) != "" {
		result["alt_svc"] = httpsResponse["alt_svc"]
	}
	result["http3_advertised"] = strings.Contains(altSvc, "h3")
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	udpTarget := net.JoinHostPort(parsed.Hostname(), port)
	udpResult, udpErr := runUDPProbe(ctx, udpTarget, map[string]any{"payload": "", "wait_response": false, "read_timeout_ms": 500})
	if udpErr != nil {
		result["udp_443_reachable"] = false
		result["udp_error"] = udpErr.Error()
	} else {
		result["udp_443_reachable"] = true
		result["response_ip"] = stringFromMap(udpResult, "response_ip")
	}
	method := strings.ToUpper(strings.TrimSpace(firstNonEmptyStringAgent(stringOptionAny(options, "http_method"), stringOptionAny(options, "method"))))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return result, fmt.Errorf("http3_check method must be GET or POST")
	}
	body := ""
	if method == http.MethodPost {
		body = stringOptionAny(options, "http_body")
	}
	headers := map[string]string{}
	for _, item := range []struct {
		option string
		header string
	}{
		{"http_user_agent", "user-agent"},
		{"http_referer", "referer"},
		{"http_cookie", "cookie"},
		{"http_content_type", "content-type"},
	} {
		if value := strings.TrimSpace(stringOptionAny(options, item.option)); value != "" {
			headers[item.header] = value
		}
	}
	latency, responseIP, http3Response, err := runHTTP3RequestWithTLSConfig(ctx, method, target, headers, body, options, tlsConfig)
	for key, value := range http3Response {
		result[key] = value
	}
	result["http3_check"] = elapsedMS(started)
	result["http3_latency_ms"] = latency
	result["protocol"] = "HTTP/3"
	result["http3_used"] = err == nil
	result["http3_ready"] = err == nil
	if responseIP != "" {
		result["response_ip"] = responseIP
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func runHTTP3Request(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any) (float64, string, map[string]any, error) {
	return runHTTP3RequestWithTLSConfig(ctx, method, target, headers, body, options, nil)
}

func runHTTP3RequestWithTLSConfig(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any, tlsConfig *tls.Config) (float64, string, map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	responseIP := ""
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: deadlineTimeout(ctx, 5*time.Second),
			MaxIdleTimeout:       deadlineTimeout(ctx, 10*time.Second),
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
			if err == nil {
				responseIP = remoteAddrIP(conn.RemoteAddr())
			}
			return conn, err
		},
	}
	defer transport.Close()
	client := &http.Client{
		Transport: transport,
		Timeout:   deadlineTimeout(ctx, 10*time.Second),
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return elapsedMS(started), responseIP, map[string]any{}, err
	}
	defer resp.Body.Close()
	maxBodyBytes := intOption(options, "max_body_bytes", 1<<20)
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	if maxBodyBytes > 1<<20 {
		maxBodyBytes = 1 << 20
	}
	readBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBodyBytes)+1))
	latency := elapsedMS(started)
	result := map[string]any{
		"status_code":       resp.StatusCode,
		"body_bytes":        len(readBody),
		"http3_request":     latency,
		"negotiated_proto":  http3.NextProtoH3,
		"http_version":      resp.Proto,
		"http3_status_code": resp.StatusCode,
	}
	if len(readBody) > maxBodyBytes {
		result["body_truncated"] = true
		result["body_bytes"] = maxBodyBytes
	}
	if responseIP == "" && resp.Request != nil && resp.Request.URL != nil {
		responseIP = literalIP(resp.Request.URL.Hostname())
	}
	if expectedStatus := intOption(options, "expected_status", 0); expectedStatus > 0 && resp.StatusCode != expectedStatus {
		return latency, responseIP, result, fmt.Errorf("unexpected HTTP/3 status: got %d want %d", resp.StatusCode, expectedStatus)
	}
	if contains := strings.TrimSpace(stringOptionAny(options, "expect_body_contains")); contains != "" && !strings.Contains(string(readBody), contains) {
		return latency, responseIP, result, errors.New("HTTP/3 body assertion failed")
	}
	return latency, responseIP, result, nil
}

func runNodeStatus() (map[string]any, error) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	host, _ := os.Hostname()
	result := map[string]any{
		"node_status":        0,
		"hostname":           strings.TrimSpace(host),
		"goos":               runtime.GOOS,
		"goarch":             runtime.GOARCH,
		"go_version":         runtime.Version(),
		"cpu_count":          runtime.NumCPU(),
		"goroutines":         runtime.NumGoroutine(),
		"memory_alloc_bytes": stats.Alloc,
		"memory_sys_bytes":   stats.Sys,
	}
	if loadAvg := readProcField("/proc/loadavg", 0); loadAvg != "" {
		result["loadavg_1m"] = loadAvg
	}
	if uptime := readProcField("/proc/uptime", 0); uptime != "" {
		if parsed, err := strconv.ParseFloat(uptime, 64); err == nil {
			result["uptime_seconds"] = parsed
		}
	}
	if disk := rootDiskUsage(); disk != nil {
		result["disk_total_bytes"] = disk["total"]
		result["disk_free_bytes"] = disk["free"]
		result["disk_used_percent"] = disk["used_percent"]
	}
	return result, nil
}

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
	args := []string{"start", cfg.UpgradeUnit}
	started := time.Now()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	result := map[string]any{
		"mode":     "systemd",
		"unit":     cfg.UpgradeUnit,
		"version":  versionValue,
		"duration": elapsedMS(started),
		"stdout":   truncateOutput(string(out), 16*1024),
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

func runTLSCheck(ctx context.Context, payload map[string]any) (map[string]any, error) {
	host := strings.TrimSpace(fmt.Sprint(payload["host"]))
	if host == "" {
		host = strings.TrimSpace(fmt.Sprint(payload["target"]))
	}
	if host == "" || host == "<nil>" {
		return nil, errors.New("tls host is required")
	}
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
		if parsed.Port() != "" {
			host = net.JoinHostPort(host, parsed.Port())
		}
	}
	serverName := host
	if rawName := strings.TrimSpace(fmt.Sprint(payload["server_name"])); rawName != "" && rawName != "<nil>" {
		serverName = rawName
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		port := strings.TrimSpace(fmt.Sprint(payload["port"]))
		if port == "" || port == "<nil>" {
			port = "443"
		}
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if h, _, err := net.SplitHostPort(host); err == nil && serverName == host {
		serverName = strings.Trim(h, "[]")
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 5*time.Second)}
	started := time.Now()
	conn, err := tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	cert := state.PeerCertificates[0]
	responseIP := remoteAddrIP(conn.RemoteAddr())
	return map[string]any{
		"tls_check":          elapsedMS(started),
		"response_ip":        responseIP,
		"remote_addr":        conn.RemoteAddr().String(),
		"server_name":        serverName,
		"not_before":         cert.NotBefore.UTC(),
		"not_after":          cert.NotAfter.UTC(),
		"days_until_expiry":  int(time.Until(cert.NotAfter).Hours() / 24),
		"subject":            cert.Subject.String(),
		"issuer":             cert.Issuer.String(),
		"dns_names":          cert.DNSNames,
		"verified_chains":    len(state.VerifiedChains),
		"negotiated_proto":   state.NegotiatedProtocol,
		"cipher_suite":       tls.CipherSuiteName(state.CipherSuite),
		"handshake_complete": state.HandshakeComplete,
	}, nil
}

func runTraceroute(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("traceroute target is required")
	}
	path, err := exec.LookPath("traceroute")
	if err != nil {
		return nil, errors.New("traceroute command not found")
	}
	maxHops := intOption(options, "max_hops", 30)
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 64 {
		maxHops = 64
	}
	protocol := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "protocol")))
	args := []string{"-n", "-m", strconv.Itoa(maxHops), "-q", "1", "-w", "2"}
	switch protocol {
	case "icmp":
		args = append(args, "-I")
	case "tcp":
		args = append(args, "-T")
	case "", "udp":
		protocol = "udp"
	default:
		return nil, fmt.Errorf("unsupported traceroute protocol: %s", protocol)
	}
	args = append(args, target)
	started := time.Now()
	out, cmdErr := exec.CommandContext(ctx, path, args...).CombinedOutput()
	hops := parseTraceHops(string(out))
	targetIP := firstResolvedIP(ctx, target)
	reached := traceReachedTarget(hops, targetIP)
	if cmdErr != nil && len(hops) == 0 {
		return nil, fmt.Errorf("traceroute failed: %s", strings.TrimSpace(string(out)))
	}
	result := map[string]any{
		"traceroute": elapsedMS(started),
		"hops":       hops,
		"hop_count":  len(hops),
		"max_hops":   maxHops,
		"protocol":   protocol,
		"reached":    reached,
		"raw_output": strings.TrimSpace(string(out)),
	}
	if targetIP != "" {
		result["target_ip"] = targetIP
	}
	if cmdErr != nil {
		result["command_error"] = cmdErr.Error()
	}
	return result, nil
}

func runMTR(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("mtr target is required")
	}
	path, err := exec.LookPath("mtr")
	if err != nil {
		return nil, errors.New("mtr command not found")
	}
	reportCycles := intOption(options, "report_cycles", 5)
	if reportCycles < 1 {
		reportCycles = 1
	}
	if reportCycles > 20 {
		reportCycles = 20
	}
	maxHops := intOption(options, "max_hops", 30)
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 64 {
		maxHops = 64
	}
	protocol := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "protocol")))
	args := []string{"-r", "-c", strconv.Itoa(reportCycles), "-m", strconv.Itoa(maxHops), "-n", "-j"}
	switch protocol {
	case "icmp", "":
		protocol = "icmp"
	case "udp":
		args = append(args, "-u")
	case "tcp":
		args = append(args, "-T")
	default:
		return nil, fmt.Errorf("unsupported mtr protocol: %s", protocol)
	}
	args = append(args, target)
	started := time.Now()
	out, cmdErr := exec.CommandContext(ctx, path, args...).CombinedOutput()
	result, parseErr := parseMTRJSON(out)
	if parseErr != nil {
		if cmdErr != nil {
			return nil, fmt.Errorf("mtr failed: %s", strings.TrimSpace(string(out)))
		}
		return nil, parseErr
	}
	targetIP := firstResolvedIP(ctx, target)
	hops, _ := result["hops"].([]map[string]any)
	result["mtr"] = elapsedMS(started)
	result["hop_count"] = len(hops)
	result["max_hops"] = maxHops
	result["report_cycles"] = reportCycles
	result["protocol"] = protocol
	result["reached"] = traceReachedTarget(hops, targetIP)
	result["raw_output"] = strings.TrimSpace(string(out))
	if targetIP != "" {
		result["target_ip"] = targetIP
	}
	if cmdErr != nil {
		result["command_error"] = cmdErr.Error()
	}
	return result, nil
}

func parseTraceHops(output string) []map[string]any {
	var hops []map[string]any
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hopNumber, err := strconv.Atoi(strings.TrimSuffix(fields[0], "."))
		if err != nil {
			continue
		}
		hop := map[string]any{"hop": hopNumber}
		var rtts []float64
		timeout := false
		for index := 1; index < len(fields); index++ {
			field := strings.Trim(fields[index], "(),")
			if field == "*" {
				timeout = true
				continue
			}
			if ip := net.ParseIP(field); ip != nil {
				if hop["ip"] == nil {
					hop["ip"] = ip.String()
				}
				continue
			}
			if value, err := strconv.ParseFloat(strings.TrimSuffix(field, "ms"), 64); err == nil {
				if index+1 < len(fields) && strings.EqualFold(strings.Trim(fields[index+1], ","), "ms") {
					rtts = append(rtts, value)
				} else if strings.HasSuffix(fields[index], "ms") {
					rtts = append(rtts, value)
				}
				continue
			}
			if hop["host"] == nil && !strings.EqualFold(field, "ms") {
				hop["host"] = field
			}
		}
		if len(rtts) > 0 {
			hop["rtt_ms"] = rtts[0]
			hop["rtts_ms"] = rtts
		}
		if timeout && hop["ip"] == nil && hop["host"] == nil {
			hop["timeout"] = true
		}
		hops = append(hops, hop)
	}
	return hops
}

func parseMTRJSON(raw []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse mtr json: %w", err)
	}
	report, _ := doc["report"].(map[string]any)
	if report == nil {
		return nil, errors.New("mtr json report is missing")
	}
	rawHubs, _ := report["hubs"].([]any)
	hops := make([]map[string]any, 0, len(rawHubs))
	for _, rawHub := range rawHubs {
		hub, _ := rawHub.(map[string]any)
		if hub == nil {
			continue
		}
		hop := map[string]any{}
		if value := intFromAny(hub["count"]); value > 0 {
			hop["hop"] = value
		}
		host := strings.TrimSpace(fmt.Sprint(hub["host"]))
		if host != "" && host != "<nil>" {
			hop["host"] = host
			if ip := net.ParseIP(host); ip != nil {
				hop["ip"] = ip.String()
			}
		}
		copyMTRFloat(hop, "loss_percent", hub["Loss%"])
		copyMTRFloat(hop, "sent", hub["Snt"])
		copyMTRFloat(hop, "last_ms", hub["Last"])
		copyMTRFloat(hop, "avg_ms", hub["Avg"])
		copyMTRFloat(hop, "best_ms", hub["Best"])
		copyMTRFloat(hop, "worst_ms", hub["Wrst"])
		copyMTRFloat(hop, "stdev_ms", hub["StDev"])
		hops = append(hops, hop)
	}
	return map[string]any{"hops": hops}, nil
}

func copyMTRFloat(target map[string]any, key string, raw any) {
	if value, ok := floatFromAny(raw); ok {
		target[key] = value
	}
}

func traceReachedTarget(hops []map[string]any, targetIP string) bool {
	targetIP = strings.TrimSpace(targetIP)
	if len(hops) == 0 || targetIP == "" {
		return false
	}
	last := hops[len(hops)-1]
	return strings.TrimSpace(fmt.Sprint(last["ip"])) == targetIP || strings.TrimSpace(fmt.Sprint(last["host"])) == targetIP
}

func firstResolvedIP(ctx context.Context, target string) string {
	host := strings.TrimSpace(target)
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}

func discoverPublicIP(ctx context.Context) string {
	for _, endpoint := range []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipv4.icanhazip.com",
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if ip != nil && isPublicIP(ip) {
			return ip.String()
		}
	}
	return ""
}

func postJSON(ctx context.Context, cfg config, path string, payload any, out any) error {
	return postJSONWithToken(ctx, cfg, cfg.Token, path, payload, out)
}

func postAgentJSON(ctx context.Context, cfg config, path string, payload any, out any) error {
	return postJSONWithToken(ctx, cfg, cfg.AgentToken, path, payload, out)
}

func getJSONWithToken(ctx context.Context, cfg config, token string, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ServerURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func postJSONWithToken(ctx context.Context, cfg config, token string, path string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func dnsServerAddress(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if strings.Count(server, ":") > 1 {
		return net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	return net.JoinHostPort(server, "53")
}

func parsePingLatency(out string) float64 {
	for _, marker := range []string{"time=", "time<"} {
		index := strings.Index(out, marker)
		if index < 0 {
			continue
		}
		rest := out[index+len(marker):]
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value := strings.Trim(fields[0], " ms")
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return 0
}

func deadlineTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
	}
	return fallback
}

func elapsedMS(started time.Time) float64 {
	return math.Round(float64(time.Since(started).Microseconds())) / 1000
}

func elapsedBetweenMS(started time.Time, finished time.Time) float64 {
	return math.Round(float64(finished.Sub(started).Microseconds())) / 1000
}

func literalIP(value string) string {
	ip := net.ParseIP(strings.Trim(value, "[] "))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func hostLiteralIP(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return literalIP(value)
	}
	return literalIP(host)
}

func remoteAddrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return literalIP(host)
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(values[key]))
}

func stringOptionAny(options map[string]any, key string) string {
	if options == nil {
		return ""
	}
	switch value := options[key].(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	case json.Number:
		return value.String()
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func firstNonEmptyStringAgent(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func intOption(options map[string]any, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	return intFromAnyDefault(options[key], fallback)
}

func boolOptionDefault(options map[string]any, key string, fallback bool) bool {
	if options == nil {
		return fallback
	}
	switch value := options[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	case json.Number:
		parsed, _ := value.Int64()
		return parsed != 0
	case int:
		return value != 0
	case float64:
		return value != 0
	}
	return fallback
}

func intFromAnyDefault(raw any, fallback int) int {
	if value := intFromAny(raw); value != 0 {
		return value
	}
	return fallback
}

func intFromAny(raw any) int {
	switch value := raw.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		if parsed, err := value.Int64(); err == nil {
			return int(parsed)
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return parsed
		}
	}
	return 0
}

func floatFromMap(values map[string]any, key string) float64 {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		parsed, _ := value.Float64()
		return parsed
	default:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(value)), 64)
		return parsed
	}
}

func minFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}

func maxFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, value := range values[1:] {
		if value > max {
			max = value
		}
	}
	return max
}

func avgFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func jitterStats(values []float64) (float64, float64) {
	if len(values) < 2 {
		return 0, 0
	}
	jitters := make([]float64, 0, len(values)-1)
	for index := 1; index < len(values); index++ {
		jitter := math.Abs(values[index] - values[index-1])
		jitters = append(jitters, jitter)
	}
	return avgFloat(jitters), maxFloat(jitters)
}

func percentileFloat(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	if percentile <= 0 {
		return cp[0]
	}
	if percentile >= 1 {
		return cp[len(cp)-1]
	}
	index := int(math.Ceil(percentile*float64(len(cp)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(cp) {
		index = len(cp) - 1
	}
	return cp[index]
}

func lossPercent(total int, successes int) float64 {
	if total <= 0 {
		return 0
	}
	failures := total - successes
	if failures < 0 {
		failures = 0
	}
	return float64(failures) * 100 / float64(total)
}

func compareResolvers(raw any) []string {
	var values []string
	switch rows := raw.(type) {
	case []any:
		for _, item := range rows {
			values = append(values, fmt.Sprint(item))
		}
	case []string:
		values = append(values, rows...)
	case string:
		values = strings.FieldsFunc(rows, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';'
		})
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[strings.ToLower(value)] {
			continue
		}
		seen[strings.ToLower(value)] = true
		result = append(result, value)
	}
	return result
}

func answerSetKey(answers []map[string]any) string {
	values := make([]string, 0, len(answers))
	for _, answer := range answers {
		value := strings.TrimSpace(fmt.Sprint(answer["data"]))
		if value == "" || value == "<nil>" {
			value = strings.TrimSpace(fmt.Sprint(answer["value"]))
		}
		if value != "" && value != "<nil>" {
			values = append(values, strings.ToLower(value))
		}
	}
	sort.Strings(values)
	return strings.Join(values, "|")
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func floatFromAny(raw any) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func isPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func readProcField(path string, index int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(raw))
	if index < 0 || index >= len(fields) {
		return ""
	}
	return fields[index]
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
	if value := readAgentIDFile(defaultAgentIDFile()); value != "" {
		return value
	}
	host := sanitizeAgentIDPart(hostname())
	seed := strings.Join([]string{
		host,
		readFirstExistingFile("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"),
	}, ":")
	if strings.Trim(seed, ":") == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err == nil {
			seed = hex.EncodeToString(raw)
		} else {
			seed = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
	}
	sum := sha256.Sum256([]byte(seed))
	suffix := hex.EncodeToString(sum[:])[:12]
	if host == "" {
		host = "nodeping-agent"
	}
	value := "agent-" + host + "-" + suffix
	_ = writeAgentIDFile(defaultAgentIDFile(), value)
	return value
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
