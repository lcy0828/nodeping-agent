package main

import (
	"encoding/json"
	"net/http"
	"time"
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
	StreamIdleTimeout  time.Duration
	StreamRetryMin     time.Duration
	StreamRetryMax     time.Duration
	Concurrency        int
	HTTPClient         *http.Client
	PrintVersion       bool
	Doctor             bool
	DoctorJSON         bool
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
	AgentID    string `json:"agent_id"`
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
	Key          string   `json:"key,omitempty"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Severity     string   `json:"severity,omitempty"`
	Message      string   `json:"message,omitempty"`
	Remediation  string   `json:"remediation,omitempty"`
	Path         string   `json:"path,omitempty"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Required     bool     `json:"required,omitempty"`
}

type doctorSnapshot struct {
	Status       string        `json:"status"`
	InstallMode  string        `json:"install_mode"`
	Version      string        `json:"version"`
	AgentID      string        `json:"agent_id,omitempty"`
	Capabilities []string      `json:"capabilities"`
	Checks       []doctorCheck `json:"checks"`
	CheckCount   int           `json:"check_count"`
	FailedCount  int           `json:"failed_count"`
	WarningCount int           `json:"warning_count"`
	GeneratedAt  time.Time     `json:"generated_at"`
}

var capabilities = []string{"ping", "tcp_ping", "long_ping", "long_tcp_ping", "udp_probe", "http_ping", "http_request", "http3_check", "dns_lookup", "dns_compare", "tls_check", "traceroute", "mtr", "node_status", "ip"}
