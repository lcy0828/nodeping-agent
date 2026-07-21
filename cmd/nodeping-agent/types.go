package main

import (
	"encoding/json"
	"net/http"
	"time"

	"nodeping/internal/dnsobs"
)

type config struct {
	ServerURL          string
	Token              string
	AgentToken         string
	AgentTokenFile     string
	AgentIDFile        string
	AgentID            string
	Name               string
	Version            string
	UpgradeMode        string
	UpgradeUnit        string
	UpgradeScript      string
	UpgradeRequestFile string
	ReleaseProxyFile   string
	LatestVersionFile  string
	DNSRootStateDir    string
	DNSRootHintsFile   string
	DNSRootManifest    string
	DNSRootPublicKeys  string
	DNSAnchorBinary    string
	DNSCheckconfBinary string
	HeartbeatInterval  time.Duration
	PublicIPInterval   time.Duration
	StreamIdleTimeout  time.Duration
	StreamRetryMin     time.Duration
	StreamRetryMax     time.Duration
	ShutdownDrain      time.Duration
	Concurrency        int
	HTTPClient         *http.Client
	AllowInsecureHTTP  bool
	RestartRequested   chan struct{}
	PrintVersion       bool
	Doctor             bool
	DoctorJSON         bool
	Liveness           bool
}

type taskRequest struct {
	ID             string          `json:"task_id"`
	NodeID         int64           `json:"node_id"`
	AgentID        string          `json:"agent_id"`
	TaskType       string          `json:"task_type"`
	Payload        json.RawMessage `json:"payload"`
	Options        map[string]any  `json:"options,omitempty"`
	TimeoutMS      int             `json:"timeout_ms,omitempty"`
	MaxConcurrency int             `json:"max_concurrency,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Operation      string          `json:"operation,omitempty"`
	CancelTaskID   string          `json:"cancel_task_id,omitempty"`
}

type taskResult struct {
	TaskID       string              `json:"task_id"`
	Status       string              `json:"status"`
	Success      bool                `json:"success"`
	LatencyMS    float64             `json:"latency_ms,omitempty"`
	ResponseIP   string              `json:"response_ip,omitempty"`
	Result       map[string]any      `json:"result,omitempty"`
	DNSResult    *dnsobs.BatchResult `json:"dns_result,omitempty"`
	Extra        map[string]any      `json:"extra,omitempty"`
	ErrorCode    string              `json:"error_code,omitempty"`
	ErrorMessage string              `json:"error_message,omitempty"`
	FinishedAt   time.Time           `json:"finished_at"`
}

type taskEvent struct {
	TaskID         string              `json:"task_id"`
	Status         string              `json:"status"`
	Message        string              `json:"message,omitempty"`
	Progress       int                 `json:"progress,omitempty"`
	EventKind      string              `json:"event_kind,omitempty"`
	DNSObservation *dnsobs.Observation `json:"dns_observation,omitempty"`
	Extra          map[string]any      `json:"extra,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
}

type registerResponse struct {
	AgentID        string              `json:"agent_id"`
	AgentToken     string              `json:"agent_token"`
	ReleaseProxies []agentReleaseProxy `json:"release_proxies"`
	LatestVersion  string              `json:"latest_version"`
}

type heartbeatResponse struct {
	ReleaseProxies []agentReleaseProxy `json:"release_proxies"`
	LatestVersion  string              `json:"latest_version"`
}

type agentReleaseProxy struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	BaseURL    string `json:"base_url"`
	Mode       string `json:"mode"`
	QueryParam string `json:"query_param,omitempty"`
	Priority   int    `json:"priority"`
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
	IssueCode    string   `json:"issue_code,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Message      string   `json:"message,omitempty"`
	Remediation  string   `json:"remediation,omitempty"`
	Path         string   `json:"path,omitempty"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Required     bool     `json:"required,omitempty"`
}

type doctorComponentReadiness struct {
	Ready      bool   `json:"ready"`
	ReasonCode string `json:"reason_code"`
	Version    string `json:"version,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

type doctorDNSWireCodeAvailability struct {
	AllAvailable bool `json:"all_available"`
	UDP          bool `json:"udp"`
	TCP          bool `json:"tcp"`
	DoT          bool `json:"dot"`
	DoH          bool `json:"doh"`
	DoQ          bool `json:"doq"`
}

type doctorDNSObservationReadiness struct {
	Ready              bool                          `json:"ready"`
	ReasonCode         string                        `json:"reason_code"`
	SystemDNSDiscovery doctorComponentReadiness      `json:"system_dns_discovery"`
	WireTransports     doctorDNSWireCodeAvailability `json:"wire_transports"`
	UnboundWorker      doctorComponentReadiness      `json:"unbound_worker"`
	DNSTapCollector    doctorComponentReadiness      `json:"dnstap_collector"`
	RootHints          doctorComponentReadiness      `json:"root_hints"`
	TrustAnchor        doctorComponentReadiness      `json:"trust_anchor"`
	Fixtures           doctorComponentReadiness      `json:"fixtures"`
}

type doctorSnapshot struct {
	Status                  string                        `json:"status"`
	InstallMode             string                        `json:"install_mode"`
	Version                 string                        `json:"version"`
	AgentID                 string                        `json:"agent_id,omitempty"`
	Capabilities            []string                      `json:"capabilities"`
	DNSObservationReadiness doctorDNSObservationReadiness `json:"dns_observation_readiness"`
	Checks                  []doctorCheck                 `json:"checks"`
	CheckCount              int                           `json:"check_count"`
	FailedCount             int                           `json:"failed_count"`
	WarningCount            int                           `json:"warning_count"`
	GeneratedAt             time.Time                     `json:"generated_at"`
}
