package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestDNSServerAddressDefaultsPort(t *testing.T) {
	tests := map[string]string{
		"8.8.8.8":                "8.8.8.8:53",
		"8.8.8.8:5353":           "8.8.8.8:5353",
		"2001:4860::8888":        "[2001:4860::8888]:53",
		"[2001:4860::8888]:5353": "[2001:4860::8888]:5353",
	}
	for input, want := range tests {
		if got := dnsServerAddress(input); got != want {
			t.Fatalf("dnsServerAddress(%q)=%q want %q", input, got, want)
		}
	}
}

func TestReadSSETasksAllowsLargePayload(t *testing.T) {
	large := strings.Repeat("x", 128*1024)
	stream := fmt.Sprintf("event: task\ndata: {\"task_id\":\"task-large\",\"agent_id\":\"agent-a\",\"task_type\":\"http_request\",\"payload\":{\"http_request\":{\"url\":\"https://example.com/\",\"body\":\"%s\"}}}\n\n", large)
	var got taskRequest
	err := readSSETasks(context.Background(), strings.NewReader(stream), func(task taskRequest) {
		got = task
	})
	if err != nil {
		t.Fatalf("readSSETasks returned error: %v", err)
	}
	if got.ID != "task-large" {
		t.Fatalf("task id = %q", got.ID)
	}
}

func TestTaskStreamHTTPClientKeepsLongLivedConnection(t *testing.T) {
	base := &http.Client{Timeout: 30 * time.Second}
	streamClient := taskStreamHTTPClient(config{HTTPClient: base})
	if streamClient == base {
		t.Fatal("taskStreamHTTPClient should not mutate the shared client")
	}
	if streamClient.Timeout != 0 {
		t.Fatalf("stream client timeout = %s, want no timeout", streamClient.Timeout)
	}
	if base.Timeout != 30*time.Second {
		t.Fatalf("base client timeout mutated to %s", base.Timeout)
	}
}

func TestDoctorConfigReportsMissingRequiredValues(t *testing.T) {
	check := checkConfig(config{})
	if check.Status != "fail" || !strings.Contains(check.Message, "NODEPING_SERVER_URL") || !strings.Contains(check.Message, "NODEPING_TOKEN") {
		t.Fatalf("checkConfig missing values = %+v", check)
	}
}

func TestFormatDoctorCheckBilingual(t *testing.T) {
	line := formatDoctorCheck(doctorCheck{Name: "backend health", Status: "ok", Message: "http://127.0.0.1:8099"})
	for _, want := range []string{"后端健康", "backend health", "正常", "ok", "http://127.0.0.1:8099"} {
		if !strings.Contains(line, want) {
			t.Fatalf("formatDoctorCheck()=%q, missing %q", line, want)
		}
	}

	missingLine := formatDoctorCheck(doctorCheck{Name: "config", Status: "fail", Message: "missing NODEPING_SERVER_URL, NODEPING_TOKEN"})
	if !strings.Contains(missingLine, "缺少 NODEPING_SERVER_URL, NODEPING_TOKEN") || !strings.Contains(missingLine, "missing NODEPING_SERVER_URL, NODEPING_TOKEN") {
		t.Fatalf("missing config line is not bilingual: %q", missingLine)
	}
}

func TestDoctorAgentTokenFileWritable(t *testing.T) {
	check := checkAgentTokenFile(config{AgentTokenFile: filepath.Join(t.TempDir(), "agent-token")})
	if check.Status != "ok" {
		t.Fatalf("checkAgentTokenFile = %+v", check)
	}
}

func TestAgentIDFilePersistsStableValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	if got := readAgentIDFile(path); got != "" {
		t.Fatalf("empty agent id file read = %q", got)
	}
	if err := writeAgentIDFile(path, "agent-test-123"); err != nil {
		t.Fatalf("writeAgentIDFile: %v", err)
	}
	if got := readAgentIDFile(path); got != "agent-test-123" {
		t.Fatalf("readAgentIDFile()=%q", got)
	}
	if got := sanitizeAgentIDPart(" Host.Name 01 "); got != "host.name-01" {
		t.Fatalf("sanitizeAgentIDPart()=%q", got)
	}
}

func TestAgentTokenCanContinueWhenBindingTokenInvalid(t *testing.T) {
	var statusAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/status":
			statusAuth = r.Header.Get("Authorization")
			if statusAuth != "Bearer agent-token-ok" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"invalid agent token"}}`, http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"registered":true,"node_id":42,"node_status":"active","agent_status":"online"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ok := agentTokenCanContinue(context.Background(), config{
		ServerURL:  server.URL,
		Token:      "deleted-binding-token",
		AgentToken: "agent-token-ok",
		AgentID:    "agent-existing",
		HTTPClient: server.Client(),
	})
	if !ok {
		t.Fatal("expected stored agent token to allow continue")
	}
	if statusAuth != "Bearer agent-token-ok" {
		t.Fatalf("status auth=%q", statusAuth)
	}
}

func TestRegisterAgentReportsServerURL(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/register" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer binding-token" {
			t.Fatalf("authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"agent_id":"agent-test","agent_token":"agent-token","server_time":"2026-06-23T00:00:00Z"}`))
	}))
	defer server.Close()

	_, err := registerAgent(context.Background(), config{
		ServerURL:  server.URL,
		Token:      "binding-token",
		AgentID:    "agent-test",
		Name:       "agent-test",
		Version:    "nodeping-agent/test",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("registerAgent: %v", err)
	}
	if payload["server_url"] != server.URL {
		t.Fatalf("server_url = %#v, want %q; payload=%+v", payload["server_url"], server.URL, payload)
	}
	if caps, ok := payload["capabilities"].([]any); !ok || len(caps) == 0 {
		t.Fatalf("capabilities missing from register payload: %+v", payload)
	}
	dependencies, ok := payload["dependency_status"].(map[string]any)
	if !ok {
		t.Fatalf("dependency_status missing from register payload: %+v", payload)
	}
	if dependencies["status"] == "" || dependencies["install_mode"] == "" {
		t.Fatalf("dependency status missing summary fields: %+v", dependencies)
	}
	if caps, ok := dependencies["capabilities"].([]any); !ok || len(caps) == 0 {
		t.Fatalf("dependency status capabilities missing: %+v", dependencies)
	}
	if checks, ok := dependencies["checks"].([]any); !ok || len(checks) == 0 {
		t.Fatalf("dependency status checks missing: %+v", dependencies)
	}
}

func TestRunAgentDoctorReturnsStructuredChecks(t *testing.T) {
	dir := t.TempDir()
	result, err := runAgentDoctor(context.Background(), config{
		ServerURL:          "https://nodeping.example",
		Token:              "np_test",
		AgentID:            "agent-test",
		Version:            "nodeping-agent/test",
		AgentTokenFile:     filepath.Join(dir, "agent-token"),
		UpgradeMode:        "request_file",
		UpgradeRequestFile: filepath.Join(dir, "update-request.json"),
		HTTPClient:         &http.Client{Timeout: time.Millisecond},
	})
	if result["agent_doctor"] == "" {
		t.Fatalf("missing structured doctor status: %+v", result)
	}
	if result["check_count"].(int) == 0 {
		t.Fatalf("missing checks: %+v", result)
	}
	if _, ok := result["checks"].([]map[string]any); !ok {
		t.Fatalf("checks type = %#v", result["checks"])
	}
	if caps, ok := result["capabilities"].([]string); !ok || len(caps) == 0 {
		t.Fatalf("capabilities type = %#v", result["capabilities"])
	}
	if result["install_mode"] == "" {
		t.Fatalf("missing install mode: %+v", result)
	}
	checks := result["checks"].([]map[string]any)
	if checks[0]["key"] == "" || checks[0]["severity"] == "" {
		t.Fatalf("structured check missing key/severity: %+v", checks[0])
	}
	_ = err
}

func TestDoctorSnapshotCapabilitiesFollowDependencyChecks(t *testing.T) {
	snapshot := doctorSnapshotFromChecks([]doctorCheck{
		{Key: "ping_command", Name: "ping command", Status: "fail", Capabilities: []string{"ping", "long_ping"}},
		{Key: "traceroute_command", Name: "traceroute command", Status: "ok", Path: "/usr/bin/traceroute", Capabilities: []string{"traceroute"}},
		{Key: "mtr_command", Name: "mtr command", Status: "warn", Path: "/usr/bin/mtr", Capabilities: []string{"mtr"}},
	}, config{Version: "nodeping-agent/test", AgentID: "agent-test"})

	for _, missing := range []string{"ping", "long_ping"} {
		if stringSliceContains(snapshot.Capabilities, missing) {
			t.Fatalf("capability %q should be withheld when ping check fails: %+v", missing, snapshot.Capabilities)
		}
	}
	for _, want := range []string{"traceroute", "mtr", "tcp_ping", "http_ping", "dns_lookup"} {
		if !stringSliceContains(snapshot.Capabilities, want) {
			t.Fatalf("capability %q missing from snapshot: %+v", want, snapshot.Capabilities)
		}
	}
	if snapshot.Status != "fail" || snapshot.FailedCount != 1 || snapshot.WarningCount != 1 {
		t.Fatalf("unexpected snapshot status/counts: %+v", snapshot)
	}
}

func TestDoctorSnapshotSkipsMissingOptionalCommandCapabilities(t *testing.T) {
	snapshot := doctorSnapshotFromChecks([]doctorCheck{
		{Key: "ping_command", Name: "ping command", Status: "ok", Path: "/bin/ping", Capabilities: []string{"ping", "long_ping"}},
		{Key: "traceroute_command", Name: "traceroute command", Status: "warn", Message: "traceroute not found", Capabilities: []string{"traceroute"}},
		{Key: "mtr_command", Name: "mtr command", Status: "warn", Message: "mtr not found", Capabilities: []string{"mtr"}},
	}, config{Version: "nodeping-agent/test", AgentID: "agent-test"})

	for _, missing := range []string{"traceroute", "mtr"} {
		if stringSliceContains(snapshot.Capabilities, missing) {
			t.Fatalf("capability %q should be withheld when command is missing: %+v", missing, snapshot.Capabilities)
		}
	}
	for _, want := range []string{"ping", "long_ping", "tcp_ping"} {
		if !stringSliceContains(snapshot.Capabilities, want) {
			t.Fatalf("capability %q missing from snapshot: %+v", want, snapshot.Capabilities)
		}
	}
	if snapshot.Status != "warn" || snapshot.WarningCount != 2 {
		t.Fatalf("unexpected snapshot status/counts: %+v", snapshot)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunAgentUpgradeWritesRequestFile(t *testing.T) {
	dir := t.TempDir()
	requestFile := filepath.Join(dir, "update-request.json")
	result, err := runAgentUpgrade(context.Background(), config{
		AgentID:            "agent-test",
		UpgradeMode:        "request_file",
		UpgradeRequestFile: requestFile,
	}, map[string]any{"version": "1.2.3"}, map[string]any{"release_base_url": "https://nodeping.example/downloads/nodeping-agent"})
	if err != nil {
		t.Fatalf("runAgentUpgrade: %v result=%+v", err, result)
	}
	if result["mode"] != "request_file" || result["queued"] != true {
		t.Fatalf("unexpected request-file result: %+v", result)
	}
	raw, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("read request file: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"version": "1.2.3"`) || !strings.Contains(text, `"release_base_url": "https://nodeping.example/downloads/nodeping-agent"`) {
		t.Fatalf("unexpected request file: %s", text)
	}
}

func TestRunAgentUpgradeScriptUsesFixedPathAndEnv(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "nodeping-agent-update")
	outputFile := filepath.Join(dir, "env.out")
	if err := os.WriteFile(script, []byte(fmt.Sprintf("#!/usr/bin/env sh\nprintf '%%s %%s %%s' \"$NODEPING_AGENT_VERSION\" \"$NODEPING_SERVER_URL\" \"$NODEPING_AGENT_ID\" > %q\n", outputFile)), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	result, err := scriptUpgrade(context.Background(), config{
		ServerURL:     "https://nodeping.example",
		AgentID:       "agent-script",
		UpgradeScript: script,
	}, "2.0.0", "")
	if err != nil {
		t.Fatalf("scriptUpgrade: %v result=%+v", err, result)
	}
	if result["mode"] != "script" || result["completed"] != true {
		t.Fatalf("unexpected script result: %+v", result)
	}
	raw, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(raw) != "2.0.0 https://nodeping.example agent-script" {
		t.Fatalf("unexpected script env: %q", string(raw))
	}
}

func TestRunTLSCheck(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse tls server url: %v", err)
	}
	got, err := runTLSCheck(context.Background(), map[string]any{"host": parsed.Host, "server_name": "example.com"})
	if err == nil {
		t.Fatalf("expected hostname verification failure for self-signed test cert, got result %+v", got)
	}
}

func TestRunLongProbeSummarizesSamples(t *testing.T) {
	calls := 0
	result, err := runLongProbe(context.Background(), "long_ping", "example.com", map[string]any{"sample_count": 3, "interval_ms": 200}, func(context.Context, string) (float64, error) {
		calls++
		if calls == 2 {
			return 0, fmt.Errorf("sample failed")
		}
		return float64(calls * 10), nil
	})
	if err != nil {
		t.Fatalf("runLongProbe: %v", err)
	}
	if result["sample_count"] != 3 || result["completed_count"] != 3 || result["success_count"] != 2 || result["failure_count"] != 1 {
		t.Fatalf("unexpected summary counts: %+v", result)
	}
	if got := result["avg_latency_ms"]; got != 20.0 {
		t.Fatalf("avg_latency_ms = %v, want 20", got)
	}
	if got := result["loss_percent"].(float64); got < 33.3 || got > 33.4 {
		t.Fatalf("loss_percent = %v, want about 33.33", got)
	}
	if got := result["jitter_ms"]; got != 20.0 {
		t.Fatalf("jitter_ms = %v, want 20", got)
	}
	samples, ok := result["samples"].([]map[string]any)
	if !ok || len(samples) != 3 {
		t.Fatalf("samples = %#v", result["samples"])
	}
}

func TestRunLongProbeAllowsSustainedSampleCount(t *testing.T) {
	originalWait := waitLongProbeInterval
	waitLongProbeInterval = func(context.Context, time.Duration) error { return nil }
	defer func() { waitLongProbeInterval = originalWait }()

	calls := 0
	result, err := runLongProbe(context.Background(), "long_ping", "example.com", map[string]any{"sample_count": 125, "interval_ms": 200}, func(context.Context, string) (float64, error) {
		calls++
		return 1, nil
	})
	if err != nil {
		t.Fatalf("runLongProbe: %v", err)
	}
	if result["sample_count"] != 125 || result["completed_count"] != 125 || calls != 125 {
		t.Fatalf("unexpected sustained sample count: calls=%d result=%+v", calls, result)
	}
}

func TestLongProbeProgressReporterPostsEachSample(t *testing.T) {
	var events []taskEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/tasks/task-1/events" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
			t.Fatalf("authorization = %q", got)
		}
		var event taskEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		events = append(events, event)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	report := longProbeProgressReporter(context.Background(), config{
		ServerURL:  server.URL,
		AgentToken: "agent-token",
		HTTPClient: server.Client(),
	}, taskRequest{ID: "task-1"}, "long_ping")
	report(map[string]any{"sample_count": 100, "completed_count": 1, "success_count": 1, "samples": []map[string]any{{"seq": 1, "success": true, "latency_ms": 8.0}}})
	report(map[string]any{"sample_count": 100, "completed_count": 2, "success_count": 2, "samples": []map[string]any{{"seq": 1, "success": true, "latency_ms": 8.0}, {"seq": 2, "success": true, "latency_ms": 9.0}}})

	if len(events) != 2 {
		t.Fatalf("posted events = %d, want 2", len(events))
	}
	if events[0].Progress != 1 || events[1].Progress != 2 {
		t.Fatalf("unexpected progress values: %+v", events)
	}
	if events[1].Extra["event_kind"] != "long_probe_sample" || events[1].Extra["task_type"] != "long_ping" {
		t.Fatalf("unexpected event extra: %+v", events[1].Extra)
	}
}

func TestRunUDPProbe(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		n, addr, err := conn.ReadFrom(buf)
		if err == nil && n > 0 {
			_, _ = conn.WriteTo([]byte("ok"), addr)
		}
	}()

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), map[string]any{"payload": "hello", "wait_response": true, "read_timeout_ms": 1000})
	if err != nil {
		t.Fatalf("runUDPProbe: %v", err)
	}
	if result["response_received"] != true || result["received_bytes"] != 2 {
		t.Fatalf("unexpected udp result: %+v", result)
	}
	<-done
}

func TestRunUDPProbeTimeoutKeepsSendLatencySeparate(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), map[string]any{"payload": "hello", "wait_response": true, "read_timeout_ms": 200})
	if err != nil {
		t.Fatalf("runUDPProbe: %v", err)
	}
	if result["response_timeout"] != true || result["response_received"] != false {
		t.Fatalf("unexpected timeout result: %+v", result)
	}
	if _, ok := result["elapsed_ms"]; !ok {
		t.Fatalf("elapsed_ms missing from timeout result: %+v", result)
	}
	udpLatency, _ := result["udp_probe"].(float64)
	if udpLatency >= 200 {
		t.Fatalf("udp_probe = %v, want send latency rather than read timeout", udpLatency)
	}
	if _, ok := result["send_latency_ms"]; !ok {
		t.Fatalf("send_latency_ms missing from timeout result: %+v", result)
	}
}

func TestRunUDPProbeSendsDNSQueryPayload(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, err := conn.ReadFrom(buf)
		if err == nil {
			received <- append([]byte(nil), buf[:n]...)
		}
	}()

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), map[string]any{"payload_mode": "dns_query", "dns_query_domain": "example.com", "wait_response": false})
	if err != nil {
		t.Fatalf("runUDPProbe: %v", err)
	}
	if result["payload_mode"] != "dns_query" {
		t.Fatalf("payload_mode = %v, want dns_query", result["payload_mode"])
	}
	select {
	case payload := <-received:
		if len(payload) < 12 || payload[2] != 0x01 || payload[5] != 0x01 {
			t.Fatalf("payload does not look like DNS query: %v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for udp payload")
	}
}

func TestRunHTTPRequestAssertionsAndTimings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		_, _ = w.Write([]byte("nodeping-ok"))
	}))
	defer server.Close()

	latency, responseIP, result, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", map[string]any{
		"expected_status":      200,
		"expect_body_contains": "nodeping",
	})
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if latency <= 0 || result["status_code"] != 200 || result["http3_advertised"] != true || result["body"] != "nodeping-ok" {
		t.Fatalf("unexpected http result latency=%v result=%+v", latency, result)
	}
	serverIP := hostLiteralIP(server.Listener.Addr().String())
	if responseIP != serverIP || result["response_ip"] != serverIP {
		t.Fatalf("response IP = %q result=%+v, want %q", responseIP, result, serverIP)
	}
}

func TestRunHTTPRequestReturnsTruncatedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nodeping-body"))
	}))
	defer server.Close()

	_, _, result, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", map[string]any{
		"max_body_bytes": 4,
	})
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if result["body"] != "node" || result["body_truncated"] != true || result["body_bytes"] != 4 {
		t.Fatalf("unexpected truncated body result: %+v", result)
	}
}

func TestRunHTTPRequestUsesOriginalHostHeader(t *testing.T) {
	seenHost := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, _, _, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", map[string]any{
		"original_host": "origin.example.com",
	})
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if seenHost != "origin.example.com" {
		t.Fatalf("Host = %q, want original host", seenHost)
	}
}

func TestExecuteTaskHTTPPingAcceptsObjectPayloadWithOriginalHost(t *testing.T) {
	seenHost := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{"http_ping": map[string]any{
		"url":           server.URL,
		"original_host": "meeting.tencent.com",
	}})
	result := executeTask(context.Background(), config{}, taskRequest{
		ID:       "http-ping-object-payload",
		TaskType: "http_ping",
		Payload:  payload,
	})
	if !result.Success {
		t.Fatalf("executeTask failed: %+v", result)
	}
	if seenHost != "meeting.tencent.com" {
		t.Fatalf("Host = %q, want original host", seenHost)
	}
}

func TestExecuteTaskHTTPPingIncludesResponseIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{"http_ping": server.URL})
	result := executeTask(context.Background(), config{}, taskRequest{
		ID:       "http-ping-response-ip",
		TaskType: "http_ping",
		Payload:  payload,
	})
	serverIP := hostLiteralIP(server.Listener.Addr().String())
	if !result.Success {
		t.Fatalf("executeTask failed: %+v", result)
	}
	if result.ResponseIP != serverIP || result.Result["response_ip"] != serverIP {
		t.Fatalf("response IP = %q result=%+v, want %q", result.ResponseIP, result.Result, serverIP)
	}
}

func TestExecuteTaskHTTPRequestFailureKeepsResponseIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed"))
	}))
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{
		"http_request": map[string]any{
			"url":    server.URL,
			"method": http.MethodGet,
		},
	})
	result := executeTask(context.Background(), config{}, taskRequest{
		ID:       "http-request-failed-response-ip",
		TaskType: "http_request",
		Payload:  payload,
		Options:  map[string]any{"expected_status": 200},
	})
	serverIP := hostLiteralIP(server.Listener.Addr().String())
	if result.Success {
		t.Fatalf("executeTask success = true, want failed status assertion")
	}
	if result.ResponseIP != serverIP || result.Result["response_ip"] != serverIP {
		t.Fatalf("response IP = %q result=%+v, want %q", result.ResponseIP, result.Result, serverIP)
	}
}

func TestRunHTTP3CheckPerformsRealRequest(t *testing.T) {
	cert, parsedCert := mustSelfSignedHTTP3Cert(t)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	seen := make(chan string, 1)
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen <- r.Proto
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("h3-ok"))
		}),
	}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(conn)
	}()
	defer func() {
		_ = server.Close()
		select {
		case err := <-serverErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("http3 server: %v", err)
			}
		case <-time.After(time.Second):
			t.Errorf("http3 server did not stop")
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(parsedCert)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runHTTP3CheckWithTLSConfig(ctx, "https://"+conn.LocalAddr().String()+"/real", map[string]any{
		"expected_status":      http.StatusAccepted,
		"expect_body_contains": "h3-ok",
	}, &tls.Config{
		RootCAs:    roots,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("runHTTP3CheckWithTLSConfig: %v result=%+v", err, result)
	}
	if result["http3_used"] != true || result["http3_ready"] != true {
		t.Fatalf("http3 flags not set: %+v", result)
	}
	if result["status_code"] != http.StatusAccepted || result["http3_status_code"] != http.StatusAccepted {
		t.Fatalf("unexpected status result: %+v", result)
	}
	if result["negotiated_proto"] != http3.NextProtoH3 || !strings.HasPrefix(fmt.Sprint(result["http_version"]), "HTTP/3") {
		t.Fatalf("unexpected protocol result: %+v", result)
	}
	select {
	case proto := <-seen:
		if !strings.HasPrefix(proto, "HTTP/3") {
			t.Fatalf("server saw proto %q", proto)
		}
	default:
		t.Fatalf("server did not receive HTTP/3 request")
	}
}

func TestRunMTRFallsBackWhenJSONOptionUnsupported(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
for arg in "$@"; do
  if [ "$arg" = "-j" ]; then
    echo "/usr/sbin/mtr: invalid option -- 'j'" >&2
    exit 1
  fi
done
cat <<'OUT'
Start: 2026-06-24T12:00:00+0800
HOST: test-node                 Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 192.0.2.1                0.0%     5    1.2   1.5   1.1   2.0   0.3
  2.|-- ???                    100.0%     5    0.0   0.0   0.0   0.0   0.0
  3.|-- 93.184.216.34            0.0%     5   11.0  12.5  10.8  14.0   1.1
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := runMTR(context.Background(), "example.com", map[string]any{"report_cycles": 5, "max_hops": 8})
	if err != nil {
		t.Fatalf("runMTR: %v result=%+v", err, result)
	}
	hops, ok := result["hops"].([]map[string]any)
	if !ok || len(hops) != 3 {
		t.Fatalf("hops = %#v", result["hops"])
	}
	if hops[0]["ip"] != "192.0.2.1" || hops[0]["loss_percent"] != 0.0 || hops[0]["avg_ms"] != 1.5 {
		t.Fatalf("first hop not parsed: %+v", hops[0])
	}
	if hops[1]["timeout"] != true || hops[1]["loss_percent"] != 100.0 {
		t.Fatalf("timeout hop not parsed: %+v", hops[1])
	}
	if hops[2]["ip"] != "93.184.216.34" || hops[2]["avg_ms"] != 12.5 {
		t.Fatalf("last hop not parsed: %+v", hops[2])
	}
	if result["hop_count"] != 3 || result["protocol"] != "icmp" || result["report_cycles"] != 5 {
		t.Fatalf("unexpected mtr metadata: %+v", result)
	}
}

func TestRunNodeStatus(t *testing.T) {
	result, err := runNodeStatus()
	if err != nil {
		t.Fatalf("runNodeStatus: %v", err)
	}
	if result["cpu_count"] == nil || result["goos"] == "" {
		t.Fatalf("unexpected node status: %+v", result)
	}
}

func mustSelfSignedHTTP3Cert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert, parsed
}
