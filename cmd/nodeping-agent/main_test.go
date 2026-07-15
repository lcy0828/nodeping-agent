package main

import (
	"bytes"
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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func trustedPrivateTaskOptions(values map[string]any) map[string]any {
	out := map[string]any{
		"allow_private_targets": true,
		"health_check":          true,
		"health_check_kind":     "service_http",
	}
	for key, value := range values {
		out[key] = value
	}
	return out
}

func TestProbeTargetResolverRequiresTrustedHealthMarkersForPrivateTargets(t *testing.T) {
	resolver := newProbeTargetResolver(map[string]any{"allow_private_targets": true})
	if _, err := resolver.resolveHost(context.Background(), "127.0.0.1"); !errors.Is(err, errUnsafeProbeDestination) {
		t.Fatalf("single private marker error = %v, want unsafe destination", err)
	}

	resolver = newProbeTargetResolver(trustedPrivateTaskOptions(nil))
	addr, err := resolver.resolveHost(context.Background(), "127.0.0.1")
	if err != nil || addr.String() != "127.0.0.1" {
		t.Fatalf("trusted private target addr=%v err=%v", addr, err)
	}
}

func TestProbeTargetResolverRejectsReservedAndOptionTargets(t *testing.T) {
	resolver := newProbeTargetResolver(nil)
	for _, target := range []string{"100.64.0.1", "192.0.2.1", "2001:db8::1", "-I"} {
		if _, err := resolver.resolveHost(context.Background(), target); err == nil {
			t.Fatalf("resolveHost(%q) succeeded, want rejection", target)
		}
	}
	if _, err := resolver.resolveHostPort(context.Background(), "-connect:443"); err == nil {
		t.Fatal("option-like host:port target succeeded")
	}
	if _, err := resolver.resolveHostPort(context.Background(), "1.1.1.1:https"); err == nil {
		t.Fatal("named port target succeeded")
	}
}

func TestProbeTargetResolverPinsFirstPublicResolutionAndRejectsMixedAnswers(t *testing.T) {
	originalLookup := lookupProbeNetIP
	defer func() { lookupProbeNetIP = originalLookup }()

	calls := 0
	lookupProbeNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	resolver := newProbeTargetResolver(nil)
	first, err := resolver.resolveHost(context.Background(), "probe.example")
	if err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	second, err := resolver.resolveHost(context.Background(), "probe.example")
	if err != nil || second != first || calls != 1 {
		t.Fatalf("pinned resolution first=%v second=%v calls=%d err=%v", first, second, calls, err)
	}

	lookupProbeNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err := newProbeTargetResolver(nil).resolveHost(context.Background(), "mixed.example"); !errors.Is(err, errUnsafeProbeDestination) {
		t.Fatalf("mixed resolution error = %v, want unsafe destination", err)
	}
}

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
	err := readSSETasks(context.Background(), strings.NewReader(stream), time.Second, func(task taskRequest) {
		got = task
	})
	if err != nil {
		t.Fatalf("readSSETasks returned error: %v", err)
	}
	if got.ID != "task-large" {
		t.Fatalf("task id = %q", got.ID)
	}
}

func TestReadSSETasksIgnoresKeepaliveComments(t *testing.T) {
	stream := ": connected\n\n: keepalive\n\nevent: task\ndata: {\"task_id\":\"task-1\",\"agent_id\":\"agent-a\",\"task_type\":\"ping\",\"payload\":{\"ping\":\"1.1.1.1\"}}\n\n"
	var got taskRequest
	err := readSSETasks(context.Background(), strings.NewReader(stream), time.Second, func(task taskRequest) {
		got = task
	})
	if err != nil {
		t.Fatalf("readSSETasks returned error: %v", err)
	}
	if got.ID != "task-1" {
		t.Fatalf("task id = %q", got.ID)
	}
}

func TestReadSSETasksDecodesCancellationControl(t *testing.T) {
	stream := "event: task\ndata: {\"task_id\":\"task-1\",\"operation\":\"cancel\",\"cancel_task_id\":\"task-1\"}\n\n"
	var got taskRequest
	if err := readSSETasks(context.Background(), strings.NewReader(stream), time.Second, func(task taskRequest) {
		got = task
	}); err != nil {
		t.Fatalf("readSSETasks returned error: %v", err)
	}
	if got.Operation != "cancel" || got.CancelTaskID != "task-1" {
		t.Fatalf("cancellation control = %+v", got)
	}
}

func TestReadSSETasksReturnsIdleTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	err := readSSETasks(context.Background(), pr, 20*time.Millisecond, func(task taskRequest) {
		t.Fatalf("unexpected task: %+v", task)
	})
	if err == nil || !strings.Contains(err.Error(), "task stream idle") {
		t.Fatalf("readSSETasks error = %v, want idle timeout", err)
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

func TestTaskStreamReconnectDelayIsJitteredWithinConfiguredMaximum(t *testing.T) {
	base := 10 * time.Second
	for range 100 {
		got := taskStreamReconnectDelay(base)
		if got < 8*time.Second || got > base {
			t.Fatalf("reconnect delay=%s, want within [8s, 10s]", got)
		}
	}
	if got := taskStreamReconnectDelay(0); got != 0 {
		t.Fatalf("zero reconnect delay=%s, want zero", got)
	}
}

func TestConsumeTaskStreamReportsWhetherConnectionWasEstablished(t *testing.T) {
	streamClosed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		if flusher, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(": connected\n\n"))
			flusher.Flush()
		}
	}))
	defer streamClosed.Close()

	connected, err := consumeTaskStream(context.Background(), config{
		ServerURL:         streamClosed.URL,
		AgentID:           "agent-a",
		AgentToken:        "agent-token",
		StreamIdleTimeout: time.Second,
		StreamRetryMin:    time.Millisecond,
		StreamRetryMax:    time.Millisecond,
		Concurrency:       1,
		HTTPClient:        streamClosed.Client(),
	}, newTaskConcurrencyLimiter(1), newAgentTaskExecutor(context.Background(), config{}))
	if !connected || err == nil || !strings.Contains(err.Error(), "task stream closed") {
		t.Fatalf("consumeTaskStream connected=%v err=%v, want connected closed stream", connected, err)
	}

	statusFailed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
	}))
	defer statusFailed.Close()
	connected, err = consumeTaskStream(context.Background(), config{
		ServerURL:         statusFailed.URL,
		AgentID:           "agent-a",
		AgentToken:        "agent-token",
		StreamIdleTimeout: time.Second,
		StreamRetryMin:    time.Millisecond,
		StreamRetryMax:    time.Millisecond,
		Concurrency:       1,
		HTTPClient:        statusFailed.Client(),
	}, newTaskConcurrencyLimiter(1), newAgentTaskExecutor(context.Background(), config{}))
	if connected || err == nil || !strings.Contains(err.Error(), "stream status 503") {
		t.Fatalf("consumeTaskStream connected=%v err=%v, want pre-connect status error", connected, err)
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

func TestDefaultAgentIDGeneratesOpaqueStableValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	if got := readAgentIDFile(path); got != "" {
		t.Fatalf("empty agent id file read = %q", got)
	}
	id := randomLocalAgentID()
	uuidAgentIDPattern := regexp.MustCompile(`^agent-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidAgentIDPattern.MatchString(id) {
		t.Fatalf("randomLocalAgentID()=%q, want agent UUID v4 format", id)
	}
	if strings.Contains(strings.ToLower(id), strings.ToLower(hostname())) {
		t.Fatalf("randomLocalAgentID() should not include hostname: %q", id)
	}
	if err := writeAgentIDFile(path, id); err != nil {
		t.Fatalf("writeAgentIDFile: %v", err)
	}
	if got := readAgentIDFile(path); got != id {
		t.Fatalf("readAgentIDFile()=%q, want %q", got, id)
	}
}

func TestResolveAgentIDMigratesLegacyConfiguredIDWhenAgentTokenExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	got := resolveAgentIDForConfig("ops", "npa_existing", path)
	if !agentIDIsUUIDV4(got) {
		t.Fatalf("resolveAgentIDForConfig()=%q, want agent UUID v4 format", got)
	}
	if got == "ops" {
		t.Fatalf("legacy configured id should not be reused when agent token exists")
	}
	if stored := readAgentIDFile(path); stored != "" {
		t.Fatalf("migration candidate should not be persisted before register succeeds, stored=%q", stored)
	}
}

func TestResolveAgentIDPrefersStoredUUIDOverLegacyConfiguredID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	stored := "agent-12345678-1234-4123-9123-123456789abc"
	if err := writeAgentIDFile(path, stored); err != nil {
		t.Fatalf("writeAgentIDFile: %v", err)
	}
	if got := resolveAgentIDForConfig("ops", "npa_existing", path); got != stored {
		t.Fatalf("resolveAgentIDForConfig()=%q, want stored uuid %q", got, stored)
	}
}

func TestResolveAgentIDKeepsLegacyConfiguredIDWithoutAgentToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	if got := resolveAgentIDForConfig("ops", "", path); got != "ops" {
		t.Fatalf("resolveAgentIDForConfig()=%q, want legacy configured id before first token", got)
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
		_, _ = w.Write([]byte(`{"ok":true,"agent_id":"agent-test","agent_token":"agent-token","latest_version":"v1.2.3","server_time":"2026-06-23T00:00:00Z"}`))
	}))
	defer server.Close()

	resp, err := registerAgent(context.Background(), config{
		ServerURL:   server.URL,
		Token:       "binding-token",
		AgentID:     "agent-test",
		Name:        "agent-test",
		Version:     "nodeping-agent/test",
		Concurrency: 7,
		HTTPClient:  server.Client(),
	})
	if err != nil {
		t.Fatalf("registerAgent: %v", err)
	}
	if resp.AgentID != "agent-test" || resp.AgentToken != "agent-token" {
		t.Fatalf("register response = %+v", resp)
	}
	if resp.LatestVersion != "v1.2.3" {
		t.Fatalf("latest version = %q, want v1.2.3", resp.LatestVersion)
	}
	if payload["server_url"] != server.URL {
		t.Fatalf("server_url = %#v, want %q; payload=%+v", payload["server_url"], server.URL, payload)
	}
	if caps, ok := payload["capabilities"].([]any); !ok || len(caps) == 0 {
		t.Fatalf("capabilities missing from register payload: %+v", payload)
	}
	if payload["concurrency"] != float64(7) {
		t.Fatalf("concurrency = %#v, want 7; payload=%+v", payload["concurrency"], payload)
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

func TestNormalizeAgentTaskConcurrency(t *testing.T) {
	tests := []struct {
		name  string
		value int
		want  int
	}{
		{name: "legacy default", value: 3, want: 10},
		{name: "backend execution pool default", value: 10, want: 10},
		{name: "larger local ceiling", value: 20, want: 20},
		{name: "invalid high value", value: 1001, want: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAgentTaskConcurrency(tt.value); got != tt.want {
				t.Fatalf("normalizeAgentTaskConcurrency(%d) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestTaskConcurrencyLimiterFollowsServerLimit(t *testing.T) {
	limiter := newTaskConcurrencyLimiter(10)
	limiter.SetLimit(1)
	if got := limiter.Limit(); got != 1 {
		t.Fatalf("limit = %d, want 1", got)
	}
	if !limiter.Acquire(context.Background()) {
		t.Fatal("first acquire failed")
	}

	acquired := make(chan bool, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		acquired <- limiter.Acquire(ctx)
	}()
	select {
	case <-acquired:
		t.Fatal("second acquire should wait at limit 1")
	case <-time.After(20 * time.Millisecond):
	}

	limiter.SetLimit(2)
	select {
	case ok := <-acquired:
		if !ok {
			t.Fatal("second acquire failed after increasing limit")
		}
	case <-time.After(time.Second):
		t.Fatal("second acquire did not resume after increasing limit")
	}
	limiter.Release()
	limiter.Release()
}

func TestAgentTaskExecutorCancelsRunningTask(t *testing.T) {
	executor := newAgentTaskExecutor(context.Background(), config{})
	started := make(chan struct{})
	stopped := make(chan error, 1)
	executor.run = func(ctx context.Context, _ config, _ taskRequest) {
		close(started)
		<-ctx.Done()
		stopped <- ctx.Err()
	}
	if !executor.Start(taskRequest{ID: "cancel-me"}, nil) {
		t.Fatal("task did not start")
	}
	<-started
	executor.CancelTask("cancel-me")
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("task stopped with %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("running task did not stop after cancellation")
	}
	if !executor.Wait(time.Second) {
		t.Fatal("executor did not drain cancelled task")
	}
}

func TestAgentTaskExecutorBoundsUnknownCancellationTombstones(t *testing.T) {
	executor := newAgentTaskExecutor(context.Background(), config{})
	executor.mu.Lock()
	executor.cancelled["expired"] = time.Now().Add(-cancelledTaskTTL)
	for index := 0; index <= maxCancelledTasks; index++ {
		executor.cancelled[fmt.Sprintf("task-%d", index)] = time.Now().Add(time.Duration(index) * time.Nanosecond)
	}
	executor.cleanupCancelledLocked(time.Now())
	executor.trimCancelledLocked()
	_, expiredPresent := executor.cancelled["expired"]
	count := len(executor.cancelled)
	executor.mu.Unlock()
	if expiredPresent {
		t.Fatal("expired cancellation tombstone was retained")
	}
	if count > maxCancelledTasks {
		t.Fatalf("cancellation tombstones = %d, max %d", count, maxCancelledTasks)
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

func TestExecuteTaskAgentDependencyFixRejectsUnknownDependency(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"dependency": "curl"})
	result := executeTask(context.Background(), config{}, taskRequest{
		ID:       "dependency-fix-unknown",
		TaskType: "agent_dependency_fix",
		Payload:  payload,
	})
	if result.Success || result.ErrorCode != "TASK_FAILED" {
		t.Fatalf("dependency fix should fail for unknown dependency: %+v", result)
	}
	if !strings.Contains(result.ErrorMessage, "unsupported dependency") {
		t.Fatalf("unexpected error message: %+v", result)
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
	got, err := runTLSCheck(context.Background(), map[string]any{"host": parsed.Host, "server_name": "example.com"}, trustedPrivateTaskOptions(nil))
	if err == nil {
		t.Fatalf("expected hostname verification failure for self-signed test cert, got result %+v", got)
	}
}

func TestTLSCheckPayloadInheritsTopLevelFallbacks(t *testing.T) {
	payload := tlsCheckPayload(map[string]any{
		"tls_check": map[string]any{
			"server_name": "origin.example.com",
		},
		"host":   "203.0.113.10:443",
		"target": "203.0.113.10:443",
	})

	if payload["host"] != "203.0.113.10:443" || payload["target"] != "203.0.113.10:443" || payload["server_name"] != "origin.example.com" {
		t.Fatalf("tls payload = %+v", payload)
	}
	if got := tlsTargetSummary(payload); got != "203.0.113.10:443" {
		t.Fatalf("tls target summary = %q", got)
	}
}

func TestTLSCheckPayloadUsesHostAsTarget(t *testing.T) {
	payload := tlsCheckPayload(map[string]any{
		"tls_check": map[string]any{
			"host": "example.com:443",
		},
	})

	if payload["host"] != "example.com:443" || payload["target"] != "example.com:443" {
		t.Fatalf("tls payload = %+v", payload)
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
	if _, exists := events[1].Extra["samples"]; exists {
		t.Fatalf("progress event repeated full sample history: %+v", events[1].Extra)
	}
	latest, ok := events[1].Extra["latest_sample"].(map[string]any)
	if !ok || latest["seq"] != float64(2) || latest["latency_ms"] != float64(9) {
		t.Fatalf("latest sample = %#v", events[1].Extra["latest_sample"])
	}
}

func TestLongProbeProgressEmitterDoesNotBlockOnSlowServer(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-releaseRequest
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	emitter := newLongProbeProgressEmitter(context.Background(), config{
		ServerURL:  server.URL,
		AgentToken: "agent-token",
		HTTPClient: server.Client(),
	}, taskRequest{ID: "slow-task"}, "long_ping")
	emitter.Emit(map[string]any{"sample_count": 100, "completed_count": 1})
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("progress request did not start")
	}

	started := time.Now()
	for seq := 2; seq <= 1000; seq++ {
		emitter.Emit(map[string]any{"sample_count": 1000, "completed_count": seq})
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("coalesced Emit calls blocked for %s", elapsed)
	}

	close(releaseRequest)
	emitter.Close()
	server.Close()

	// Close is idempotent and later progress is ignored instead of panicking.
	emitter.Close()
	emitter.Emit(map[string]any{"sample_count": 1000, "completed_count": 1000})
}

func TestMTRProgressReporterPostsEachReport(t *testing.T) {
	var events []taskEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/tasks/task-mtr/events" {
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

	report := mtrProgressReporter(context.Background(), config{
		ServerURL:  server.URL,
		AgentToken: "agent-token",
		HTTPClient: server.Client(),
	}, taskRequest{ID: "task-mtr"})
	report(map[string]any{"report_cycles": 5, "completed_count": 1, "hop_count": 2, "hops": []map[string]any{{"hop": 1, "ip": "192.0.2.1"}}})
	report(map[string]any{"report_cycles": 5, "completed_count": 2, "hop_count": 2, "hops": []map[string]any{{"hop": 1, "ip": "192.0.2.1"}}})

	if len(events) != 2 {
		t.Fatalf("posted events = %d, want 2", len(events))
	}
	if events[0].Progress != 20 || events[1].Progress != 40 {
		t.Fatalf("unexpected progress values: %+v", events)
	}
	if events[1].Extra["event_kind"] != "mtr_report" || events[1].Extra["task_type"] != "mtr" || events[1].Extra["live_running"] != true {
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

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), trustedPrivateTaskOptions(map[string]any{"payload": "hello", "wait_response": true, "read_timeout_ms": 1000}))
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

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), trustedPrivateTaskOptions(map[string]any{"payload": "hello", "wait_response": true, "read_timeout_ms": 200}))
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

	result, err := runUDPProbe(context.Background(), conn.LocalAddr().String(), trustedPrivateTaskOptions(map[string]any{"payload_mode": "dns_query", "dns_query_domain": "example.com", "wait_response": false}))
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

	latency, responseIP, result, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", trustedPrivateTaskOptions(map[string]any{
		"expected_status":      200,
		"expect_body_contains": "nodeping",
	}))
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if latency <= 0 || result["status_code"] != 200 || result["http3_advertised"] != true {
		t.Fatalf("unexpected http result latency=%v result=%+v", latency, result)
	}
	if _, exists := result["body"]; exists {
		t.Fatalf("HTTP response body must not be returned: %+v", result)
	}
	serverIP := hostLiteralIP(server.Listener.Addr().String())
	if responseIP != serverIP || result["response_ip"] != serverIP {
		t.Fatalf("response IP = %q result=%+v, want %q", responseIP, result, serverIP)
	}
}

func TestRunHTTPRequestReportsTruncationWithoutReturningBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nodeping-body"))
	}))
	defer server.Close()

	_, _, result, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", trustedPrivateTaskOptions(map[string]any{
		"max_body_bytes": 4,
	}))
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if result["body_truncated"] != true || result["body_bytes"] != 4 {
		t.Fatalf("unexpected truncated body result: %+v", result)
	}
	if _, exists := result["body"]; exists {
		t.Fatalf("truncated HTTP response body must not be returned: %+v", result)
	}
}

func TestRunHTTPRequestUsesOriginalHostHeader(t *testing.T) {
	seenHost := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, _, _, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", trustedPrivateTaskOptions(map[string]any{
		"original_host": "origin.example.com",
	}))
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
		Options:  trustedPrivateTaskOptions(nil),
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
		Options:  trustedPrivateTaskOptions(nil),
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
		Options:  trustedPrivateTaskOptions(map[string]any{"expected_status": 200}),
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
	result, err := runHTTP3CheckWithTLSConfig(ctx, "https://"+conn.LocalAddr().String()+"/real", trustedPrivateTaskOptions(map[string]any{
		"expected_status":      http.StatusAccepted,
		"expect_body_contains": "h3-ok",
	}), &tls.Config{
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

	result, err := runMTR(context.Background(), "93.184.216.34", map[string]any{"report_cycles": 5, "max_hops": 8})
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

func TestRunMTRRawStreamsCyclesAndPreservesMultipath(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
cat <<'OUT'
x 0 1
h 0 192.0.2.1
p 0 1000 1
x 1 2
h 1 203.0.113.9
p 1 10000 2
x 0 3
h 0 192.0.2.2
p 0 3000 3
x 1 4
h 1 203.0.113.9
p 1 12000 4
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	var reports []map[string]any
	result, _, err := runMTRRaw(context.Background(), &mtrRunConfig{
		Target:       "203.0.113.9",
		Path:         mtrPath,
		ReportCycles: 2,
		MaxHops:      8,
		Protocol:     "icmp",
	}, func(summary map[string]any) {
		reports = append(reports, summary)
	})
	if err != nil {
		t.Fatalf("runMTRRaw: %v", err)
	}
	if result["stream_mode"] != "raw" || result["completed_count"] != 2 || result["reached"] != true {
		t.Fatalf("unexpected raw result: %+v", result)
	}
	hops := mtrHops(result)
	if len(hops) != 2 {
		t.Fatalf("hops = %+v", hops)
	}
	first := hops[0]
	if first["multipath"] != true || first["path_count"] != 2 || first["sent"] != 2 || first["avg_ms"] != 2.0 {
		t.Fatalf("multipath hop = %+v", first)
	}
	paths, ok := first["paths"].([]map[string]any)
	if !ok || len(paths) != 2 || paths[0]["ip"] == paths[1]["ip"] {
		t.Fatalf("paths = %#v", first["paths"])
	}
	if len(reports) != 2 || reports[0]["completed_count"] != 1 || reports[1]["completed_count"] != 2 {
		t.Fatalf("reports = %+v", reports)
	}
}

func TestNewMTRRunConfigDefaultsAndClampsToOneHundredSamples(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	if err := os.WriteFile(mtrPath, []byte("#!/usr/bin/env sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg, err := newMTRRunConfig(context.Background(), "192.0.2.1", trustedPrivateTaskOptions(nil))
	if err != nil {
		t.Fatalf("newMTRRunConfig default: %v", err)
	}
	if cfg.ReportCycles != 100 {
		t.Fatalf("default report cycles = %d, want 100", cfg.ReportCycles)
	}
	cfg, err = newMTRRunConfig(context.Background(), "192.0.2.1", trustedPrivateTaskOptions(map[string]any{"report_cycles": 1000}))
	if err != nil {
		t.Fatalf("newMTRRunConfig clamp: %v", err)
	}
	if cfg.ReportCycles != 100 {
		t.Fatalf("clamped report cycles = %d, want 100", cfg.ReportCycles)
	}
}

func TestMTRDiagnosticOutputIsBounded(t *testing.T) {
	var output bytes.Buffer
	appendMTRDiagnosticString(&output, strings.Repeat("x", maxMTRRawDiagnosticBytes+1024))
	appendMTRDiagnosticBytes(&output, []byte("more"))
	if output.Len() != maxMTRRawDiagnosticBytes {
		t.Fatalf("diagnostic output length = %d, want %d", output.Len(), maxMTRRawDiagnosticBytes)
	}
}

func TestRunMTRRawKeepsLostFirstHopAsCompletedSamples(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
cat <<'OUT'
x 0 1
x 1 2
h 1 203.0.113.9
p 1 10000 2
x 0 3
x 1 4
p 1 12000 4
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	result, _, err := runMTRRaw(context.Background(), &mtrRunConfig{
		Target:       "203.0.113.9",
		Path:         mtrPath,
		ReportCycles: 2,
		MaxHops:      8,
		Protocol:     "icmp",
	}, nil)
	if err != nil {
		t.Fatalf("runMTRRaw: %v", err)
	}
	hops := mtrHops(result)
	if len(hops) != 2 || result["completed_count"] != 2 || result["reached"] != true {
		t.Fatalf("unexpected result: %+v", result)
	}
	if hops[0]["sent"] != 2 || hops[0]["loss_percent"] != 100.0 || hops[0]["timeout"] != true {
		t.Fatalf("lost first hop = %+v", hops[0])
	}
}

func TestRunMTRRawDeduplicatesSequenceEvents(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
cat <<'OUT'
x 0 1
x 0 1
h 0 192.0.2.1
p 0 1000 1
p 0 9000 1
x 0 2
p 0 2000 2
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	var reports []map[string]any
	result, _, err := runMTRRaw(context.Background(), &mtrRunConfig{
		Target:       "192.0.2.1",
		Path:         mtrPath,
		ReportCycles: 2,
		MaxHops:      8,
		Protocol:     "icmp",
	}, func(summary map[string]any) {
		reports = append(reports, summary)
	})
	if err != nil {
		t.Fatalf("runMTRRaw: %v", err)
	}
	hops := mtrHops(result)
	if len(hops) != 1 || hops[0]["sent"] != 2 || hops[0]["avg_ms"] != 1.5 || hops[0]["loss_percent"] != 0.0 {
		t.Fatalf("deduplicated hop = %+v", hops)
	}
	if len(reports) != 2 || mtrHops(reports[0])[0]["loss_percent"] != 0.0 {
		t.Fatalf("duplicate transmit emitted an incomplete report: %+v", reports)
	}
}

func TestRunMTRRawReturnsPartialResultOnTimeout(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
cat <<'OUT'
x 0 1
h 0 192.0.2.1
p 0 1000 1
OUT
exec sleep 5
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, _, err := runMTRRaw(ctx, &mtrRunConfig{
		Target:       "192.0.2.1",
		Path:         mtrPath,
		ReportCycles: 5,
		MaxHops:      8,
		Protocol:     "icmp",
	}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("timeout took too long: %s", time.Since(started))
	}
	if result == nil || result["completed_count"] != 1 || result["stopped_early"] != true {
		t.Fatalf("partial result = %+v", result)
	}
}

func TestParseMTRRawEventSupportsReplySequenceSuffix(t *testing.T) {
	event, ok := parseMTRRawEvent("p 4 12500 77")
	if !ok || event.kind != 'p' || event.hop != 5 || event.latencyMS != 12.5 || !event.hasSequence || event.sequence != 77 {
		t.Fatalf("event = %+v ok=%v", event, ok)
	}
}

func TestRunMTRWithProgressFallsBackWhenRawModeIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
for arg in "$@"; do
  if [ "$arg" = "-l" ]; then
    echo "mtr: invalid option -- l" >&2
    exit 1
  fi
done
cat <<'OUT'
{"report":{"hubs":[{"count":1,"host":"192.0.2.1","Loss%":0,"Snt":2,"Last":1,"Avg":1.5,"Best":1,"Wrst":2,"StDev":0.5}]}}
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	result, err := runMTRWithProgress(context.Background(), config{}, taskRequest{
		ID:      "mtr-fallback",
		Options: trustedPrivateTaskOptions(map[string]any{"report_cycles": 2, "max_hops": 8}),
	}, "192.0.2.1")
	if err != nil {
		t.Fatalf("runMTRWithProgress: %v", err)
	}
	if result["stream_mode"] != "report_fallback" || result["completed_count"] != 2 {
		t.Fatalf("fallback result = %+v", result)
	}
}

func TestRunMTRFallsBackWhenJSONOptionPrintsWithZeroExit(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
for arg in "$@"; do
  if [ "$arg" = "-j" ]; then
    echo "/usr/sbin/mtr: invalid option -- 'j'"
    exit 0
  fi
done
cat <<'OUT'
Start: 2026-06-24T12:00:00+0800
HOST: test-node                 Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 192.0.2.1                0.0%     5    1.2   1.5   1.1   2.0   0.3
OUT
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := runMTR(context.Background(), "93.184.216.34", map[string]any{"report_cycles": 5, "max_hops": 8})
	if err != nil {
		t.Fatalf("runMTR: %v result=%+v", err, result)
	}
	hops, ok := result["hops"].([]map[string]any)
	if !ok || len(hops) != 1 {
		t.Fatalf("hops = %#v", result["hops"])
	}
	if hops[0]["ip"] != "192.0.2.1" || hops[0]["avg_ms"] != 1.5 {
		t.Fatalf("first hop not parsed: %+v", hops[0])
	}
}

func TestMTRSupportsJSONRejectsTextOutputWithZeroExit(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
if [ "$1" = "--version" ]; then
  echo "mtr 0.85"
  exit 0
fi
for arg in "$@"; do
  if [ "$arg" = "-j" ]; then
    echo "/usr/sbin/mtr: invalid option -- 'j'"
    exit 0
  fi
done
echo "unexpected"
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if mtrSupportsJSON(context.Background(), mtrPath) {
		t.Fatalf("mtrSupportsJSON should reject non-JSON output from %s", mtrPath)
	}
	check := checkMTRCommand(context.Background())
	if check.Status != "warn" || !strings.Contains(check.Message, "text fallback") {
		t.Fatalf("checkMTRCommand status = %+v, want text fallback warning", check)
	}
}

func TestCheckMTRCommandUsesShortGracePeriod(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
if [ "$1" = "--version" ]; then
  echo "mtr 0.96"
  exit 0
fi
if [ "$1" = "--help" ]; then
  echo "-j, --json output json"
  echo "-G, --gracetime SECONDS wait for responses"
  exit 0
fi
has_json=
has_grace=
for arg in "$@"; do
  [ "$arg" = "-j" ] && has_json=1
  [ "$arg" = "-G" ] && has_grace=1
done
if [ -z "$has_json" ] || [ -z "$has_grace" ]; then
  echo "missing short JSON probe options" >&2
  exit 1
fi
echo '{"report":{"hubs":[]}}'
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	check := checkMTRCommand(context.Background())
	if check.Status != "ok" || check.Version != "mtr 0.96" {
		t.Fatalf("checkMTRCommand = %+v, want working JSON probe", check)
	}
}

func TestCheckMTRCommandReportsRuntimeFailureSeparately(t *testing.T) {
	dir := t.TempDir()
	mtrPath := filepath.Join(dir, "mtr")
	script := `#!/usr/bin/env sh
if [ "$1" = "--version" ]; then
  echo "mtr 0.96"
  exit 0
fi
if [ "$1" = "--help" ]; then
  echo "-j, --json output json"
  echo "-G, --gracetime SECONDS wait for responses"
  exit 0
fi
echo "mtr-packet: Failure to open IPv4 sockets: Operation not permitted" >&2
exit 1
`
	if err := os.WriteFile(mtrPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mtr: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if mtrSupportsJSON(context.Background(), mtrPath) {
		t.Fatal("mtrSupportsJSON should reject a runtime permission failure")
	}
	check := checkMTRCommand(context.Background())
	if check.Status != "fail" || !strings.Contains(check.Message, "runtime check failed") || strings.Contains(check.Message, "does not support") {
		t.Fatalf("checkMTRCommand = %+v, want runtime failure", check)
	}
	if !strings.Contains(check.Remediation, "NET_RAW") {
		t.Fatalf("remediation = %q, want packet permission guidance", check.Remediation)
	}
}

func TestInstallHintsIncludeYumFallback(t *testing.T) {
	for _, binary := range []string{"ping", "traceroute", "mtr"} {
		hint := installHint(binary)
		if !strings.Contains(hint, "dnf install") || !strings.Contains(hint, "yum install") {
			t.Fatalf("install hint for %s should include dnf and yum commands: %q", binary, hint)
		}
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
