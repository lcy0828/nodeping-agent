package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestDoctorConfigReportsMissingRequiredValues(t *testing.T) {
	check := checkConfig(config{})
	if check.Status != "fail" || !strings.Contains(check.Message, "NODEPING_SERVER_URL") || !strings.Contains(check.Message, "NODEPING_TOKEN") {
		t.Fatalf("checkConfig missing values = %+v", check)
	}
}

func TestDoctorAgentTokenFileWritable(t *testing.T) {
	check := checkAgentTokenFile(config{AgentTokenFile: filepath.Join(t.TempDir(), "agent-token")})
	if check.Status != "ok" {
		t.Fatalf("checkAgentTokenFile = %+v", check)
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
	_ = err
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

func TestRunHTTPRequestAssertionsAndTimings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		_, _ = w.Write([]byte("nodeping-ok"))
	}))
	defer server.Close()

	latency, _, result, err := runHTTPRequest(context.Background(), http.MethodGet, server.URL, nil, "", map[string]any{
		"expected_status":      200,
		"expect_body_contains": "nodeping",
	})
	if err != nil {
		t.Fatalf("runHTTPRequest: %v", err)
	}
	if latency <= 0 || result["status_code"] != 200 || result["http3_advertised"] != true {
		t.Fatalf("unexpected http result latency=%v result=%+v", latency, result)
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
