package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

func runHTTPPing(ctx context.Context, target string, options map[string]any) (float64, string, error) {
	latency, responseIP, _, err := runHTTPRequest(ctx, http.MethodGet, target, nil, "", options)
	return latency, responseIP, err
}

func runHTTPRequest(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any) (float64, string, map[string]any, error) {
	return runHTTPRequestWithResolver(ctx, method, target, headers, body, options, newProbeTargetResolver(options))
}

func runHTTPRequestWithResolver(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any, resolver *probeTargetResolver) (float64, string, map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	target = strings.TrimSpace(target)
	if _, err := validateHTTPProbeURL(target, false); err != nil {
		return 0, "", nil, err
	}
	trace := &httpTimingTrace{}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace.clientTrace()), method, target, strings.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	originalHost := originalHostOption(options)
	if originalHost != "" {
		req.Host = originalHost
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if resolver == nil {
		resolver = newProbeTargetResolver(options)
	}
	transport := safeHTTPTransportWithResolver(originalHost, resolver)
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: deadlineTimeout(ctx, 10*time.Second), Transport: transport, CheckRedirect: safeHTTPRedirectPolicy(resolver.allowPrivate)}
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
	responseIP := trace.responseIP
	if responseIP == "" {
		responseIP = literalIP(resp.Request.URL.Hostname())
	}
	if responseIP == "" {
		parsed, err := url.Parse(target)
		if err == nil {
			responseIP = literalIP(parsed.Hostname())
		}
	}
	result := map[string]any{
		"status_code":  resp.StatusCode,
		"http_request": latency,
		"body_bytes":   len(readBody),
	}
	if responseIP != "" {
		result["response_ip"] = responseIP
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

func originalHostOption(options map[string]any) string {
	host := strings.Trim(strings.TrimSpace(firstNonEmptyStringAgent(
		stringOptionAny(options, "original_host"),
		stringOptionAny(options, "server_name"),
	)), "[]")
	if host == "" || strings.ContainsAny(host, " \t\r\n") {
		return ""
	}
	return host
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
	responseIP   string
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
		GotConn: func(info httptrace.GotConnInfo) {
			t.gotConn = time.Now()
			if ip := remoteAddrIP(info.Conn.RemoteAddr()); ip != "" {
				t.responseIP = ip
			}
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
