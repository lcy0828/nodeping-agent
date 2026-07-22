package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxPublishedIPSourceResponseBodyBytes = 64 << 10

type httpResponsePolicy struct {
	publishIPSourceResponseBody bool
	allowHTTPSDowngrade         bool
}

func runHTTPPing(ctx context.Context, target string, options map[string]any) (float64, string, error) {
	latency, responseIP, _, err := runHTTPRequestWithResponsePolicy(ctx, http.MethodGet, target, nil, "", options, newProbeTargetResolver(options), httpResponsePolicy{
		allowHTTPSDowngrade: true,
	})
	return latency, responseIP, err
}

func runHTTPRequest(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any) (float64, string, map[string]any, error) {
	return runHTTPRequestForTask(ctx, method, target, headers, body, options, false)
}

func runHTTPRequestWithResolver(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any, resolver *probeTargetResolver) (float64, string, map[string]any, error) {
	return runHTTPRequestWithResponsePolicy(ctx, method, target, headers, body, options, resolver, httpResponsePolicy{})
}

func runHTTPRequestForTask(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any, publishIPSourceResponseBody bool) (float64, string, map[string]any, error) {
	return runHTTPRequestWithResponsePolicy(ctx, method, target, headers, body, options, newProbeTargetResolver(options), httpResponsePolicy{
		publishIPSourceResponseBody: publishIPSourceResponseBody,
	})
}

func runHTTPRequestWithResponsePolicy(ctx context.Context, method string, target string, headers map[string]string, body string, options map[string]any, resolver *probeTargetResolver, responsePolicy httpResponsePolicy) (float64, string, map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	target = strings.TrimSpace(target)
	parsedTarget, err := validateHTTPProbeURL(target, false)
	if err != nil {
		return 0, "", nil, err
	}
	if resolver == nil {
		resolver = newProbeTargetResolver(options)
	}
	originalHost := originalHostOption(options)
	if originalHost != "" {
		parsedTarget, err = composeHTTPProbeTarget(ctx, parsedTarget, originalHost, resolver)
		if err != nil {
			return 0, "", nil, err
		}
	}
	trace := &httpTimingTrace{}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace.clientTrace()), method, parsedTarget.String(), strings.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	if originalHost != "" {
		req.Host = originalHost
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	transport := safeHTTPTransportWithResolver("", resolver)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   deadlineTimeout(ctx, 10*time.Second),
		Transport: transport,
		CheckRedirect: safeHTTPRedirectPolicy(httpRedirectPolicy{
			allowPrivate:        resolver.allowPrivate,
			allowHTTPSDowngrade: responsePolicy.allowHTTPSDowngrade,
		}),
	}
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
	if responsePolicy.publishIPSourceResponseBody && maxBodyBytes > maxPublishedIPSourceResponseBodyBytes {
		maxBodyBytes = maxPublishedIPSourceResponseBodyBytes
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
	bodyForResult := readBody
	if len(bodyForResult) > maxBodyBytes {
		bodyForResult = bodyForResult[:maxBodyBytes]
	}
	if responsePolicy.publishIPSourceResponseBody && len(bodyForResult) > 0 {
		result["body"] = string(bodyForResult)
	}
	if boolOptionDefault(options, "extract_public_ips", false) {
		if publicIPs := extractPublicIPsFromHTTPBody(readBody); len(publicIPs) > 0 {
			result["public_ips"] = publicIPs
		}
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

func composeHTTPProbeTarget(ctx context.Context, target *url.URL, originalHost string, resolver *probeTargetResolver) (*url.URL, error) {
	if target == nil {
		return nil, errors.New("HTTP target URL is invalid")
	}
	if resolver == nil {
		return nil, errors.New("HTTP target resolver is required")
	}
	host, err := validateProbeHost(strings.Trim(originalHost, "[]"))
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSuffix(target.Hostname(), "."), strings.TrimSuffix(host, ".")) {
		return target, nil
	}
	connectIP, err := resolver.resolveHost(ctx, target.Hostname())
	if err != nil {
		return nil, err
	}
	if err := resolver.pinHost(host, connectIP); err != nil {
		return nil, err
	}

	composed := *target
	composed.Host = host
	if port := target.Port(); port != "" {
		composed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		composed.Host = "[" + host + "]"
	}
	return &composed, nil
}

func extractPublicIPsFromHTTPBody(body []byte) []string {
	const maxExtractedPublicIPs = 8
	var result []string
	for _, field := range strings.FieldsFunc(string(body), func(r rune) bool {
		return !(r == ':' || r == '.' || r == '%' || r == '[' || r == ']' ||
			(r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F'))
	}) {
		candidate := strings.Trim(strings.TrimSpace(field), "[]")
		if zoneIndex := strings.LastIndex(candidate, "%"); zoneIndex > 0 {
			candidate = candidate[:zoneIndex]
		}
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !isPublicProbeAddr(addr) {
			continue
		}
		ipText := addr.String()
		seen := false
		for _, existing := range result {
			if existing == ipText {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		result = append(result, ipText)
		if len(result) >= maxExtractedPublicIPs {
			break
		}
	}
	return result
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
