package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
	originalHost := originalHostOption(options)
	started := time.Now()
	httpsOptions := map[string]any{"max_body_bytes": 0}
	if originalHost != "" {
		httpsOptions["original_host"] = originalHost
	}
	_, _, httpsResponse, _ := runHTTPRequest(ctx, http.MethodGet, target, nil, "", httpsOptions)
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
	if originalHost != "" {
		headers["host"] = originalHost
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
	allowPrivate := allowPrivateHTTPDestinations(options)
	originalHost := originalHostOption(options)
	if originalHost != "" {
		req.Host = originalHost
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
	if originalHost != "" {
		tlsConfig.ServerName = originalHost
	}
	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: deadlineTimeout(ctx, 5*time.Second),
			MaxIdleTimeout:       deadlineTimeout(ctx, 10*time.Second),
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", strings.Trim(host, "[]"))
			if err != nil {
				return nil, err
			}
			if !allowPrivate {
				for _, ip := range ips {
					if !isPublicIP(ip) {
						return nil, errUnsafeHTTPDestination
					}
				}
			}
			conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
			if err == nil {
				responseIP = remoteAddrIP(conn.RemoteAddr())
			}
			return conn, err
		},
	}
	defer transport.Close()
	client := &http.Client{
		Transport:     transport,
		Timeout:       deadlineTimeout(ctx, 10*time.Second),
		CheckRedirect: safeHTTPRedirectPolicy(allowPrivate),
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
