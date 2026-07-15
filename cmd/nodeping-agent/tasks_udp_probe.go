package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func runUDPProbe(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("udp_probe target is required")
	}
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHostPort(ctx, target)
	if err != nil {
		return nil, err
	}
	pinnedTarget := net.JoinHostPort(resolved.IP.String(), resolved.Port)
	payloadMode := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "payload_mode")))
	payloadText := stringOptionAny(options, "payload")
	payloadBytes := []byte(payloadText)
	dnsQueryDomain := strings.TrimSpace(stringOptionAny(options, "dns_query_domain"))
	if dnsQueryDomain == "" {
		dnsQueryDomain = "example.com"
	}
	if payloadMode == "" || payloadMode == "auto" {
		if payloadText == "" && resolved.Port == "53" {
			payloadMode = "dns_query"
		} else {
			payloadMode = "text"
		}
	}
	switch payloadMode {
	case "dns_query":
		payloadBytes = buildDNSQueryPayload(dnsQueryDomain, "A")
	case "text":
		if payloadText == "" {
			payloadText = "nodeping"
			payloadBytes = []byte(payloadText)
		}
	default:
		return nil, fmt.Errorf("unsupported udp payload_mode: %s", payloadMode)
	}
	if len(payloadBytes) > 1024 {
		payloadBytes = payloadBytes[:1024]
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
	conn, err := dialer.DialContext(ctx, "udp", pinnedTarget)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	connectLatencyMS := elapsedMS(started)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(readTimeoutMS) * time.Millisecond))
	}
	writeStarted := time.Now()
	sent, err := conn.Write(payloadBytes)
	if err != nil {
		return nil, err
	}
	sendLatencyMS := elapsedMS(writeStarted)
	result := map[string]any{
		"udp_probe":          sendLatencyMS,
		"target":             target,
		"target_ip":          resolved.IP.String(),
		"sent_bytes":         sent,
		"payload_mode":       payloadMode,
		"wait_response":      waitResponse,
		"read_timeout_ms":    readTimeoutMS,
		"connect_latency_ms": connectLatencyMS,
		"send_latency_ms":    sendLatencyMS,
	}
	if payloadMode == "dns_query" {
		result["dns_query_domain"] = dnsQueryDomain
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
			result["elapsed_ms"] = elapsedMS(started)
			return result, nil
		}
		return nil, err
	}
	result["reachable"] = true
	result["response_received"] = true
	result["received_bytes"] = received
	responseLatencyMS := elapsedMS(started)
	result["udp_probe"] = responseLatencyMS
	result["response_latency_ms"] = responseLatencyMS
	return result, nil
}

func udpTargetPort(target string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
}

func buildDNSQueryPayload(domain string, recordType string) []byte {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		domain = "example.com"
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	qtype := uint16(1)
	if recordType == "AAAA" {
		qtype = 28
	}
	id := make([]byte, 2)
	if _, err := rand.Read(id); err != nil {
		now := time.Now().UnixNano()
		id[0] = byte(now >> 8)
		id[1] = byte(now)
	}
	payload := []byte{
		id[0], id[1],
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		payload = append(payload, byte(len(label)))
		payload = append(payload, []byte(label)...)
	}
	payload = append(payload, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return payload
}
