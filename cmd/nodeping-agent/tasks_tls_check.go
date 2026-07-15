package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func runTLSCheck(ctx context.Context, payload map[string]any, optionSets ...map[string]any) (map[string]any, error) {
	var options map[string]any
	if len(optionSets) > 0 {
		options = optionSets[0]
	}
	host := strings.TrimSpace(fmt.Sprint(payload["host"]))
	if host == "" {
		host = strings.TrimSpace(fmt.Sprint(payload["target"]))
	}
	if host == "" || host == "<nil>" {
		return nil, errors.New("tls host is required")
	}
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		if parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "tls") {
			return nil, errors.New("tls target URL is invalid")
		}
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
	serverName = strings.Trim(serverName, "[]")
	if _, err := validateProbeHost(serverName); err != nil {
		return nil, fmt.Errorf("invalid TLS server name: %w", err)
	}
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHostPort(ctx, host)
	if err != nil {
		return nil, err
	}
	pinnedTarget := net.JoinHostPort(resolved.IP.String(), resolved.Port)
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 5*time.Second)}
	started := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", pinnedTarget)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
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
