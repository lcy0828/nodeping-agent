package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func validateSecureBaseURL(raw string, field string) (*url.URL, error) {
	return validateControlPlaneBaseURL(raw, field, false)
}

func validateControlPlaneBaseURL(raw string, field string, allowInsecureHTTP bool) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%s is invalid: %w", field, err)
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute base URL without credentials, query, or fragment", field)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" {
		if scheme != "http" || !isLoopbackDevelopmentHost(parsed.Hostname()) {
			if scheme != "http" || !allowInsecureHTTP {
				return nil, fmt.Errorf("%s must use HTTPS (HTTP requires NODEPING_AGENT_ALLOW_INSECURE_HTTP=true outside localhost development)", field)
			}
		}
	}
	if parsed.Port() != "" {
		if _, err := validateProbePort(parsed.Port()); err != nil {
			return nil, fmt.Errorf("%s has an invalid port: %w", field, err)
		}
	}
	return parsed, nil
}

func isLoopbackDevelopmentHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func controlPlaneEndpoint(baseURL string, path string, allowInsecureHTTP bool) (string, error) {
	if _, err := validateControlPlaneBaseURL(baseURL, "NODEPING_SERVER_URL", allowInsecureHTTP); err != nil {
		return "", err
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\r\n") {
		return "", errors.New("control-plane request path is invalid")
	}
	return strings.TrimRight(baseURL, "/") + path, nil
}

func newControlPlaneHTTPClient(timeout time.Duration, allowInsecureHTTP bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return controlPlaneRedirect(req, via, allowInsecureHTTP)
		},
	}
}

func secureControlPlaneRedirect(req *http.Request, via []*http.Request) error {
	return controlPlaneRedirect(req, via, false)
}

func controlPlaneRedirect(req *http.Request, via []*http.Request, allowInsecureHTTP bool) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if req == nil || req.URL == nil {
		return errors.New("invalid control-plane redirect")
	}
	if _, err := validateControlPlaneBaseURL(req.URL.Scheme+"://"+req.URL.Host, "control-plane redirect", allowInsecureHTTP); err != nil {
		return err
	}
	if len(via) == 0 || via[len(via)-1] == nil || via[len(via)-1].URL == nil {
		return nil
	}
	previous := via[len(via)-1].URL
	if strings.EqualFold(previous.Scheme, "https") && strings.EqualFold(req.URL.Scheme, "http") {
		return errors.New("control-plane HTTPS redirect downgrade is not allowed")
	}
	if !sameURLOrigin(previous, req.URL) {
		for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
			req.Header.Del(header)
		}
	}
	return nil
}

func sameURLOrigin(left *url.URL, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) {
		return false
	}
	leftHost, leftPort := normalizedURLHostPort(left)
	rightHost, rightPort := normalizedURLHostPort(right)
	return strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
}

func normalizedURLHostPort(target *url.URL) (string, string) {
	if target == nil {
		return "", ""
	}
	host := strings.Trim(strings.TrimSpace(target.Hostname()), "[]")
	port := target.Port()
	if port == "" {
		if strings.EqualFold(target.Scheme, "https") {
			port = "443"
		} else if strings.EqualFold(target.Scheme, "http") {
			port = "80"
		}
	}
	return host, port
}

func loopbackURLHost(host string) bool {
	if isLoopbackDevelopmentHost(host) {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
