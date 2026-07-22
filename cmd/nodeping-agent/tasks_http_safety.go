package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

var errUnsafeHTTPDestination = errUnsafeProbeDestination

type httpRedirectPolicy struct {
	allowPrivate        bool
	allowHTTPSDowngrade bool
}

func safeHTTPTransport(ctx context.Context, originalHost string, allowPrivate bool) *http.Transport {
	resolver := &probeTargetResolver{allowPrivate: allowPrivate, cache: make(map[string]netip.Addr)}
	return safeHTTPTransportWithResolver(originalHost, resolver)
}

func safeHTTPTransportWithResolver(originalHost string, resolver *probeTargetResolver) *http.Transport {
	if resolver == nil {
		resolver = newProbeTargetResolver(nil)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return resolver.dialContext(ctx, network, address)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	if originalHost != "" {
		transport.TLSClientConfig.ServerName = strings.Trim(originalHost, "[]")
	}
	return transport
}

func safeDialContext(ctx context.Context, network string, address string, allowPrivate bool) (net.Conn, error) {
	resolver := &probeTargetResolver{allowPrivate: allowPrivate, cache: make(map[string]netip.Addr)}
	return resolver.dialContext(ctx, network, address)
}

func safeHTTPRedirectPolicy(policy httpRedirectPolicy) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		return checkSafeHTTPRedirect(req, via, policy)
	}
}

func checkSafeHTTPRedirect(req *http.Request, via []*http.Request, policy httpRedirectPolicy) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if req == nil || req.URL == nil {
		return errors.New("invalid redirect target")
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	if scheme != "http" && scheme != "https" {
		return errors.New("redirect target must use http or https")
	}
	if len(via) > 0 && via[len(via)-1] != nil && via[len(via)-1].URL != nil &&
		strings.EqualFold(via[len(via)-1].URL.Scheme, "https") && scheme == "http" && !policy.allowHTTPSDowngrade {
		return errors.New("HTTPS redirect downgrade is not allowed")
	}
	for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		req.Header.Del(header)
	}
	host := strings.Trim(req.URL.Hostname(), "[]")
	if host == "" {
		return errors.New("redirect target host is required")
	}
	if _, err := validateProbePort(defaultURLPort(req.URL)); err != nil {
		return err
	}
	if policy.allowPrivate {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return errUnsafeHTTPDestination
	}
	if addr, err := netip.ParseAddr(host); err == nil && !isPublicProbeAddr(addr) {
		return errUnsafeHTTPDestination
	}
	return nil
}

func allowPrivateHTTPDestinations(options map[string]any) bool {
	return trustedPrivateTargetTask(options)
}

func publicDialIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() == nil {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func requirePublicResolverHost(ctx context.Context, server string) error {
	host := strings.TrimSpace(server)
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil || parsed.Hostname() == "" {
			if err != nil {
				return err
			}
			return fmt.Errorf("resolver address is invalid")
		}
		host = parsed.Hostname()
	} else if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("resolver address must be public")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !isPublicProbeAddr(addr) {
			return fmt.Errorf("resolver address must be public")
		}
		return nil
	}
	addrs, err := lookupProbeNetIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolver address did not resolve")
	}
	for _, addr := range addrs {
		if !isPublicProbeAddr(addr) {
			return fmt.Errorf("resolver address must resolve to public IPs")
		}
	}
	return nil
}

func validateHTTPProbeURL(raw string, requireHTTPS bool) (*url.URL, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return nil, errors.New("HTTP target is required")
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || (requireHTTPS && scheme != "https") {
		if requireHTTPS {
			return nil, errors.New("HTTP/3 target must use https")
		}
		return nil, errors.New("HTTP target must use http or https")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("HTTP target URL is invalid")
	}
	if _, err := validateProbeHost(parsed.Hostname()); err != nil {
		return nil, err
	}
	if _, err := validateProbePort(defaultURLPort(parsed)); err != nil {
		return nil, err
	}
	return parsed, nil
}

func defaultURLPort(target *url.URL) string {
	if target == nil {
		return ""
	}
	if port := target.Port(); port != "" {
		return port
	}
	switch strings.ToLower(target.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
