package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errUnsafeHTTPDestination = errors.New("HTTP target resolved to a private or reserved IP")

func safeHTTPTransport(ctx context.Context, originalHost string, allowPrivate bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return safeDialContext(ctx, network, address, allowPrivate)
	}
	if originalHost != "" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			if transport.TLSClientConfig.MinVersion == 0 {
				transport.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		transport.TLSClientConfig.ServerName = strings.Trim(originalHost, "[]")
	}
	return transport
}

func safeDialContext(ctx context.Context, network string, address string, allowPrivate bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
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
	if len(ips) == 0 {
		return nil, errors.New("HTTP target did not resolve to an IP")
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 5*time.Second)}
	return dialer.DialContext(ctx, network, net.JoinHostPort(publicDialIP(ips[0]), port))
}

func safeHTTPRedirectPolicy(allowPrivate bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		return checkSafeHTTPRedirect(req, via, allowPrivate)
	}
}

func checkSafeHTTPRedirect(req *http.Request, via []*http.Request, allowPrivate bool) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if allowPrivate {
		return nil
	}
	if req == nil || req.URL == nil {
		return errors.New("invalid redirect target")
	}
	host := strings.Trim(req.URL.Hostname(), "[]")
	if host == "" {
		return errors.New("redirect target host is required")
	}
	if strings.EqualFold(host, "localhost") {
		return errUnsafeHTTPDestination
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return errUnsafeHTTPDestination
	}
	return nil
}

func allowPrivateHTTPDestinations(options map[string]any) bool {
	return boolOptionDefault(options, "allow_private_redirects", false) || boolOptionDefault(options, "allow_private_targets", false)
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
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("resolver address must be public")
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolver address did not resolve")
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("resolver address must resolve to public IPs")
		}
	}
	return nil
}
