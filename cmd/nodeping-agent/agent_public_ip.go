package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func discoverPublicIP(ctx context.Context) string {
	for _, endpoint := range []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipv4.icanhazip.com",
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if ip != nil && isPublicIP(ip) {
			return ip.String()
		}
	}
	return ""
}
