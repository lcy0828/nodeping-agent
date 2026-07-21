package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestProbeTargetResolverSelectsRequestedFamilyFromDualStackDNS(t *testing.T) {
	originalLookup := lookupProbeNetIP
	defer func() { lookupProbeNetIP = originalLookup }()

	var networks []string
	lookupProbeNetIP = func(_ context.Context, network string, _ string) ([]netip.Addr, error) {
		networks = append(networks, network)
		return []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
		}, nil
	}

	ipv4, err := newProbeTargetResolver(map[string]any{"ip_family": "4"}).resolveHost(context.Background(), "dual.example")
	if err != nil || ipv4.String() != "1.1.1.1" {
		t.Fatalf("IPv4 resolution addr=%v err=%v", ipv4, err)
	}
	ipv6, err := newProbeTargetResolver(map[string]any{"ip_family": "IPv6"}).resolveHost(context.Background(), "dual.example")
	if err != nil || ipv6.String() != "2606:4700:4700::1111" {
		t.Fatalf("IPv6 resolution addr=%v err=%v", ipv6, err)
	}
	if got, want := strings.Join(networks, ","), "ip4,ip6"; got != want {
		t.Fatalf("lookup networks = %q, want %q", got, want)
	}
}

func TestProbeTargetResolverRejectsDNSWithOnlyAnotherFamily(t *testing.T) {
	originalLookup := lookupProbeNetIP
	defer func() { lookupProbeNetIP = originalLookup }()

	lookupProbeNetIP = func(_ context.Context, network string, _ string) ([]netip.Addr, error) {
		if network != "ip6" {
			t.Fatalf("lookup network = %q, want ip6", network)
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}

	_, err := newProbeTargetResolver(map[string]any{"ip_family": 6}).resolveHost(context.Background(), "ipv4-only.example")
	if !errors.Is(err, errProbeIPFamilyMismatch) || !strings.Contains(err.Error(), "no IPv6 address") {
		t.Fatalf("resolution error = %v, want explicit IPv6 family mismatch", err)
	}
}

func TestProbeTargetResolverCacheIsScopedByFamily(t *testing.T) {
	originalLookup := lookupProbeNetIP
	defer func() { lookupProbeNetIP = originalLookup }()

	calls := 0
	lookupProbeNetIP = func(_ context.Context, network string, _ string) ([]netip.Addr, error) {
		calls++
		if network == "ip4" {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, nil
	}

	resolver := newProbeTargetResolver(map[string]any{"ip_family": "ipv4"})
	ipv4, err := resolver.resolveHost(context.Background(), "cache.example")
	if err != nil {
		t.Fatalf("resolve IPv4: %v", err)
	}
	resolver.family = probeIPFamilyIPv6
	ipv6, err := resolver.resolveHost(context.Background(), "cache.example")
	if err != nil {
		t.Fatalf("resolve IPv6: %v", err)
	}
	if ipv4.String() != "1.1.1.1" || ipv6.String() != "2606:4700:4700::1111" || calls != 2 {
		t.Fatalf("family-scoped cache IPv4=%v IPv6=%v lookups=%d", ipv4, ipv6, calls)
	}
}

func TestProbeTargetResolverRejectsLiteralFamilyMismatch(t *testing.T) {
	tests := []struct {
		name     string
		family   any
		target   string
		required string
	}{
		{name: "IPv4 task with IPv6 literal", family: "ipv4", target: "2606:4700:4700::1111", required: "IPv4"},
		{name: "IPv6 task with IPv4 literal", family: "6", target: "1.1.1.1", required: "IPv6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newProbeTargetResolver(map[string]any{"ip_family": tt.family}).resolveHost(context.Background(), tt.target)
			if !errors.Is(err, errProbeIPFamilyMismatch) || !strings.Contains(err.Error(), "requires "+tt.required) {
				t.Fatalf("resolution error = %v, want explicit %s mismatch", err, tt.required)
			}
		})
	}
}

func TestProbeTargetResolverRejectsInvalidFamilyOption(t *testing.T) {
	_, err := newProbeTargetResolver(map[string]any{"ip_family": "ipx"}).resolveHost(context.Background(), "1.1.1.1")
	if !errors.Is(err, errInvalidProbeIPFamily) {
		t.Fatalf("resolution error = %v, want invalid ip_family", err)
	}
}

type publicIPRoundTripFunc func(*http.Request) (*http.Response, error)

func (f publicIPRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDiscoverPublicIPFromEndpointsRequiresRequestedFamily(t *testing.T) {
	responses := []string{"1.1.1.1", "2606:4700:4700::1111"}
	client := &http.Client{Transport: publicIPRoundTripFunc(func(*http.Request) (*http.Response, error) {
		body := responses[0]
		responses = responses[1:]
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}

	got := discoverPublicIPFromEndpoints(
		context.Background(),
		probeIPFamilyIPv6,
		[]string{"https://first.example/ip", "https://second.example/ip"},
		client,
	)
	if got != "2606:4700:4700::1111" {
		t.Fatalf("discovered IPv6 = %q", got)
	}
}

func TestPublicIPFamilyDialContextForcesSocketFamily(t *testing.T) {
	tests := []struct {
		family  probeIPFamily
		network string
	}{
		{family: probeIPFamilyIPv4, network: "tcp4"},
		{family: probeIPFamilyIPv6, network: "tcp6"},
	}
	for _, tt := range tests {
		t.Run(tt.family.String(), func(t *testing.T) {
			gotNetwork := ""
			dial := publicIPFamilyDialContext(tt.family, func(_ context.Context, network string, _ string) (net.Conn, error) {
				gotNetwork = network
				return nil, errors.New("stop after recording network")
			})
			_, _ = dial(context.Background(), "tcp", "echo.example:443")
			if gotNetwork != tt.network {
				t.Fatalf("dial network = %q, want %q", gotNetwork, tt.network)
			}
		})
	}
}

func TestPostPublicIPReportIncludesOnlySuccessfulFamilies(t *testing.T) {
	tests := []struct {
		name         string
		discovery    publicIPDiscovery
		wantPrimary  string
		wantFamilies []string
		wantIPv4     bool
		wantIPv6     bool
	}{
		{
			name:         "dual stack prefers IPv4 compatibility address",
			discovery:    publicIPDiscovery{IPv4: "1.1.1.1", IPv6: "2606:4700:4700::1111"},
			wantPrimary:  "1.1.1.1",
			wantFamilies: []string{"ipv4", "ipv6"},
			wantIPv4:     true,
			wantIPv6:     true,
		},
		{
			name:         "single successful family does not mark the other unavailable",
			discovery:    publicIPDiscovery{IPv6: "2606:4700:4700::1111"},
			wantPrimary:  "2606:4700:4700::1111",
			wantFamilies: []string{"ipv6"},
			wantIPv6:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/v1/public-ip" {
					http.NotFound(w, r)
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			err := postPublicIPReport(context.Background(), config{
				ServerURL:  server.URL,
				AgentID:    "agent-family-test",
				AgentToken: "agent-token",
				HTTPClient: server.Client(),
			}, tt.discovery)
			if err != nil {
				t.Fatalf("postPublicIPReport: %v", err)
			}
			if payload["public_ip"] != tt.wantPrimary {
				t.Fatalf("public_ip = %#v, want %q", payload["public_ip"], tt.wantPrimary)
			}
			if _, ok := payload["public_ipv4"]; ok != tt.wantIPv4 {
				t.Fatalf("public_ipv4 present = %v, payload=%+v", ok, payload)
			}
			if _, ok := payload["public_ipv6"]; ok != tt.wantIPv6 {
				t.Fatalf("public_ipv6 present = %v, payload=%+v", ok, payload)
			}
			rawFamilies, ok := payload["public_ip_families"].([]any)
			if !ok {
				t.Fatalf("public_ip_families = %#v", payload["public_ip_families"])
			}
			families := make([]string, 0, len(rawFamilies))
			for _, family := range rawFamilies {
				families = append(families, family.(string))
			}
			if strings.Join(families, ",") != strings.Join(tt.wantFamilies, ",") {
				t.Fatalf("public_ip_families = %v, want %v", families, tt.wantFamilies)
			}
		})
	}
}
