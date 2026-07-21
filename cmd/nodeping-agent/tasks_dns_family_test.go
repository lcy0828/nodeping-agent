package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestDNSLookupStrictFamilyRejectsSystemResolver(t *testing.T) {
	_, err := runDNSLookupWithOptions(context.Background(), map[string]any{
		"domain": "example.com",
	}, map[string]any{"ip_family": "ipv6"})
	if err == nil || !strings.Contains(err.Error(), "system DNS transport cannot guarantee requested IPv6") {
		t.Fatalf("runDNSLookupWithOptions error = %v, want strict system resolver rejection", err)
	}
}

func TestExecuteTaskPassesIPFamilyToDNSLookup(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"dns_lookup": map[string]any{"domain": "example.com"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	result := executeTask(context.Background(), config{}, taskRequest{
		ID:       "dns-family",
		TaskType: "dns_lookup",
		Payload:  payload,
		Options:  map[string]any{"ip_family": "ipv4"},
	})
	if result.Success || result.Status != "failed" || !strings.Contains(result.ErrorMessage, "system DNS transport cannot guarantee requested IPv4") {
		t.Fatalf("executeTask result = %+v, want strict family failure from DNS lookup", result)
	}
}

func TestDNSResolverLiteralMustMatchRequestedFamily(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		server   string
	}{
		{name: "udp", protocol: "udp", server: "1.1.1.1"},
		{name: "tcp", protocol: "tcp", server: "1.1.1.1"},
		{name: "dot", protocol: "dot", server: "1.1.1.1"},
		{name: "doq", protocol: "doq", server: "1.1.1.1"},
		{name: "doh", protocol: "doh", server: "https://1.1.1.1/dns-query"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lookupDNSRecordWithOptions(context.Background(), "example.com", "A", map[string]any{
				"dns_server":   tt.server,
				"dns_protocol": tt.protocol,
			}, map[string]any{"ip_family": "ipv6"})
			if !errors.Is(err, errProbeIPFamilyMismatch) {
				t.Fatalf("lookup error = %v, want errProbeIPFamilyMismatch", err)
			}
		})
	}
}

func TestPrepareDNSExchangeTargetPinsFamilyAndPreservesAuthority(t *testing.T) {
	originalLookup := lookupProbeNetIP
	defer func() { lookupProbeNetIP = originalLookup }()

	var networks []string
	lookupProbeNetIP = func(_ context.Context, network string, host string) ([]netip.Addr, error) {
		networks = append(networks, network+":"+host)
		return []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, nil
	}
	options := map[string]any{"ip_family": "ipv6"}

	dot, err := prepareDNSExchangeTarget(context.Background(), "resolver.example:8853", "dot", options)
	if err != nil {
		t.Fatalf("prepare DoT target: %v", err)
	}
	if dot.address != "[2606:4700:4700::1111]:8853" || dot.tlsServerName != "resolver.example" {
		t.Fatalf("DoT target = %+v, want pinned IPv6 address and original SNI", dot)
	}
	doq, err := prepareDNSExchangeTarget(context.Background(), "resolver.example:8853", "doq", options)
	if err != nil {
		t.Fatalf("prepare DoQ target: %v", err)
	}
	if doq.address != "[2606:4700:4700::1111]:8853" || doq.tlsServerName != "resolver.example" {
		t.Fatalf("DoQ target = %+v, want pinned IPv6 address and original SNI", doq)
	}

	doh, err := prepareDNSExchangeTarget(context.Background(), "https://resolver.example/custom-dns", "doh", options)
	if err != nil {
		t.Fatalf("prepare DoH target: %v", err)
	}
	parsed, parseErr := url.Parse(doh.dohEndpoint)
	if parseErr != nil {
		t.Fatalf("parse prepared DoH endpoint: %v", parseErr)
	}
	if doh.address != "[2606:4700:4700::1111]:443" || doh.tlsServerName != "resolver.example" || parsed.Hostname() != "resolver.example" || parsed.Path != "/custom-dns" {
		t.Fatalf("DoH target = %+v, URL = %+v; want pinned IPv6 connect address with original authority", doh, parsed)
	}

	wantLookups := []string{"ip6:resolver.example", "ip6:resolver.example", "ip6:resolver.example"}
	if len(networks) != len(wantLookups) {
		t.Fatalf("resolver lookups = %v, want %v", networks, wantLookups)
	}
	for i := range wantLookups {
		if networks[i] != wantLookups[i] {
			t.Fatalf("resolver lookup[%d] = %q, want %q", i, networks[i], wantLookups[i])
		}
	}
}

func TestDefaultDNSCompareResolversFollowRequestedFamily(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		want    []string
	}{
		{name: "auto", want: []string{"system", "223.5.5.5", "119.29.29.29"}},
		{name: "ipv4", options: map[string]any{"ip_family": "ipv4"}, want: []string{"223.5.5.5", "119.29.29.29"}},
		{name: "ipv6", options: map[string]any{"ip_family": "6"}, want: []string{"2400:3200::1", "2402:4e00::"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := defaultDNSCompareResolvers(tt.options)
			if err != nil {
				t.Fatalf("defaultDNSCompareResolvers: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("resolvers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSCompareFailsWhenEveryResolverViolatesFamily(t *testing.T) {
	result, err := runDNSCompare(context.Background(), map[string]any{
		"domain":    "example.com",
		"resolvers": []any{"1.1.1.1", "8.8.8.8"},
	}, map[string]any{"ip_family": "ipv6"})
	if err == nil || !strings.Contains(err.Error(), "all DNS resolvers failed") {
		t.Fatalf("runDNSCompare error = %v, want aggregate failure", err)
	}
	if got := int(result["success_count"].(int)); got != 0 {
		t.Fatalf("success_count = %d, want 0; result = %+v", got, result)
	}
	rows, ok := result["resolvers"].([]map[string]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("resolver rows = %#v, want two failure rows", result["resolvers"])
	}
	for _, row := range rows {
		if row["success"] != false || !strings.Contains(row["error"].(string), errProbeIPFamilyMismatch.Error()) {
			t.Fatalf("resolver row = %+v, want family mismatch failure", row)
		}
	}
}

func TestDNSNetworkForAddressIsExplicit(t *testing.T) {
	if got := dnsNetworkForAddress("udp", "1.1.1.1:53"); got != "udp4" {
		t.Fatalf("IPv4 UDP network = %q, want udp4", got)
	}
	if got := dnsNetworkForAddress("tcp", "[2606:4700:4700::1111]:853"); got != "tcp6" {
		t.Fatalf("IPv6 TCP network = %q, want tcp6", got)
	}
}

func TestDoHRedirectsAreRejected(t *testing.T) {
	err := rejectDNSRedirect(&http.Request{}, []*http.Request{{}})
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("redirect policy error = %v, want fail-closed DoH redirect", err)
	}
}
