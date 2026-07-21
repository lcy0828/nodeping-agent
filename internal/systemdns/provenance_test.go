package systemdns

import (
	"context"
	"net/netip"
	"testing"
)

func TestLinuxSnapshotProvenanceCoversPlatformRotateOrderAndResolverSlice(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DiscoveryResult)
	}{
		{name: "platform", mutate: func(result *DiscoveryResult) { result.Platform = PlatformDarwin }},
		{name: "rotate", mutate: func(result *DiscoveryResult) { result.Options.Rotate = false }},
		{name: "source", mutate: func(result *DiscoveryResult) { result.Resolvers[0].Source = SourceSCUtil }},
		{name: "scope", mutate: func(result *DiscoveryResult) { result.Resolvers[0].ScopeDomain = "corp.example" }},
		{name: "discovery index", mutate: func(result *DiscoveryResult) { result.Resolvers[0].discoveryIndex++ }},
		{name: "group index", mutate: func(result *DiscoveryResult) { result.Resolvers[0].groupIndex++ }},
		{name: "reordered", mutate: func(result *DiscoveryResult) {
			result.Resolvers[0], result.Resolvers[1] = result.Resolvers[1], result.Resolvers[0]
		}},
		{name: "removed", mutate: func(result *DiscoveryResult) { result.Resolvers = result.Resolvers[:1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := trustedLinuxSnapshotFixture(t)
			test.mutate(&result)
			assertSnapshotTamperRejected(t, result, Selection{Name: "example.com", Rotation: 1})
		})
	}
}

func TestDarwinSnapshotProvenanceCoversScopeOrderInterfaceAndUnsupportedRoutes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DiscoveryResult)
	}{
		{name: "scope", mutate: func(result *DiscoveryResult) { result.Resolvers[1].ScopeDomain = "other.example" }},
		{name: "scoped", mutate: func(result *DiscoveryResult) { result.Resolvers[1].Scoped = false }},
		{name: "order", mutate: func(result *DiscoveryResult) { result.Resolvers[1].Order++ }},
		{name: "order set", mutate: func(result *DiscoveryResult) { result.Resolvers[1].OrderSet = false }},
		{name: "interface", mutate: func(result *DiscoveryResult) { result.Resolvers[1].InterfaceIndex++ }},
		{name: "interface name", mutate: func(result *DiscoveryResult) { result.Resolvers[1].InterfaceName = "en9" }},
		{name: "resolver reorder", mutate: func(result *DiscoveryResult) {
			result.Resolvers[0], result.Resolvers[1] = result.Resolvers[1], result.Resolvers[0]
		}},
		{name: "resolver removal", mutate: func(result *DiscoveryResult) { result.Resolvers = result.Resolvers[:1] }},
		{name: "unsupported scope", mutate: func(result *DiscoveryResult) { result.UnsupportedRoutes[0].ScopeDomain = "corp.example" }},
		{name: "unsupported order", mutate: func(result *DiscoveryResult) { result.UnsupportedRoutes[0].Order++ }},
		{name: "unsupported interface", mutate: func(result *DiscoveryResult) { result.UnsupportedRoutes[0].InterfaceIndex = 4 }},
		{name: "unsupported reason", mutate: func(result *DiscoveryResult) { result.UnsupportedRoutes[0].Reason = "changed" }},
		{name: "unsupported removal", mutate: func(result *DiscoveryResult) { result.UnsupportedRoutes = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := trustedDarwinSnapshotFixture(t)
			test.mutate(&result)
			assertSnapshotTamperRejected(t, result, Selection{Name: "host.corp.example", InterfaceIndex: 4})
		})
	}
}

func TestWindowsSnapshotProvenanceCoversInterfacesMetricsAndResolverSlice(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DiscoveryResult)
	}{
		{name: "interface", mutate: func(result *DiscoveryResult) { result.Resolvers[0].InterfaceIndex++ }},
		{name: "route interface", mutate: func(result *DiscoveryResult) { result.Resolvers[0].RouteInterfaceIndex++ }},
		{name: "IPv6 metric", mutate: func(result *DiscoveryResult) { result.Resolvers[0].IPv6Metric++ }},
		{name: "route interface metric", mutate: func(result *DiscoveryResult) { result.Resolvers[0].RouteInterfaceMetric++ }},
		{name: "route metric", mutate: func(result *DiscoveryResult) { result.Resolvers[0].RouteMetric++ }},
		{name: "metric set", mutate: func(result *DiscoveryResult) { result.Resolvers[0].MetricSet = false }},
		{name: "connection suffix", mutate: func(result *DiscoveryResult) { result.Resolvers[0].ConnectionSuffix = "changed.example" }},
		{name: "resolver reorder", mutate: func(result *DiscoveryResult) {
			result.Resolvers[0], result.Resolvers[1] = result.Resolvers[1], result.Resolvers[0]
		}},
		{name: "resolver removal", mutate: func(result *DiscoveryResult) { result.Resolvers = result.Resolvers[:1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := trustedWindowsSnapshotFixture(t)
			test.mutate(&result)
			assertSnapshotTamperRejected(t, result, Selection{Name: "example.com"})
		})
	}
}

func trustedLinuxSnapshotFixture(t *testing.T) DiscoveryResult {
	t.Helper()
	result, err := ParseResolvConf([]byte("nameserver 127.0.0.53\nnameserver fe80::53%eth0\noptions rotate\n"))
	if err != nil {
		t.Fatal(err)
	}
	return sealAndCheckSnapshot(t, result, Selection{Name: "example.com", Rotation: 1})
}

func trustedDarwinSnapshotFixture(t *testing.T) DiscoveryResult {
	t.Helper()
	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 1.1.1.1
  order : 200000

resolver #2
  domain : corp.example
  nameserver[0] : fe80::53
  if_index : 4 (en4)
  flags : Scoped
  order : 100000

resolver #3
  domain : local
  options : mdns
  order : 300000
`))
	if err != nil {
		t.Fatal(err)
	}
	return sealAndCheckSnapshot(t, result, Selection{Name: "host.corp.example", InterfaceIndex: 4})
}

func trustedWindowsSnapshotFixture(t *testing.T) DiscoveryResult {
	t.Helper()
	adapters := []windowsAdapterSnapshot{
		{
			up: true, interfaceIndex: 10, ipv6InterfaceIndex: 11, ipv6Metric: 5,
			servers: []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::53"), scopeID: 11}},
		},
		{
			up: true, interfaceIndex: 20, ipv4Metric: 10,
			servers: []windowsServerSnapshot{{address: netip.MustParseAddr("10.0.0.53")}},
		},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("fe80::/10"), interfaceIndex: 11, metric: 2},
		{destination: netip.MustParsePrefix("10.0.0.0/8"), interfaceIndex: 20, metric: 3},
	}
	result, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	return sealAndCheckSnapshot(t, result, Selection{Name: "example.com"})
}

func sealAndCheckSnapshot(t testing.TB, result DiscoveryResult, selection Selection) DiscoveryResult {
	t.Helper()
	if err := sealDiscoveryResult(&result); err != nil {
		t.Fatal(err)
	}
	if !snapshotProvenanceValid(result) {
		t.Fatal("freshly sealed snapshot provenance is invalid")
	}
	selected, err := result.SelectTrusted(selection)
	if err != nil || len(selected) == 0 {
		t.Fatalf("unmodified trusted selection = %#v, %v", selected, err)
	}
	return result
}

func assertSnapshotTamperRejected(t testing.TB, result DiscoveryResult, selection Selection) {
	t.Helper()
	if snapshotProvenanceValid(result) {
		t.Fatal("mutated resolver snapshot retained provenance")
	}
	if selected, err := result.SelectTrusted(selection); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("mutated snapshot selection = %#v, %v", selected, err)
	}
}
