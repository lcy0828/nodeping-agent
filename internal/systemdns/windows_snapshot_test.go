package systemdns

import (
	"context"
	"net/netip"
	"testing"
)

func TestBuildWindowsResultOrdersByCombinedMetricAndPreservesSuffixMetadata(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             false,
			dnsSuffix:      "corp.example",
			interfaceIndex: 1,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("192.0.2.53")}},
		},
		{up: true, interfaceIndex: 2},
		{
			up:                 true,
			interfaceIndex:     10,
			ipv6InterfaceIndex: 11,
			interfaceName:      "Office Ethernet",
			dnsSuffix:          "example.com",
			dnsSuffixes:        []string{"example.com", "search.example"},
			ipv4Metric:         50,
			ipv6Metric:         60,
			servers: []windowsServerSnapshot{
				{address: netip.MustParseAddr("8.8.8.8")},
				{address: netip.MustParseAddr("8.8.8.8")},
				{address: netip.MustParseAddr("1.1.1.1")},
			},
		},
		{
			up:                 true,
			interfaceIndex:     20,
			ipv6InterfaceIndex: 21,
			interfaceName:      "Corp",
			dnsSuffix:          "corp.example",
			ipv4Metric:         20,
			ipv6Metric:         20,
			servers:            []windowsServerSnapshot{{address: netip.MustParseAddr("10.0.0.53")}},
		},
		{
			up:                 true,
			interfaceIndex:     30,
			ipv6InterfaceIndex: 31,
			interfaceName:      "Corp v6",
			dnsSuffix:          "corp.example",
			ipv4Metric:         5,
			ipv6Metric:         5,
			servers: []windowsServerSnapshot{
				{address: netip.MustParseAddr("fe80::53"), scopeID: 31},
				{address: netip.MustParseAddr("9.9.9.9")},
			},
		},
	}
	limits := mustSystemDNSLimits(t)
	result, err := buildWindowsResult(context.Background(), adapters, defaultWindowsRoutes(adapters), limits)
	if err != nil {
		t.Fatalf("buildWindowsResult() error = %v", err)
	}
	if len(result.Resolvers) != 5 {
		t.Fatalf("resolver count = %d", len(result.Resolvers))
	}
	assertStrings(t, result.SearchDomains, []string{"example.com", "search.example", "corp.example"})
	if result.Resolvers[0].ConnectionSuffix != "example.com" || result.Resolvers[0].ScopeDomain != "" {
		t.Fatalf("Windows suffix metadata = %#v", result.Resolvers[0])
	}
	if result.Resolvers[3].Endpoint.Zone() != "31" || result.Resolvers[3].InterfaceIndex != 31 || result.Resolvers[3].RouteInterfaceIndex != 31 {
		t.Fatalf("link-local resolver = %#v", result.Resolvers[3])
	}

	want := []string{"[fe80::53%31]:53", "9.9.9.9:53", "10.0.0.53:53", "8.8.8.8:53", "1.1.1.1:53"}
	for _, name := range []string{"host.corp.example", "www.example.com", "public.example"} {
		selected, selectErr := result.ResolversForName(name)
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		assertStrings(t, resolverAddresses(selected), want)
	}
	trusted := result
	if err := sealDiscoveryResult(&trusted); err != nil {
		t.Fatal(err)
	}
	trustedSelected, err := trusted.SelectTrusted(Selection{Name: "public.example"})
	if err != nil {
		t.Fatalf("SelectTrusted() error = %v", err)
	}
	assertStrings(t, resolverAddresses(trustedSelected), want)
	if trustedSelected[0].Endpoint.Zone() != "31" || !trustedSelected[0].Endpoint.IsTrustedSystem() {
		t.Fatalf("trusted Windows metric/zone = %#v", trustedSelected[0])
	}
}

func TestBuildWindowsResultInfersIPv6LinkLocalZone(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{{
		up:                 true,
		interfaceIndex:     4,
		ipv6InterfaceIndex: 7,
		servers:            []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::1")}},
	}}
	result, err := buildWindowsResult(context.Background(), adapters, defaultWindowsRoutes(adapters), mustSystemDNSLimits(t))
	if err != nil {
		t.Fatalf("buildWindowsResult() error = %v", err)
	}
	if result.Resolvers[0].Endpoint.Zone() != "7" || result.Resolvers[0].InterfaceIndex != 7 || result.Resolvers[0].RouteInterfaceIndex != 7 {
		t.Fatalf("link-local resolver = %#v", result.Resolvers[0])
	}
}

func TestBuildWindowsResultRejectsLinkLocalWithoutZone(t *testing.T) {
	t.Parallel()

	_, err := buildWindowsResult(context.Background(), []windowsAdapterSnapshot{{
		up:      true,
		servers: []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::1")}},
	}}, nil, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultRejectsZeroProvenanceInterface(t *testing.T) {
	t.Parallel()

	_, err := buildWindowsResult(context.Background(), []windowsAdapterSnapshot{{
		up:      true,
		servers: []windowsServerSnapshot{{address: netip.MustParseAddr("127.0.0.1")}},
	}}, []windowsRouteSnapshot{{
		destination:    netip.MustParsePrefix("127.0.0.0/8"),
		interfaceIndex: 1,
		loopback:       true,
	}}, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultRejectsLinkLocalScopeOnDifferentAdapter(t *testing.T) {
	t.Parallel()

	_, err := buildWindowsResult(context.Background(), []windowsAdapterSnapshot{{
		up:                 true,
		interfaceIndex:     4,
		ipv6InterfaceIndex: 7,
		servers:            []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::1"), scopeID: 8}},
	}}, nil, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultRejectsLinkLocalRouteOnDifferentInterface(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:                 true,
			interfaceIndex:     4,
			ipv6InterfaceIndex: 7,
			servers:            []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::1"), scopeID: 7}},
		},
		{up: true, interfaceIndex: 8, ipv6InterfaceIndex: 8},
	}
	routes := []windowsRouteSnapshot{{
		destination:    netip.MustParsePrefix("fe80::/64"),
		interfaceIndex: 8,
	}}
	_, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorSystemAPI) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultRequiresUpAdapterWithDNS(t *testing.T) {
	t.Parallel()

	_, err := buildWindowsResult(context.Background(), []windowsAdapterSnapshot{{up: false}}, nil, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorNoResolvers) {
		t.Fatalf("error = %v", err)
	}
}

func TestWindowsSelectionCombinesInterfaceAndRouteMetric(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             true,
			interfaceIndex: 1,
			ipv4Metric:     1,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("1.1.1.1")}},
		},
		{
			up:             true,
			interfaceIndex: 2,
			ipv4Metric:     50,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("8.8.8.8")}},
		},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("0.0.0.0/0"), interfaceIndex: 1, metric: 100},
		{destination: netip.MustParsePrefix("0.0.0.0/0"), interfaceIndex: 2, metric: 1},
	}
	result, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := result.ResolversForName("public.example")
	if err != nil {
		t.Fatal(err)
	}
	if selected[0].Endpoint.Address().String() != "8.8.8.8" || effectiveMetric(selected[0]) != 51 {
		t.Fatalf("resolver order/metric = %v/%d", resolverAddresses(selected), effectiveMetric(selected[0]))
	}
}

func TestWindowsConnectionSuffixDoesNotRouteFQDN(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             true,
			interfaceIndex: 1,
			dnsSuffix:      "primary.example",
			dnsSuffixes:    []string{"special.example"},
			ipv4Metric:     50,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("1.1.1.1")}},
		},
		{
			up:             true,
			interfaceIndex: 2,
			ipv4Metric:     5,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("8.8.8.8")}},
		},
	}
	result, err := buildWindowsResult(context.Background(), adapters, defaultWindowsRoutes(adapters), mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := result.ResolversForName("host.special.example")
	if err != nil {
		t.Fatal(err)
	}
	if selected[0].Endpoint.Address().String() != "8.8.8.8" {
		t.Fatalf("connection suffix changed FQDN routing: %v", resolverAddresses(selected))
	}
}

func TestBuildWindowsResultFailsClosedWithoutEndpointRoute(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{{
		up:             true,
		interfaceIndex: 4,
		servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("192.0.2.53")}},
	}}
	_, err := buildWindowsResult(context.Background(), adapters, []windowsRouteSnapshot{{
		destination:    netip.MustParsePrefix("198.51.100.0/24"),
		interfaceIndex: 4,
	}}, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorSystemAPI) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultUsesLoopbackDialRouteAndPreservesAdapterProvenance(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:                 true,
			interfaceIndex:     4,
			ipv6InterfaceIndex: 6,
			ipv4Metric:         100,
			ipv6Metric:         200,
			servers: []windowsServerSnapshot{
				{address: netip.MustParseAddr("127.0.0.1")},
				{address: netip.MustParseAddr("::1")},
			},
		},
		{
			up:                 true,
			interfaceIndex:     1,
			ipv6InterfaceIndex: 1,
			ipv4Metric:         5,
			ipv6Metric:         7,
		},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("0.0.0.0/0"), interfaceIndex: 4, metric: 1},
		{destination: netip.MustParsePrefix("::/0"), interfaceIndex: 6, metric: 1},
		{destination: netip.MustParsePrefix("127.0.0.0/8"), interfaceIndex: 1, metric: 3, loopback: true},
		{destination: netip.MustParsePrefix("::1/128"), interfaceIndex: 1, metric: 4, loopback: true},
	}
	result, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolvers) != 2 {
		t.Fatalf("resolvers = %#v", result.Resolvers)
	}

	ipv4 := result.Resolvers[0]
	if ipv4.InterfaceIndex != 4 || ipv4.RouteInterfaceIndex != 1 || ipv4.RouteInterfaceMetric != 5 || ipv4.RouteMetric != 3 || effectiveMetric(ipv4) != 8 {
		t.Fatalf("IPv4 loopback resolver = %#v, effective metric = %d", ipv4, effectiveMetric(ipv4))
	}
	ipv6 := result.Resolvers[1]
	if ipv6.InterfaceIndex != 6 || ipv6.RouteInterfaceIndex != 1 || ipv6.RouteInterfaceMetric != 7 || ipv6.RouteMetric != 4 || effectiveMetric(ipv6) != 11 {
		t.Fatalf("IPv6 loopback resolver = %#v, effective metric = %d", ipv6, effectiveMetric(ipv6))
	}
}

func TestBuildWindowsResultLoopbackUsesLongestPrefixThenCompleteMetric(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             true,
			interfaceIndex: 4,
			ipv4Metric:     10,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("127.0.0.1")}},
		},
		{up: true, interfaceIndex: 1, ipv4Metric: 1},
		{up: true, interfaceIndex: 2, ipv4Metric: 200},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("127.0.0.0/8"), interfaceIndex: 1, metric: 100, loopback: true},
		{destination: netip.MustParsePrefix("127.0.0.0/8"), interfaceIndex: 2, metric: 0, loopback: true},
		{destination: netip.MustParsePrefix("127.0.0.1/32"), interfaceIndex: 1, metric: 150, loopback: true},
		{destination: netip.MustParsePrefix("127.0.0.1/32"), interfaceIndex: 2, metric: 0, loopback: true},
	}
	result, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	resolver := result.Resolvers[0]
	if resolver.RouteInterfaceIndex != 1 || resolver.RouteMetric != 150 || effectiveMetric(resolver) != 151 {
		t.Fatalf("loopback route = %#v, effective metric = %d", resolver, effectiveMetric(resolver))
	}
}

func TestBuildWindowsResultRejectsLoopbackDefaultRouteAndMissingMetric(t *testing.T) {
	t.Parallel()

	source := windowsAdapterSnapshot{
		up:             true,
		interfaceIndex: 4,
		servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("127.0.0.1")}},
	}
	_, err := buildWindowsResult(context.Background(), []windowsAdapterSnapshot{source}, []windowsRouteSnapshot{{
		destination:    netip.MustParsePrefix("0.0.0.0/0"),
		interfaceIndex: 4,
	}}, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorSystemAPI) {
		t.Fatalf("default-route error = %v", err)
	}

	_, err = buildWindowsResult(context.Background(), []windowsAdapterSnapshot{source}, []windowsRouteSnapshot{{
		destination:    netip.MustParsePrefix("127.0.0.0/8"),
		interfaceIndex: 1,
		loopback:       true,
	}}, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorSystemAPI) {
		t.Fatalf("missing-metric error = %v", err)
	}
}

func TestBuildWindowsResultRejectsNonLoopbackRouteThatOutranksLoopback(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             true,
			interfaceIndex: 4,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("127.0.0.1")}},
		},
		{up: true, interfaceIndex: 1, ipv4Metric: 5},
		{up: true, interfaceIndex: 2, ipv4Metric: 1},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("127.0.0.0/8"), interfaceIndex: 1, loopback: true},
		{destination: netip.MustParsePrefix("127.0.0.1/32"), interfaceIndex: 2},
	}
	_, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if !IsErrorCode(err, ErrorSystemAPI) {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildWindowsResultKeepsOrdinaryResolverOnProvenanceInterface(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{
		{
			up:             true,
			interfaceIndex: 4,
			ipv4Metric:     50,
			servers:        []windowsServerSnapshot{{address: netip.MustParseAddr("192.0.2.53")}},
		},
		{up: true, interfaceIndex: 5, ipv4Metric: 1},
	}
	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("0.0.0.0/0"), interfaceIndex: 4, metric: 20},
		{destination: netip.MustParsePrefix("192.0.2.53/32"), interfaceIndex: 5, metric: 0},
	}
	result, err := buildWindowsResult(context.Background(), adapters, routes, mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	resolver := result.Resolvers[0]
	if resolver.InterfaceIndex != 4 || resolver.RouteInterfaceIndex != 4 || effectiveMetric(resolver) != 70 {
		t.Fatalf("ordinary resolver route = %#v", resolver)
	}
}

func TestBuildWindowsResultFiltersSyntheticSiteLocalDNS(t *testing.T) {
	t.Parallel()

	adapters := []windowsAdapterSnapshot{{
		up:                 true,
		interfaceIndex:     4,
		ipv6InterfaceIndex: 6,
		servers: []windowsServerSnapshot{
			{address: netip.MustParseAddr("fec0::ffff")},
			{address: netip.MustParseAddr("192.0.2.53")},
		},
	}}
	result, err := buildWindowsResult(context.Background(), adapters, defaultWindowsRoutes(adapters), mustSystemDNSLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolvers) != 1 || result.Resolvers[0].Endpoint.Address().String() != "192.0.2.53" {
		t.Fatalf("resolvers = %v", resolverAddresses(result.Resolvers))
	}
}

func TestBestWindowsRouteUsesLongestPrefixThenMetric(t *testing.T) {
	t.Parallel()

	routes := []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("0.0.0.0/0"), interfaceIndex: 4, metric: 1, discoveryIndex: 0},
		{destination: netip.MustParsePrefix("192.0.2.0/24"), interfaceIndex: 4, metric: 50, discoveryIndex: 1},
		{destination: netip.MustParsePrefix("192.0.2.0/24"), interfaceIndex: 4, metric: 20, discoveryIndex: 2},
		{destination: netip.MustParsePrefix("192.0.2.0/24"), interfaceIndex: 5, metric: 0, discoveryIndex: 3},
	}
	metrics := map[windowsInterfaceMetricKey]uint32{
		{addressBits: 32, interfaceIndex: 4}: 10,
		{addressBits: 32, interfaceIndex: 5}: 1,
	}
	route, found, err := bestWindowsRoute(netip.MustParseAddr("192.0.2.53"), 4, routes, metrics)
	if err != nil {
		t.Fatal(err)
	}
	if !found || route.route.destination.Bits() != 24 || route.route.metric != 20 || route.interfaceMetric != 10 {
		t.Fatalf("best route = %#v, %v", route, found)
	}
}

func TestBuildWindowsResultBoundsRouteSnapshot(t *testing.T) {
	t.Parallel()

	limits := mustSystemDNSLimits(t)
	limits.MaxWindowsRoutes = 1
	_, err := buildWindowsResult(context.Background(), nil, []windowsRouteSnapshot{
		{destination: netip.MustParsePrefix("0.0.0.0/0")},
		{destination: netip.MustParsePrefix("::/0")},
	}, limits)
	if !IsErrorCode(err, ErrorTooMany) {
		t.Fatalf("error = %v", err)
	}
}

func defaultWindowsRoutes(adapters []windowsAdapterSnapshot) []windowsRouteSnapshot {
	routes := make([]windowsRouteSnapshot, 0)
	type routeKey struct {
		prefix         string
		interfaceIndex uint32
	}
	seen := make(map[routeKey]struct{})
	for _, adapter := range adapters {
		for _, server := range adapter.servers {
			if !server.address.IsValid() || isWindowsSyntheticDNS(server.address) {
				continue
			}
			interfaceIndex := adapter.interfaceIndex
			prefix := netip.MustParsePrefix("0.0.0.0/0")
			if server.address.Is6() {
				interfaceIndex = adapter.ipv6InterfaceIndex
				if interfaceIndex == 0 {
					interfaceIndex = adapter.interfaceIndex
				}
				prefix = netip.MustParsePrefix("::/0")
			}
			key := routeKey{prefix: prefix.String(), interfaceIndex: interfaceIndex}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			routes = append(routes, windowsRouteSnapshot{destination: prefix, interfaceIndex: interfaceIndex, discoveryIndex: len(routes)})
		}
	}
	return routes
}

func mustSystemDNSLimits(t *testing.T) Limits {
	t.Helper()
	limits, err := normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return limits
}
