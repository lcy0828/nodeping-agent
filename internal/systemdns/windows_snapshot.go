package systemdns

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"unicode"
	"unicode/utf8"
)

type windowsServerSnapshot struct {
	address netip.Addr
	scopeID uint32
}

type windowsAdapterSnapshot struct {
	up                 bool
	interfaceIndex     uint32
	ipv6InterfaceIndex uint32
	interfaceName      string
	dnsSuffix          string
	dnsSuffixes        []string
	ipv4Metric         uint32
	ipv6Metric         uint32
	servers            []windowsServerSnapshot
}

type windowsRouteSnapshot struct {
	destination    netip.Prefix
	interfaceIndex uint32
	metric         uint32
	loopback       bool
	discoveryIndex int
}

type windowsInterfaceMetricKey struct {
	addressBits    int
	interfaceIndex uint32
}

type windowsRouteSelection struct {
	route           windowsRouteSnapshot
	interfaceMetric uint32
}

var windowsSyntheticDNSPrefix = netip.MustParsePrefix("fec0::/10")

func buildWindowsResult(ctx context.Context, adapters []windowsAdapterSnapshot, routes []windowsRouteSnapshot, limits Limits) (DiscoveryResult, error) {
	if len(adapters) > limits.MaxWindowsAdapters {
		return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_adapters", "adapters", 0, "adapter count exceeds the configured limit", nil)
	}
	if len(routes) > limits.MaxWindowsRoutes {
		return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_routes", "routes", 0, "route count exceeds the configured limit", nil)
	}
	result := DiscoveryResult{
		Platform: PlatformWindows,
		Options: ResolverOptions{
			TimeoutSeconds: defaultTimeoutSeconds,
			Attempts:       defaultAttempts,
		},
	}
	interfaceMetrics, err := windowsInterfaceMetrics(adapters)
	if err != nil {
		return DiscoveryResult{}, discoveryError(ErrorSystemAPI, PlatformWindows, "parse_adapters", "interface_metric", 0, err.Error(), err)
	}
	for adapterIndex, adapter := range adapters {
		if err := ctx.Err(); err != nil {
			return DiscoveryResult{}, contextDiscoveryError(PlatformWindows, "parse_adapters", err)
		}
		if !adapter.up || len(adapter.servers) == 0 {
			continue
		}
		if len(adapter.servers) > limits.MaxDNSServersPerAdapter {
			return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_adapters", "dns_servers", 0, "DNS server count exceeds the per-adapter limit", nil)
		}
		if adapter.interfaceName != "" {
			if err := validateWindowsInterfaceName(adapter.interfaceName, limits.MaxInterfaceNameBytes); err != nil {
				return DiscoveryResult{}, discoveryError(ErrorMalformed, PlatformWindows, "parse_adapters", "interface_name", 0, err.Error(), err)
			}
		}

		scopeDomain := ""
		if adapter.dnsSuffix != "" {
			normalized, err := normalizeName(adapter.dnsSuffix, false)
			if err != nil {
				return DiscoveryResult{}, discoveryError(ErrorMalformed, PlatformWindows, "parse_adapters", "dns_suffix", 0, err.Error(), err)
			}
			scopeDomain = normalized
		}
		search := make([]string, 0, len(adapter.dnsSuffixes)+1)
		if scopeDomain != "" {
			search = append(search, scopeDomain)
		}
		for _, suffix := range adapter.dnsSuffixes {
			normalized, err := normalizeName(suffix, false)
			if err != nil {
				return DiscoveryResult{}, discoveryError(ErrorMalformed, PlatformWindows, "parse_adapters", "dns_suffix", 0, err.Error(), err)
			}
			search = appendUniqueName(search, normalized)
			if len(search) > limits.MaxSearchDomains {
				return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_adapters", "dns_suffix", 0, "adapter search suffix count exceeds the configured limit", nil)
			}
		}
		for _, suffix := range search {
			result.SearchDomains = appendUniqueName(result.SearchDomains, suffix)
			if len(result.SearchDomains) > limits.MaxSearchDomains {
				return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_adapters", "dns_suffix", 0, "aggregate search suffix count exceeds the configured limit", nil)
			}
		}

		seen := make(map[string]struct{}, len(adapter.servers))
		for _, server := range adapter.servers {
			if isWindowsSyntheticDNS(server.address) {
				continue
			}
			endpoint, interfaceIndex, err := windowsEndpoint(server, adapter)
			if err != nil {
				return DiscoveryResult{}, discoveryError(ErrorMalformed, PlatformWindows, "parse_adapters", "dns_server", 0, err.Error(), err)
			}
			key := endpointKey(endpoint)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			routeSelection, found, routeErr := bestWindowsRoute(endpoint.address, interfaceIndex, routes, interfaceMetrics)
			if routeErr != nil {
				return DiscoveryResult{}, discoveryError(
					ErrorSystemAPI,
					PlatformWindows,
					"parse_routes",
					"route_selection",
					0,
					routeErr.Error(),
					routeErr,
				)
			}
			if !found {
				routeRequirement := fmt.Sprintf("on interface %d", interfaceIndex)
				if endpoint.address.IsLoopback() {
					routeRequirement = "through a local loopback route"
				}
				return DiscoveryResult{}, discoveryError(
					ErrorSystemAPI,
					PlatformWindows,
					"parse_routes",
					"dns_server",
					0,
					fmt.Sprintf("no route %s reaches DNS server %s", routeRequirement, endpoint.address),
					nil,
				)
			}
			route := routeSelection.route
			if len(result.Resolvers) >= limits.MaxResolvers {
				return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformWindows, "parse_adapters", "dns_server", 0, "resolver count exceeds the configured limit", nil)
			}
			result.Resolvers = append(result.Resolvers, Resolver{
				Endpoint:                endpoint,
				Source:                  SourceWindowsAdapters,
				ConnectionSuffix:        scopeDomain,
				SearchDomains:           append([]string(nil), search...),
				InterfaceIndex:          interfaceIndex,
				RouteInterfaceIndex:     route.interfaceIndex,
				InterfaceName:           adapter.interfaceName,
				IPv4Metric:              adapter.ipv4Metric,
				IPv6Metric:              adapter.ipv6Metric,
				MetricSet:               true,
				RouteInterfaceMetric:    routeSelection.interfaceMetric,
				RouteInterfaceMetricSet: true,
				RouteMetric:             route.metric,
				RouteMetricSet:          true,
				discoveryIndex:          len(result.Resolvers),
				groupIndex:              adapterIndex,
			})
		}
	}
	if len(result.Resolvers) == 0 {
		return DiscoveryResult{}, discoveryError(ErrorNoResolvers, PlatformWindows, "parse_adapters", "dns_server", 0, "no up adapter reports a usable DNS server", nil)
	}
	return result, nil
}

func isWindowsSyntheticDNS(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.WithZone("").Unmap()
	return address.Is6() && windowsSyntheticDNSPrefix.Contains(address)
}

func windowsInterfaceMetrics(adapters []windowsAdapterSnapshot) (map[windowsInterfaceMetricKey]uint32, error) {
	metrics := make(map[windowsInterfaceMetricKey]uint32, len(adapters)*2)
	for _, adapter := range adapters {
		if !adapter.up {
			continue
		}
		if adapter.interfaceIndex != 0 {
			key := windowsInterfaceMetricKey{addressBits: 32, interfaceIndex: adapter.interfaceIndex}
			if err := addWindowsInterfaceMetric(metrics, key, adapter.ipv4Metric); err != nil {
				return nil, err
			}
		}
		ipv6InterfaceIndex := adapter.ipv6InterfaceIndex
		if ipv6InterfaceIndex == 0 {
			ipv6InterfaceIndex = adapter.interfaceIndex
		}
		if ipv6InterfaceIndex != 0 {
			key := windowsInterfaceMetricKey{addressBits: 128, interfaceIndex: ipv6InterfaceIndex}
			if err := addWindowsInterfaceMetric(metrics, key, adapter.ipv6Metric); err != nil {
				return nil, err
			}
		}
	}
	return metrics, nil
}

func addWindowsInterfaceMetric(metrics map[windowsInterfaceMetricKey]uint32, key windowsInterfaceMetricKey, metric uint32) error {
	if existing, found := metrics[key]; found && existing != metric {
		return fmt.Errorf("interface %d has conflicting IPv%d metrics", key.interfaceIndex, key.addressBits)
	}
	metrics[key] = metric
	return nil
}

func bestWindowsRoute(address netip.Addr, interfaceIndex uint32, routes []windowsRouteSnapshot, interfaceMetrics map[windowsInterfaceMetricKey]uint32) (windowsRouteSelection, bool, error) {
	address = address.WithZone("").Unmap()
	loopbackAddress := address.IsLoopback()
	maximumPrefixBits := -1
	for _, route := range routes {
		prefix := route.destination.Masked()
		if !windowsRouteEligible(address, interfaceIndex, loopbackAddress, route, prefix) {
			continue
		}
		if prefix.Bits() > maximumPrefixBits {
			maximumPrefixBits = prefix.Bits()
		}
	}
	if maximumPrefixBits < 0 {
		return windowsRouteSelection{}, false, nil
	}

	var best windowsRouteSelection
	found := false
	for _, route := range routes {
		prefix := route.destination.Masked()
		if !windowsRouteEligible(address, interfaceIndex, loopbackAddress, route, prefix) || prefix.Bits() != maximumPrefixBits {
			continue
		}
		metricKey := windowsInterfaceMetricKey{addressBits: address.BitLen(), interfaceIndex: route.interfaceIndex}
		interfaceMetric, metricFound := interfaceMetrics[metricKey]
		if !metricFound {
			return windowsRouteSelection{}, false, fmt.Errorf("interface metric is unavailable for IPv%d route interface %d", address.BitLen(), route.interfaceIndex)
		}
		candidateMetric := uint64(interfaceMetric) + uint64(route.metric)
		bestMetric := uint64(best.interfaceMetric) + uint64(best.route.metric)
		if !found || candidateMetric < bestMetric ||
			(candidateMetric == bestMetric && route.discoveryIndex < best.route.discoveryIndex) {
			route.destination = prefix
			best = windowsRouteSelection{route: route, interfaceMetric: interfaceMetric}
			found = true
		}
	}
	if loopbackAddress && found && !best.route.loopback {
		return windowsRouteSelection{}, false, fmt.Errorf("best route for loopback DNS server uses non-loopback interface %d", best.route.interfaceIndex)
	}
	return best, found, nil
}

func windowsRouteEligible(address netip.Addr, interfaceIndex uint32, loopbackAddress bool, route windowsRouteSnapshot, prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Addr().BitLen() != address.BitLen() || !prefix.Contains(address) {
		return false
	}
	if loopbackAddress {
		// Loopback is configured on a provenance adapter but dialed through the
		// host's globally selected route. The winning route is verified above.
		return true
	}
	return route.interfaceIndex == interfaceIndex
}

func windowsEndpoint(server windowsServerSnapshot, adapter windowsAdapterSnapshot) (Endpoint, uint32, error) {
	address := server.address
	if !address.IsValid() {
		return Endpoint{}, 0, fmt.Errorf("DNS server address is invalid")
	}
	zone := address.Zone()
	address = address.WithZone("").Unmap()
	interfaceIndex := adapter.interfaceIndex
	if address.Is6() {
		interfaceIndex = adapter.ipv6InterfaceIndex
		if interfaceIndex == 0 {
			interfaceIndex = adapter.interfaceIndex
		}
	}
	if interfaceIndex == 0 {
		return Endpoint{}, 0, fmt.Errorf("DNS server adapter interface index is zero")
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		scopeID := server.scopeID
		if scopeID == 0 && zone != "" {
			parsed, err := strconv.ParseUint(zone, 10, 32)
			if err != nil {
				return Endpoint{}, 0, fmt.Errorf("Windows IPv6 zone must be a numeric scope ID")
			}
			scopeID = uint32(parsed)
		}
		if scopeID == 0 {
			scopeID = interfaceIndex
		}
		if scopeID == 0 {
			return Endpoint{}, 0, fmt.Errorf("IPv6 link-local DNS server has no scope ID")
		}
		if interfaceIndex != 0 && scopeID != interfaceIndex {
			return Endpoint{}, 0, fmt.Errorf("IPv6 link-local DNS server scope ID does not match its adapter")
		}
		if zone != "" && zone != strconv.FormatUint(uint64(scopeID), 10) {
			return Endpoint{}, 0, fmt.Errorf("IPv6 link-local DNS server has conflicting scope IDs")
		}
		zone = strconv.FormatUint(uint64(scopeID), 10)
	} else if server.scopeID != 0 || zone != "" {
		return Endpoint{}, 0, fmt.Errorf("scope ID is only valid for an IPv6 link-local DNS server")
	}
	raw := address.String()
	if zone != "" {
		raw += "%" + zone
	}
	endpoint, err := parseSystemEndpoint(raw, "")
	return endpoint, interfaceIndex, err
}

func validateWindowsInterfaceName(value string, maxBytes int) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("interface name is not valid UTF-8")
	}
	if len(value) > maxBytes {
		return fmt.Errorf("interface name exceeds the byte limit")
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return fmt.Errorf("interface name contains a control character")
		}
	}
	return nil
}
