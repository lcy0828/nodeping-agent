package systemdns

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
)

const snapshotProvenanceDomain = "nodeping.systemdns.native-snapshot.v1\x00"

type snapshotEndpointProjection struct {
	Address    string   `json:"address"`
	Zone       string   `json:"zone"`
	Port       uint16   `json:"port"`
	Provenance [32]byte `json:"provenance"`
}

type snapshotResolverProjection struct {
	Endpoint snapshotEndpointProjection `json:"endpoint"`
	Source   Source                     `json:"source"`

	ScopeDomain   string   `json:"scope_domain"`
	SearchDomains []string `json:"search_domains"`
	Scoped        bool     `json:"scoped"`

	Order    uint32 `json:"order"`
	OrderSet bool   `json:"order_set"`

	InterfaceIndex      uint32   `json:"interface_index"`
	RouteInterfaceIndex uint32   `json:"route_interface_index"`
	InterfaceName       string   `json:"interface_name"`
	Flags               []string `json:"flags"`
	NativeOptions       []string `json:"native_options"`
	ConnectionSuffix    string   `json:"connection_suffix"`

	TimeoutSeconds           uint32 `json:"timeout_seconds"`
	ConfiguredTimeoutSeconds uint32 `json:"configured_timeout_seconds"`
	TimeoutConfigured        bool   `json:"timeout_configured"`

	IPv4Metric uint32 `json:"ipv4_metric"`
	IPv6Metric uint32 `json:"ipv6_metric"`
	MetricSet  bool   `json:"metric_set"`

	RouteInterfaceMetric    uint32 `json:"route_interface_metric"`
	RouteInterfaceMetricSet bool   `json:"route_interface_metric_set"`
	RouteMetric             uint32 `json:"route_metric"`
	RouteMetricSet          bool   `json:"route_metric_set"`

	DiscoveryIndex int `json:"discovery_index"`
	GroupIndex     int `json:"group_index"`
}

type snapshotUnsupportedRouteProjection struct {
	ScopeDomain   string   `json:"scope_domain"`
	SearchDomains []string `json:"search_domains"`
	Scoped        bool     `json:"scoped"`

	Order    uint32 `json:"order"`
	OrderSet bool   `json:"order_set"`

	InterfaceIndex uint32   `json:"interface_index"`
	InterfaceName  string   `json:"interface_name"`
	Flags          []string `json:"flags"`
	NativeOptions  []string `json:"native_options"`

	Port                     uint16 `json:"port"`
	TimeoutSeconds           uint32 `json:"timeout_seconds"`
	ConfiguredTimeoutSeconds uint32 `json:"configured_timeout_seconds"`
	TimeoutConfigured        bool   `json:"timeout_configured"`
	Reason                   string `json:"reason"`

	DiscoveryIndex int `json:"discovery_index"`
	GroupIndex     int `json:"group_index"`
}

type snapshotProjection struct {
	Platform          Platform                             `json:"platform"`
	Resolvers         []snapshotResolverProjection         `json:"resolvers"`
	UnsupportedRoutes []snapshotUnsupportedRouteProjection `json:"unsupported_routes"`
	Domain            string                               `json:"domain"`
	SearchDomains     []string                             `json:"search_domains"`
	Options           ResolverOptions                      `json:"options"`
}

func sealSnapshot(result *DiscoveryResult) error {
	digest, err := snapshotDigest(*result)
	if err != nil {
		return err
	}
	result.provenance = digest
	return nil
}

func snapshotProvenanceValid(result DiscoveryResult) bool {
	if result.provenance == ([32]byte{}) {
		return false
	}
	expected, err := snapshotDigest(result)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(result.provenance[:], expected[:]) == 1
}

func snapshotDigest(result DiscoveryResult) ([32]byte, error) {
	projection := snapshotProjection{
		Platform:          result.Platform,
		Resolvers:         make([]snapshotResolverProjection, len(result.Resolvers)),
		UnsupportedRoutes: make([]snapshotUnsupportedRouteProjection, len(result.UnsupportedRoutes)),
		Domain:            result.Domain,
		SearchDomains:     append([]string(nil), result.SearchDomains...),
		Options:           result.Options,
	}
	for index, resolver := range result.Resolvers {
		projection.Resolvers[index] = snapshotResolverProjection{
			Endpoint: snapshotEndpointProjection{
				Address: resolver.Endpoint.address.String(), Zone: resolver.Endpoint.zone,
				Port: resolver.Endpoint.port, Provenance: resolver.Endpoint.provenance,
			},
			Source: resolver.Source,

			ScopeDomain: resolver.ScopeDomain, SearchDomains: append([]string(nil), resolver.SearchDomains...), Scoped: resolver.Scoped,
			Order: resolver.Order, OrderSet: resolver.OrderSet,
			InterfaceIndex: resolver.InterfaceIndex, RouteInterfaceIndex: resolver.RouteInterfaceIndex,
			InterfaceName: resolver.InterfaceName, Flags: append([]string(nil), resolver.Flags...),
			NativeOptions: append([]string(nil), resolver.NativeOptions...), ConnectionSuffix: resolver.ConnectionSuffix,
			TimeoutSeconds: resolver.TimeoutSeconds, ConfiguredTimeoutSeconds: resolver.ConfiguredTimeoutSeconds,
			TimeoutConfigured: resolver.TimeoutConfigured,
			IPv4Metric:        resolver.IPv4Metric, IPv6Metric: resolver.IPv6Metric, MetricSet: resolver.MetricSet,
			RouteInterfaceMetric: resolver.RouteInterfaceMetric, RouteInterfaceMetricSet: resolver.RouteInterfaceMetricSet,
			RouteMetric: resolver.RouteMetric, RouteMetricSet: resolver.RouteMetricSet,
			DiscoveryIndex: resolver.discoveryIndex, GroupIndex: resolver.groupIndex,
		}
	}
	for index, route := range result.UnsupportedRoutes {
		projection.UnsupportedRoutes[index] = snapshotUnsupportedRouteProjection{
			ScopeDomain: route.ScopeDomain, SearchDomains: append([]string(nil), route.SearchDomains...), Scoped: route.Scoped,
			Order: route.Order, OrderSet: route.OrderSet,
			InterfaceIndex: route.InterfaceIndex, InterfaceName: route.InterfaceName,
			Flags: append([]string(nil), route.Flags...), NativeOptions: append([]string(nil), route.NativeOptions...),
			Port: route.Port, TimeoutSeconds: route.TimeoutSeconds,
			ConfiguredTimeoutSeconds: route.ConfiguredTimeoutSeconds, TimeoutConfigured: route.TimeoutConfigured,
			Reason: route.Reason, DiscoveryIndex: route.discoveryIndex, GroupIndex: route.groupIndex,
		}
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte(snapshotProvenanceDomain), raw...)), nil
}
