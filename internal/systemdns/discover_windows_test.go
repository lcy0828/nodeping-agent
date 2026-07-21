//go:build windows

package systemdns

import (
	"context"
	"net/netip"
	"testing"
)

func TestWindowsNativeSourceClassification(t *testing.T) {
	t.Parallel()

	if !nativeDiscoverySource(Discoverer{}) {
		t.Fatal("zero-value Windows discoverer is not native")
	}
	if nativeDiscoverySource(Discoverer{windowsAdapters: func(context.Context, Limits) ([]windowsAdapterSnapshot, error) { return nil, nil }}) {
		t.Fatal("injected adapter provider was classified as native")
	}
	if nativeDiscoverySource(Discoverer{windowsRoutes: func(context.Context, Limits) ([]windowsRouteSnapshot, error) { return nil, nil }}) {
		t.Fatal("injected route provider was classified as native")
	}
}

func TestWindowsInjectedSnapshotCannotEnterTrustedSelection(t *testing.T) {
	t.Parallel()

	discoverer := Discoverer{
		windowsAdapters: func(context.Context, Limits) ([]windowsAdapterSnapshot, error) {
			return []windowsAdapterSnapshot{{
				up: true, interfaceIndex: 10, ipv6InterfaceIndex: 11, ipv6Metric: 5,
				servers: []windowsServerSnapshot{{address: netip.MustParseAddr("fe80::53"), scopeID: 11}},
			}}, nil
		},
		windowsRoutes: func(context.Context, Limits) ([]windowsRouteSnapshot, error) {
			return []windowsRouteSnapshot{{
				destination: netip.MustParsePrefix("fe80::/10"), interfaceIndex: 11, metric: 1,
			}}, nil
		},
	}
	result, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Resolvers) != 1 || result.Resolvers[0].Endpoint.Zone() != "11" {
		t.Fatalf("injected Windows resolver = %#v", result.Resolvers)
	}
	if result.Resolvers[0].Endpoint.IsTrustedSystem() {
		t.Fatal("injected Windows snapshot granted native trust")
	}
	if _, err := result.SelectTrusted(Selection{Name: "example.com"}); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("injected resolver entered trusted selection: %v", err)
	}
}
