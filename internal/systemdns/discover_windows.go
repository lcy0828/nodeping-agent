//go:build windows

package systemdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const initialWindowsAdapterBuffer = 15_000

func discoverPlatform(ctx context.Context, discoverer Discoverer, limits Limits) (DiscoveryResult, error) {
	provider := discoverer.windowsAdapters
	if provider == nil {
		provider = loadWindowsAdapterSnapshots
	}
	adapters, err := provider(ctx, limits)
	if err != nil {
		if ctx.Err() != nil {
			return DiscoveryResult{}, contextDiscoveryError(PlatformWindows, "get_adapters_addresses", ctx.Err())
		}
		if errors.Is(err, errOutputLimit) {
			return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformWindows, "get_adapters_addresses", "buffer", 0, "adapter data exceeds the byte limit", err)
		}
		var discoveryErr *DiscoveryError
		if errors.As(err, &discoveryErr) {
			return DiscoveryResult{}, err
		}
		return DiscoveryResult{}, discoveryError(ErrorSystemAPI, PlatformWindows, "get_adapters_addresses", "api", 0, "GetAdaptersAddresses failed", err)
	}
	routeProvider := discoverer.windowsRoutes
	if routeProvider == nil {
		routeProvider = loadWindowsRouteSnapshots
	}
	routes, err := routeProvider(ctx, limits)
	if err != nil {
		if ctx.Err() != nil {
			return DiscoveryResult{}, contextDiscoveryError(PlatformWindows, "get_ip_forward_table", ctx.Err())
		}
		var discoveryErr *DiscoveryError
		if errors.As(err, &discoveryErr) {
			return DiscoveryResult{}, err
		}
		return DiscoveryResult{}, discoveryError(ErrorSystemAPI, PlatformWindows, "get_ip_forward_table", "api", 0, "GetIpForwardTable2 failed", err)
	}
	return buildWindowsResult(ctx, adapters, routes, limits)
}

func nativeDiscoverySource(discoverer Discoverer) bool {
	return discoverer.windowsAdapters == nil && discoverer.windowsRoutes == nil
}

func loadWindowsAdapterSnapshots(ctx context.Context, limits Limits) ([]windowsAdapterSnapshot, error) {
	size := uint32(initialWindowsAdapterBuffer)
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size == 0 || uint64(size) > uint64(limits.MaxWindowsBufferBytes) {
			return nil, errOutputLimit
		}
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		required := size
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &required)
		if err == nil {
			if required == 0 {
				return nil, nil
			}
			adapters, captureErr := captureWindowsAdapters(ctx, first, limits)
			runtime.KeepAlive(buffer)
			return adapters, captureErr
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
		if required <= size {
			return nil, fmt.Errorf("GetAdaptersAddresses returned a non-growing buffer requirement")
		}
		size = required
	}
	return nil, fmt.Errorf("GetAdaptersAddresses buffer size did not stabilize")
}

func captureWindowsAdapters(ctx context.Context, first *windows.IpAdapterAddresses, limits Limits) ([]windowsAdapterSnapshot, error) {
	adapters := make([]windowsAdapterSnapshot, 0)
	adapterCount := 0
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		adapterCount++
		if adapterCount > limits.MaxWindowsAdapters {
			return nil, discoveryError(ErrorTooMany, PlatformWindows, "get_adapters_addresses", "adapters", 0, "adapter count exceeds the configured limit", nil)
		}
		snapshot := windowsAdapterSnapshot{
			up:                 adapter.OperStatus == windows.IfOperStatusUp,
			interfaceIndex:     adapter.IfIndex,
			ipv6InterfaceIndex: adapter.Ipv6IfIndex,
			interfaceName:      windows.UTF16PtrToString(adapter.FriendlyName),
			dnsSuffix:          windows.UTF16PtrToString(adapter.DnsSuffix),
			ipv4Metric:         adapter.Ipv4Metric,
			ipv6Metric:         adapter.Ipv6Metric,
		}
		if !snapshot.up {
			continue
		}
		serverCount := 0
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			serverCount++
			if serverCount > limits.MaxDNSServersPerAdapter {
				return nil, discoveryError(ErrorTooMany, PlatformWindows, "get_adapters_addresses", "dns_servers", 0, "DNS server count exceeds the per-adapter limit", nil)
			}
			address, scopeID, err := captureWindowsSocketAddress(server.Address)
			if err != nil {
				return nil, discoveryError(ErrorMalformed, PlatformWindows, "get_adapters_addresses", "dns_server", 0, err.Error(), err)
			}
			if isWindowsSyntheticDNS(address) {
				continue
			}
			snapshot.servers = append(snapshot.servers, windowsServerSnapshot{address: address, scopeID: scopeID})
		}
		if len(snapshot.servers) != 0 {
			suffixCount := 0
			for suffix := adapter.FirstDnsSuffix; suffix != nil; suffix = suffix.Next {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				suffixCount++
				if suffixCount > limits.MaxSearchDomains {
					return nil, discoveryError(ErrorTooMany, PlatformWindows, "get_adapters_addresses", "dns_suffix", 0, "adapter search suffix count exceeds the configured limit", nil)
				}
				value := windows.UTF16ToString(suffix.String[:])
				if value != "" {
					snapshot.dnsSuffixes = append(snapshot.dnsSuffixes, value)
				}
			}
		}
		// Keep up adapters without DNS servers: a resolver configured on another
		// adapter may be loopback, whose actual dial route uses this adapter's
		// interface metric.
		adapters = append(adapters, snapshot)
	}
	return adapters, nil
}

func loadWindowsRouteSnapshots(ctx context.Context, limits Limits) ([]windowsRouteSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, fmt.Errorf("GetIpForwardTable2 returned a nil table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if uint64(table.NumEntries) > uint64(limits.MaxWindowsRoutes) {
		return nil, discoveryError(ErrorTooMany, PlatformWindows, "get_ip_forward_table", "routes", 0, "route count exceeds the configured limit", nil)
	}
	routes := make([]windowsRouteSnapshot, 0, int(table.NumEntries))
	for index, row := range table.Rows() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		address, err := captureWindowsRawAddress(row.DestinationPrefix.Prefix)
		if err != nil {
			return nil, discoveryError(ErrorMalformed, PlatformWindows, "get_ip_forward_table", "destination_prefix", 0, err.Error(), err)
		}
		maximumBits := 128
		if address.Is4() {
			maximumBits = 32
		}
		bits := int(row.DestinationPrefix.PrefixLength)
		if bits > maximumBits {
			return nil, discoveryError(ErrorMalformed, PlatformWindows, "get_ip_forward_table", "prefix_length", 0, "route prefix length exceeds the address family width", nil)
		}
		if row.InterfaceIndex == 0 {
			return nil, discoveryError(ErrorMalformed, PlatformWindows, "get_ip_forward_table", "interface_index", 0, "route interface index is zero", nil)
		}
		routes = append(routes, windowsRouteSnapshot{
			destination:    netip.PrefixFrom(address, bits).Masked(),
			interfaceIndex: row.InterfaceIndex,
			metric:         row.Metric,
			loopback:       row.Loopback != 0,
			discoveryIndex: index,
		})
	}
	return routes, nil
}

func captureWindowsRawAddress(raw windows.RawSockaddrInet) (netip.Addr, error) {
	switch raw.Family {
	case windows.AF_INET:
		address := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
		return netip.AddrFrom4(address.Addr), nil
	case windows.AF_INET6:
		address := (*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		return netip.AddrFrom16(address.Addr), nil
	default:
		return netip.Addr{}, fmt.Errorf("route uses unsupported family %d", raw.Family)
	}
}

func captureWindowsSocketAddress(socket windows.SocketAddress) (netip.Addr, uint32, error) {
	if socket.Sockaddr == nil {
		return netip.Addr{}, 0, fmt.Errorf("DNS server socket address is nil")
	}
	if socket.SockaddrLength < 0 {
		return netip.Addr{}, 0, fmt.Errorf("DNS server socket address has a negative length")
	}
	switch socket.Sockaddr.Addr.Family {
	case windows.AF_INET:
		if uintptr(socket.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet4{}) {
			return netip.Addr{}, 0, fmt.Errorf("IPv4 DNS server socket address is truncated")
		}
		raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(socket.Sockaddr))
		return netip.AddrFrom4(raw.Addr), 0, nil
	case windows.AF_INET6:
		if uintptr(socket.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet6{}) {
			return netip.Addr{}, 0, fmt.Errorf("IPv6 DNS server socket address is truncated")
		}
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(socket.Sockaddr))
		return netip.AddrFrom16(raw.Addr), raw.Scope_id, nil
	default:
		return netip.Addr{}, 0, fmt.Errorf("DNS server socket address uses unsupported family %d", socket.Sockaddr.Addr.Family)
	}
}
