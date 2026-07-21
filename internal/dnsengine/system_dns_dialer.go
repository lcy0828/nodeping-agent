package dnsengine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
)

func (e *Engine) dialEndpoint(ctx context.Context, network string, endpoint resolvedEndpoint) (net.Conn, error) {
	dialer := e.dialer
	if endpoint.systemPlatform != "" {
		var err error
		dialer, err = prepareSystemDNSDialer(dialer, endpoint)
		if err != nil {
			return nil, err
		}
	}
	return dialer.DialContext(ctx, network, endpoint.dialAddress)
}

func systemDNSDialerWithControl(
	dialer net.Dialer,
	bind func(network string, raw syscall.RawConn) error,
) net.Dialer {
	originalControlContext := dialer.ControlContext
	originalControl := dialer.Control
	// ControlContext takes precedence in net.Dialer. Preserve that exact
	// behavior while ensuring the system DNS binding runs last.
	dialer.Control = nil
	dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if originalControlContext != nil {
			if err := originalControlContext(ctx, network, address, raw); err != nil {
				return err
			}
		} else if originalControl != nil {
			if err := originalControl(network, address, raw); err != nil {
				return err
			}
		}
		return bind(network, raw)
	}
	return dialer
}

func requireSystemDNSNetworkFamily(network string, address net.IP) error {
	isIPv4 := address.To4() != nil
	isIPv6 := !isIPv4 && address.To16() != nil
	switch {
	case strings.HasSuffix(network, "4") && isIPv4:
		return nil
	case strings.HasSuffix(network, "6") && isIPv6:
		return nil
	default:
		return fmt.Errorf("%w: socket network %q does not match trusted system resolver address", ErrInvalidEndpoint, network)
	}
}
