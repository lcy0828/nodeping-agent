//go:build linux

package dnsengine

import (
	"fmt"
	"net"

	"nodeping/internal/systemdns"
)

func prepareSystemDNSDialer(dialer net.Dialer, endpoint resolvedEndpoint) (net.Dialer, error) {
	if endpoint.systemPlatform != systemdns.PlatformLinux {
		return net.Dialer{}, fmt.Errorf("%w: trusted system resolver platform %q cannot be dialed on Linux", ErrInvalidEndpoint, endpoint.systemPlatform)
	}
	if endpoint.systemBindInterfaceIndex != 0 {
		return net.Dialer{}, fmt.Errorf("%w: Linux resolv.conf resolver unexpectedly carries a bind interface", ErrInvalidEndpoint)
	}
	return dialer, nil
}
