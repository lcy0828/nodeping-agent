//go:build !darwin && !linux && !windows

package dnsengine

import (
	"fmt"
	"net"
)

func prepareSystemDNSDialer(net.Dialer, resolvedEndpoint) (net.Dialer, error) {
	return net.Dialer{}, fmt.Errorf("%w: trusted system DNS dialing is unsupported on this platform", ErrInvalidEndpoint)
}
