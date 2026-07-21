//go:build darwin

package dnsengine

import (
	"fmt"
	"net"
	"syscall"

	"nodeping/internal/systemdns"

	"golang.org/x/sys/unix"
)

type darwinSocketBinding struct {
	level  int
	option int
	value  int
}

func prepareSystemDNSDialer(dialer net.Dialer, endpoint resolvedEndpoint) (net.Dialer, error) {
	if endpoint.systemPlatform != systemdns.PlatformDarwin {
		return net.Dialer{}, fmt.Errorf("%w: trusted system resolver platform %q cannot be dialed on macOS", ErrInvalidEndpoint, endpoint.systemPlatform)
	}
	if endpoint.systemBindInterfaceIndex == 0 {
		return dialer, nil
	}
	binding, err := darwinSystemDNSBinding(endpoint.connectIP, endpoint.systemBindInterfaceIndex)
	if err != nil {
		return net.Dialer{}, err
	}
	return systemDNSDialerWithControl(dialer, func(network string, raw syscall.RawConn) error {
		if err := requireSystemDNSNetworkFamily(network, endpoint.connectIP); err != nil {
			return err
		}
		return applyDarwinSystemDNSBinding(raw, binding)
	}), nil
}

func darwinSystemDNSBinding(address net.IP, interfaceIndex uint32) (darwinSocketBinding, error) {
	if interfaceIndex == 0 {
		return darwinSocketBinding{}, fmt.Errorf("%w: macOS system resolver bind interface is zero", ErrInvalidEndpoint)
	}
	if address.To4() != nil {
		return darwinSocketBinding{level: unix.IPPROTO_IP, option: unix.IP_BOUND_IF, value: int(interfaceIndex)}, nil
	}
	if address.To16() != nil {
		return darwinSocketBinding{level: unix.IPPROTO_IPV6, option: unix.IPV6_BOUND_IF, value: int(interfaceIndex)}, nil
	}
	return darwinSocketBinding{}, fmt.Errorf("%w: macOS system resolver address is invalid", ErrInvalidEndpoint)
}

func applyDarwinSystemDNSBinding(raw syscall.RawConn, binding darwinSocketBinding) error {
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), binding.level, binding.option, binding.value)
	}); err != nil {
		return err
	}
	return socketErr
}
