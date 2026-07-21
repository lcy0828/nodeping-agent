//go:build windows

package dnsengine

import (
	"fmt"
	"math/bits"
	"net"
	"syscall"

	"nodeping/internal/systemdns"

	"golang.org/x/sys/windows"
)

const windowsUnicastInterfaceOption = 31

type windowsSocketBinding struct {
	level  int
	option int
	value  int
}

func prepareSystemDNSDialer(dialer net.Dialer, endpoint resolvedEndpoint) (net.Dialer, error) {
	if endpoint.systemPlatform != systemdns.PlatformWindows {
		return net.Dialer{}, fmt.Errorf("%w: trusted system resolver platform %q cannot be dialed on Windows", ErrInvalidEndpoint, endpoint.systemPlatform)
	}
	binding, err := windowsSystemDNSBinding(endpoint.connectIP, endpoint.systemBindInterfaceIndex)
	if err != nil {
		return net.Dialer{}, err
	}
	return systemDNSDialerWithControl(dialer, func(network string, raw syscall.RawConn) error {
		if err := requireSystemDNSNetworkFamily(network, endpoint.connectIP); err != nil {
			return err
		}
		return applyWindowsSystemDNSBinding(raw, binding)
	}), nil
}

func windowsSystemDNSBinding(address net.IP, interfaceIndex uint32) (windowsSocketBinding, error) {
	if interfaceIndex == 0 {
		return windowsSocketBinding{}, fmt.Errorf("%w: Windows system resolver route interface is zero", ErrInvalidEndpoint)
	}
	if address.To4() != nil {
		// Winsock treats an IP_UNICAST_IF value with a non-zero high byte as
		// an IPv4 address. IF_INDEX is therefore restricted to 24 bits.
		if interfaceIndex > 0x00ffffff {
			return windowsSocketBinding{}, fmt.Errorf("%w: Windows IPv4 route interface exceeds 24 bits", ErrInvalidEndpoint)
		}
		return windowsSocketBinding{
			level:  windows.IPPROTO_IP,
			option: windowsUnicastInterfaceOption,
			value:  windowsIPv4InterfaceOptionValue(interfaceIndex),
		}, nil
	}
	if address.To16() != nil {
		return windowsSocketBinding{
			level:  windows.IPPROTO_IPV6,
			option: windowsUnicastInterfaceOption,
			value:  int(interfaceIndex),
		}, nil
	}
	return windowsSocketBinding{}, fmt.Errorf("%w: Windows system resolver address is invalid", ErrInvalidEndpoint)
}

func windowsIPv4InterfaceOptionValue(interfaceIndex uint32) int {
	// IP_UNICAST_IF specifies the IPv4 interface index in network byte order.
	// Windows Go targets are little-endian, so preserve those bytes in the
	// integer passed to setsockopt by reversing the uint32.
	return int(int32(bits.ReverseBytes32(interfaceIndex)))
}

func applyWindowsSystemDNSBinding(raw syscall.RawConn, binding windowsSocketBinding) error {
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(fd), binding.level, binding.option, binding.value)
	}); err != nil {
		return err
	}
	return socketErr
}
