//go:build windows

package dnsengine

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSystemDNSBindingUsesUnicastInterfaceOptionsAndEndian(t *testing.T) {
	ipv4, err := windowsSystemDNSBinding(net.ParseIP("10.0.0.53"), 0x00010203)
	if err != nil || ipv4.level != windows.IPPROTO_IP || ipv4.option != windowsUnicastInterfaceOption || uint32(int32(ipv4.value)) != 0x03020100 {
		t.Fatalf("IPv4 binding = %+v, %v", ipv4, err)
	}
	if got := uint32(int32(windowsIPv4InterfaceOptionValue(0x00010203))); got != 0x03020100 {
		t.Fatalf("IPv4 network-order option value = %#x", got)
	}
	if maximum, err := windowsSystemDNSBinding(net.ParseIP("10.0.0.53"), 0x00ffffff); err != nil || maximum.value != -256 {
		t.Fatalf("maximum IPv4 interface binding = %+v, %v", maximum, err)
	}
	if _, err := windowsSystemDNSBinding(net.ParseIP("10.0.0.53"), 0x01000000); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("oversized IPv4 interface error = %v", err)
	}

	ipv6, err := windowsSystemDNSBinding(net.ParseIP("fe80::53"), 0x01020304)
	if err != nil || ipv6.level != windows.IPPROTO_IPV6 || ipv6.option != windowsUnicastInterfaceOption || ipv6.value != 0x01020304 {
		t.Fatalf("IPv6 binding = %+v, %v", ipv6, err)
	}
}
