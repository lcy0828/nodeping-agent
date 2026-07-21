//go:build darwin

package dnsengine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"nodeping/internal/systemdns"

	"golang.org/x/sys/unix"
)

func TestDarwinSystemDNSBindingUsesAddressFamilySpecificOptions(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		wantLevel  int
		wantOption int
	}{
		{name: "IPv4", address: "10.0.0.53", wantLevel: unix.IPPROTO_IP, wantOption: unix.IP_BOUND_IF},
		{name: "IPv6", address: "fe80::53", wantLevel: unix.IPPROTO_IPV6, wantOption: unix.IPV6_BOUND_IF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding, err := darwinSystemDNSBinding(net.ParseIP(test.address), 17)
			if err != nil || binding.level != test.wantLevel || binding.option != test.wantOption || binding.value != 17 {
				t.Fatalf("binding = %+v, %v", binding, err)
			}
		})
	}
}

func TestDarwinSystemDNSDialerRejectsWrongPlatform(t *testing.T) {
	_, err := prepareSystemDNSDialer(net.Dialer{}, resolvedEndpoint{
		connectIP: net.ParseIP("10.0.0.53"), systemPlatform: systemdns.PlatformWindows, systemBindInterfaceIndex: 4,
	})
	if !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("wrong-platform error = %v", err)
	}
}

func TestDarwinSystemDNSDialerBindsRealLoopbackSockets(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatalf("find macOS loopback interface: %v", err)
	}
	engine := &Engine{dialer: net.Dialer{Timeout: time.Second}}
	for _, test := range []struct {
		name          string
		listenNetwork string
		dialNetwork   string
		address       string
		connectIP     net.IP
	}{
		{name: "UDP IPv4", listenNetwork: "udp4", dialNetwork: "udp", address: "127.0.0.1:0", connectIP: net.ParseIP("127.0.0.1")},
		{name: "UDP IPv6", listenNetwork: "udp6", dialNetwork: "udp", address: "[::1]:0", connectIP: net.ParseIP("::1")},
		{name: "TCP IPv4", listenNetwork: "tcp4", dialNetwork: "tcp", address: "127.0.0.1:0", connectIP: net.ParseIP("127.0.0.1")},
		{name: "TCP IPv6", listenNetwork: "tcp6", dialNetwork: "tcp", address: "[::1]:0", connectIP: net.ParseIP("::1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			endpoint := resolvedEndpoint{
				connectIP: test.connectIP, systemPlatform: systemdns.PlatformDarwin,
				systemBindInterfaceIndex: uint32(loopback.Index),
			}
			if test.dialNetwork == "udp" {
				listener, listenErr := net.ListenPacket(test.listenNetwork, test.address)
				if listenErr != nil {
					t.Fatalf("listen: %v", listenErr)
				}
				defer listener.Close()
				endpoint.dialAddress = listener.LocalAddr().String()
				connection, dialErr := engine.dialEndpoint(ctx, test.dialNetwork, endpoint)
				if dialErr != nil {
					t.Fatalf("dial bound socket: %v", dialErr)
				}
				connection.Close()
				return
			}

			listener, listenErr := net.Listen(test.listenNetwork, test.address)
			if listenErr != nil {
				t.Fatalf("listen: %v", listenErr)
			}
			defer listener.Close()
			accepted := make(chan error, 1)
			go func() {
				connection, acceptErr := listener.Accept()
				if acceptErr == nil {
					acceptErr = connection.Close()
				}
				accepted <- acceptErr
			}()
			endpoint.dialAddress = listener.Addr().String()
			connection, dialErr := engine.dialEndpoint(ctx, test.dialNetwork, endpoint)
			if dialErr != nil {
				t.Fatalf("dial bound socket: %v", dialErr)
			}
			connection.Close()
			if acceptErr := <-accepted; acceptErr != nil {
				t.Fatalf("accept bound socket: %v", acceptErr)
			}
		})
	}
}

func TestDarwinSystemDNSDialerFailsClosedWhenInterfaceBindFails(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	engine := &Engine{dialer: net.Dialer{Timeout: time.Second}}
	connection, dialErr := engine.dialEndpoint(context.Background(), "udp", resolvedEndpoint{
		dialAddress: listener.LocalAddr().String(), connectIP: net.ParseIP("127.0.0.1"),
		systemPlatform: systemdns.PlatformDarwin, systemBindInterfaceIndex: ^uint32(0),
	})
	if connection != nil {
		connection.Close()
		t.Fatal("dial unexpectedly succeeded with an invalid bind interface")
	}
	if dialErr == nil {
		t.Fatal("invalid bind interface did not fail closed")
	}
}
