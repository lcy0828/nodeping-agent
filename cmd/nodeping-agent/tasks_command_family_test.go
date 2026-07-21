package main

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestPingCommandForAddrSelectsExplicitFamily(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		target   string
		wantName string
		wantArgs []string
	}{
		{name: "Linux IPv4", goos: "linux", target: "192.0.2.1", wantName: "ping", wantArgs: []string{"-4", "-c", "1", "-W", "2", "192.0.2.1"}},
		{name: "Linux IPv6", goos: "linux", target: "2001:db8::1", wantName: "ping", wantArgs: []string{"-6", "-c", "1", "-W", "2", "2001:db8::1"}},
		{name: "Darwin IPv4", goos: "darwin", target: "192.0.2.1", wantName: "ping", wantArgs: []string{"-c", "1", "-W", "2000", "192.0.2.1"}},
		{name: "Darwin IPv6", goos: "darwin", target: "2001:db8::1", wantName: "ping6", wantArgs: []string{"-c", "1", "2001:db8::1"}},
		{name: "Windows IPv4", goos: "windows", target: "192.0.2.1", wantName: "ping", wantArgs: []string{"-4", "-n", "1", "-w", "2000", "192.0.2.1"}},
		{name: "Windows IPv6", goos: "windows", target: "2001:db8::1", wantName: "ping", wantArgs: []string{"-6", "-n", "1", "-w", "2000", "2001:db8::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pingCommandForAddr(tt.goos, netip.MustParseAddr(tt.target))
			if err != nil {
				t.Fatalf("pingCommandForAddr: %v", err)
			}
			if got.Name != tt.wantName || !reflect.DeepEqual(got.Args, tt.wantArgs) {
				t.Fatalf("command = %s %v, want %s %v", got.Name, got.Args, tt.wantName, tt.wantArgs)
			}
		})
	}
}

func TestTracerouteCommandForAddrSelectsExplicitFamily(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		target       string
		protocol     string
		wantName     string
		wantProtocol string
		wantArgs     []string
	}{
		{name: "Linux IPv4 UDP", goos: "linux", target: "192.0.2.1", wantName: "traceroute", wantProtocol: "udp", wantArgs: []string{"-4", "-n", "-m", "30", "-q", "1", "-w", "2", "192.0.2.1"}},
		{name: "Linux IPv6 ICMP", goos: "linux", target: "2001:db8::1", protocol: "icmp", wantName: "traceroute", wantProtocol: "icmp", wantArgs: []string{"-6", "-n", "-m", "30", "-q", "1", "-w", "2", "-I", "2001:db8::1"}},
		{name: "Darwin IPv4 TCP", goos: "darwin", target: "192.0.2.1", protocol: "tcp", wantName: "traceroute", wantProtocol: "tcp", wantArgs: []string{"-n", "-m", "30", "-q", "1", "-w", "2", "-P", "tcp", "192.0.2.1"}},
		{name: "Darwin IPv6 UDP", goos: "darwin", target: "2001:db8::1", wantName: "traceroute6", wantProtocol: "udp", wantArgs: []string{"-n", "-m", "30", "-q", "1", "-w", "2", "2001:db8::1"}},
		{name: "Darwin IPv6 TCP", goos: "darwin", target: "2001:db8::1", protocol: "tcp", wantName: "traceroute6", wantProtocol: "tcp", wantArgs: []string{"-n", "-m", "30", "-q", "1", "-w", "2", "-T", "2001:db8::1"}},
		{name: "Windows IPv4", goos: "windows", target: "192.0.2.1", wantName: "tracert", wantProtocol: "icmp", wantArgs: []string{"-4", "-d", "-h", "30", "-w", "2000", "192.0.2.1"}},
		{name: "Windows IPv6", goos: "windows", target: "2001:db8::1", protocol: "icmp", wantName: "tracert", wantProtocol: "icmp", wantArgs: []string{"-6", "-d", "-h", "30", "-w", "2000", "2001:db8::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tracerouteCommandForAddr(tt.goos, netip.MustParseAddr(tt.target), 30, tt.protocol)
			if err != nil {
				t.Fatalf("tracerouteCommandForAddr: %v", err)
			}
			if got.Name != tt.wantName || got.Protocol != tt.wantProtocol || !reflect.DeepEqual(got.Args, tt.wantArgs) {
				t.Fatalf("command = %s %v (%s), want %s %v (%s)", got.Name, got.Args, got.Protocol, tt.wantName, tt.wantArgs, tt.wantProtocol)
			}
		})
	}
}

func TestTracerouteCommandForAddrRejectsUnsupportedWindowsProtocol(t *testing.T) {
	_, err := tracerouteCommandForAddr("windows", netip.MustParseAddr("2001:db8::1"), 30, "tcp")
	if err == nil || !strings.Contains(err.Error(), "not supported on windows") {
		t.Fatalf("error = %v, want explicit Windows protocol error", err)
	}
}
