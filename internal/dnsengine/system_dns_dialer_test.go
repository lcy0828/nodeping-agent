package dnsengine

import (
	"context"
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"
)

type fakeSystemDNSRawConn struct{}

func (fakeSystemDNSRawConn) Control(callback func(uintptr)) error {
	callback(1)
	return nil
}

func (fakeSystemDNSRawConn) Read(func(uintptr) bool) error  { return nil }
func (fakeSystemDNSRawConn) Write(func(uintptr) bool) error { return nil }

func TestSystemDNSDialerControlCompositionPreservesPrecedenceAndOrder(t *testing.T) {
	tests := []struct {
		name        string
		dialer      func(*[]string) net.Dialer
		wantEvents  []string
		wantError   error
		bindInvoked bool
	}{
		{
			name: "ControlContext takes precedence",
			dialer: func(events *[]string) net.Dialer {
				return net.Dialer{
					Control: func(string, string, syscall.RawConn) error {
						*events = append(*events, "control")
						return nil
					},
					ControlContext: func(context.Context, string, string, syscall.RawConn) error {
						*events = append(*events, "control_context")
						return nil
					},
				}
			},
			wantEvents: []string{"control_context", "bind"}, bindInvoked: true,
		},
		{
			name: "Control retained when no ControlContext",
			dialer: func(events *[]string) net.Dialer {
				return net.Dialer{Control: func(string, string, syscall.RawConn) error {
					*events = append(*events, "control")
					return nil
				}}
			},
			wantEvents: []string{"control", "bind"}, bindInvoked: true,
		},
		{
			name: "existing error fails closed before bind",
			dialer: func(events *[]string) net.Dialer {
				return net.Dialer{ControlContext: func(context.Context, string, string, syscall.RawConn) error {
					*events = append(*events, "control_context")
					return syscall.EPERM
				}}
			},
			wantEvents: []string{"control_context"}, wantError: syscall.EPERM,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			bindInvoked := false
			dialer := systemDNSDialerWithControl(test.dialer(&events), func(string, syscall.RawConn) error {
				bindInvoked = true
				events = append(events, "bind")
				return nil
			})
			if dialer.Control != nil || dialer.ControlContext == nil {
				t.Fatalf("composed controls = Control:%v ControlContext:%v", dialer.Control != nil, dialer.ControlContext != nil)
			}
			err := dialer.ControlContext(context.Background(), "udp4", "127.0.0.1:53", fakeSystemDNSRawConn{})
			if !errors.Is(err, test.wantError) || !reflect.DeepEqual(events, test.wantEvents) || bindInvoked != test.bindInvoked {
				t.Fatalf("events=%v bind=%v error=%v", events, bindInvoked, err)
			}
		})
	}
}

func TestTrustedSystemNetworkFamilyMustMatchPinnedAddress(t *testing.T) {
	for _, test := range []struct {
		network string
		address net.IP
		valid   bool
	}{
		{network: "udp4", address: net.ParseIP("127.0.0.1"), valid: true},
		{network: "tcp6", address: net.ParseIP("fe80::53"), valid: true},
		{network: "udp6", address: net.ParseIP("127.0.0.1")},
		{network: "tcp4", address: net.ParseIP("fe80::53")},
		{network: "udp", address: net.ParseIP("127.0.0.1")},
		{network: "udp4", address: nil},
	} {
		err := requireSystemDNSNetworkFamily(test.network, test.address)
		if (err == nil) != test.valid {
			t.Errorf("network=%q address=%v error=%v valid=%v", test.network, test.address, err, test.valid)
		}
	}
}
