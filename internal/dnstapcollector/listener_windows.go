//go:build windows

package dnstapcollector

import (
	"fmt"
	"net"
)

func openPlatformListener(_ string) (*Listener, error) {
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen on dnstap loopback socket: %w", err)
	}
	address, ok := tcpListener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() || address.Port < 1 {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("dnstap listener did not bind to loopback")
	}
	return &Listener{
		listener: tcpListener,
		network:  "tcp4",
		endpoint: address.String(),
		cleanup:  func() error { return nil },
	}, nil
}

func validatePlatformPeer(connection net.Conn) error {
	address, ok := connection.RemoteAddr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() {
		return fmt.Errorf("dnstap TCP listener rejected a non-loopback peer")
	}
	return nil
}
