//go:build windows

package dnstapcollector

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestWindowsListenerLoopbackSingleAcceptAndClose(t *testing.T) {
	listener, err := OpenListener("")
	if err != nil {
		t.Fatalf("open listener: %v", err)
	}
	if listener.Network() != "tcp4" || listener.WorkDir() != "" {
		t.Fatalf("listener network/work directory = %q %q", listener.Network(), listener.WorkDir())
	}
	endpoint, err := net.ResolveTCPAddr("tcp4", listener.Endpoint())
	if err != nil || endpoint.IP == nil || !endpoint.IP.IsLoopback() || endpoint.Port < 1 {
		t.Fatalf("listener endpoint = %+v err %v", endpoint, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()
	client, err := (&net.Dialer{}).DialContext(ctx, listener.Network(), listener.Endpoint())
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := listener.Accept(ctx); err == nil {
		t.Fatal("listener accepted a second connection")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestWindowsListenerAcceptRequiresDeadline(t *testing.T) {
	listener, err := OpenListener("")
	if err != nil {
		t.Fatalf("open listener: %v", err)
	}
	defer listener.Close()
	if _, err := listener.Accept(context.Background()); err == nil {
		t.Fatal("listener accepted an unbounded context")
	}
}

func TestWindowsListenerRejectsNonLoopbackPeer(t *testing.T) {
	connection := &remoteAddressConn{
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000},
	}
	if err := validatePlatformPeer(connection); err == nil {
		t.Fatal("listener accepted a non-loopback peer")
	}
}

type remoteAddressConn struct {
	remote net.Addr
}

func (connection *remoteAddressConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (connection *remoteAddressConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (connection *remoteAddressConn) Close() error                     { return nil }
func (connection *remoteAddressConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (connection *remoteAddressConn) RemoteAddr() net.Addr             { return connection.remote }
func (connection *remoteAddressConn) SetDeadline(time.Time) error      { return nil }
func (connection *remoteAddressConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *remoteAddressConn) SetWriteDeadline(time.Time) error { return nil }
