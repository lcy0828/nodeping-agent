package dnsengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

func (e *Engine) exchangeWire(ctx context.Context, endpoint resolvedEndpoint, protocol Protocol, query []byte) ([]byte, string, error) {
	switch protocol {
	case ProtocolUDP:
		return e.exchangeUDP(ctx, endpoint, query)
	case ProtocolTCP:
		return e.exchangeTCP(ctx, endpoint, query)
	case ProtocolDoT:
		return e.exchangeDoT(ctx, endpoint, query)
	case ProtocolDoH:
		return e.exchangeDoH(ctx, endpoint, query)
	case ProtocolDoQ:
		return e.exchangeDoQ(ctx, endpoint, query)
	default:
		return nil, "", fmt.Errorf("%w: unsupported protocol %q", ErrInvalidEndpoint, protocol)
	}
}

func (e *Engine) exchangeUDP(ctx context.Context, endpoint resolvedEndpoint, query []byte) ([]byte, string, error) {
	conn, err := e.dialEndpoint(ctx, "udp", endpoint)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	setDeadlineFromContext(conn, ctx)
	if _, err := conn.Write(query); err != nil {
		return nil, peerIP(conn.RemoteAddr()), err
	}
	// A full-size buffer lets us detect a configured size violation instead of
	// silently accepting a kernel-truncated datagram.
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	peer := peerIP(conn.RemoteAddr())
	if err != nil {
		return nil, peer, err
	}
	if err := validatePeer(endpoint, conn.RemoteAddr()); err != nil {
		return nil, peer, err
	}
	return buffer[:n], peer, nil
}

func (e *Engine) exchangeTCP(ctx context.Context, endpoint resolvedEndpoint, query []byte) ([]byte, string, error) {
	conn, err := e.dialEndpoint(ctx, "tcp", endpoint)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	setDeadlineFromContext(conn, ctx)
	peer := peerIP(conn.RemoteAddr())
	if err := validatePeer(endpoint, conn.RemoteAddr()); err != nil {
		return nil, peer, err
	}
	wire, err := exchangeFramed(conn, query, e.maxResponseBytes)
	return wire, peer, err
}

func (e *Engine) exchangeDoT(ctx context.Context, endpoint resolvedEndpoint, query []byte) ([]byte, string, error) {
	raw, err := e.dialer.DialContext(ctx, "tcp", endpoint.dialAddress)
	if err != nil {
		return nil, "", err
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	setDeadlineFromContext(raw, ctx)
	peer := peerIP(raw.RemoteAddr())
	if err := validatePeer(endpoint, raw.RemoteAddr()); err != nil {
		return nil, peer, err
	}
	tlsConfig := e.tlsConfigFor(endpoint.serverName, tls.VersionTLS12, nil)
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, peer, err
	}
	wire, err := exchangeFramed(conn, query, e.maxResponseBytes)
	return wire, peer, err
}

func (e *Engine) exchangeDoH(ctx context.Context, endpoint resolvedEndpoint, query []byte) ([]byte, string, error) {
	if endpoint.dohURL == nil {
		return nil, "", fmt.Errorf("%w: missing DoH URL", ErrInvalidEndpoint)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           e.pinnedDialContext(endpoint.dialAddress),
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSClientConfig:       e.tlsConfigFor(endpoint.serverName, tls.VersionTLS12, nil),
		TLSHandshakeTimeout:   e.timeout,
		ResponseHeaderTimeout: e.timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("DoH redirects are disabled")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.dohURL.String(), bytes.NewReader(query))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	var peerMu sync.Mutex
	var peerAddr net.Addr
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		peerMu.Lock()
		peerAddr = info.Conn.RemoteAddr()
		peerMu.Unlock()
	}}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	response, err := client.Do(req)
	peerMu.Lock()
	peer := peerIP(peerAddr)
	actualPeer := peerAddr
	peerMu.Unlock()
	if err != nil {
		return nil, peer, err
	}
	defer response.Body.Close()
	if err := validatePeer(endpoint, actualPeer); err != nil {
		return nil, peer, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, peer, fmt.Errorf("unexpected DoH HTTP status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, peer, fmt.Errorf("unexpected DoH content type %q", response.Header.Get("Content-Type"))
	}
	if response.ContentLength > int64(e.maxResponseBytes) {
		return nil, peer, fmt.Errorf("%w: content length %d, limit %d", ErrResponseTooLarge, response.ContentLength, e.maxResponseBytes)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, int64(e.maxResponseBytes)+1))
	if err != nil {
		return nil, peer, err
	}
	if len(wire) > e.maxResponseBytes {
		return wire, peer, fmt.Errorf("%w: got more than %d bytes", ErrResponseTooLarge, e.maxResponseBytes)
	}
	return wire, peer, nil
}

func (e *Engine) exchangeDoQ(ctx context.Context, endpoint resolvedEndpoint, query []byte) ([]byte, string, error) {
	tlsConfig := e.tlsConfigFor(endpoint.serverName, tls.VersionTLS13, []string{"doq"})
	quicConfig := e.quicConfig.Clone()
	conn, err := quic.DialAddr(ctx, endpoint.dialAddress, tlsConfig, quicConfig)
	if err != nil {
		return nil, "", err
	}
	defer conn.CloseWithError(0, "")
	peer := peerIP(conn.RemoteAddr())
	if err := validatePeer(endpoint, conn.RemoteAddr()); err != nil {
		return nil, peer, err
	}
	if conn.ConnectionState().TLS.NegotiatedProtocol != "doq" {
		return nil, peer, fmt.Errorf("unexpected DoQ ALPN %q", conn.ConnectionState().TLS.NegotiatedProtocol)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, peer, err
	}
	defer stream.CancelRead(0)
	setDeadlineFromContext(stream, ctx)
	if err := writeFramedQuery(stream, query); err != nil {
		return nil, peer, err
	}
	// RFC 9250 assigns one query to each stream. Sending FIN after the query
	// prevents an implementation from waiting for more request bytes.
	if err := stream.Close(); err != nil {
		return nil, peer, err
	}
	wire, err := readDoQResponse(stream, e.maxResponseBytes)
	return wire, peer, err
}

func (e *Engine) pinnedDialContext(address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return e.dialer.DialContext(ctx, network, address)
	}
}

func (e *Engine) tlsConfigFor(serverName string, minVersion uint16, nextProtos []string) *tls.Config {
	config := e.tlsConfig.Clone()
	config.ServerName = serverName
	if config.MinVersion < minVersion {
		config.MinVersion = minVersion
	}
	if nextProtos != nil {
		config.NextProtos = append([]string(nil), nextProtos...)
	}
	return config
}

func exchangeFramed(conn io.ReadWriter, query []byte, maxResponseBytes int) ([]byte, error) {
	if err := writeFramedQuery(conn, query); err != nil {
		return nil, err
	}
	return readFramedResponse(conn, maxResponseBytes)
}

func writeFramedQuery(writer io.Writer, query []byte) error {
	if len(query) > 65535 {
		return fmt.Errorf("DNS query exceeds stream framing limit")
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	return writeAll(writer, frame)
}

func readFramedResponse(reader io.Reader, maxResponseBytes int) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	if size > maxResponseBytes {
		return nil, fmt.Errorf("%w: framed response is %d bytes, limit %d", ErrResponseTooLarge, size, maxResponseBytes)
	}
	wire := make([]byte, size)
	if _, err := io.ReadFull(reader, wire); err != nil {
		return nil, err
	}
	if size < 12 {
		return wire, fmt.Errorf("%w: framed response is %d bytes", ErrMalformedResponse, size)
	}
	return wire, nil
}

func readDoQResponse(reader io.Reader, maxResponseBytes int) ([]byte, error) {
	wire, err := readFramedResponse(reader, maxResponseBytes)
	if err != nil {
		return wire, err
	}
	var trailing [1]byte
	n, finErr := reader.Read(trailing[:])
	if n != 0 {
		return wire, fmt.Errorf("%w: DoQ response contains trailing bytes", ErrMalformedResponse)
	}
	if !errors.Is(finErr, io.EOF) {
		if finErr == nil {
			finErr = io.ErrNoProgress
		}
		return wire, fmt.Errorf("DoQ response did not end with FIN: %w", finErr)
	}
	return wire, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func setDeadlineFromContext(conn interface{ SetDeadline(time.Time) error }, ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

func validatePeer(endpoint resolvedEndpoint, address net.Addr) error {
	if endpoint.connectIP == nil {
		return nil
	}
	actual := net.ParseIP(peerIP(address))
	if actual == nil || !actual.Equal(endpoint.connectIP) {
		return fmt.Errorf("DNS response peer %q does not match connect_ip %q", peerIP(address), endpoint.connectIP)
	}
	return nil
}

func peerIP(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		host = strings.Trim(address.String(), "[]")
	} else {
		host = strings.Trim(host, "[]")
	}
	parsed, parseErr := netip.ParseAddr(host)
	if parseErr != nil {
		return host
	}
	return parsed.WithZone("").Unmap().String()
}
