package dnsengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestDoTUsesPinnedIPAndVerifiedServerName(t *testing.T) {
	pki := newTestPKI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DoT: %v", err)
	}
	serverTLS := pki.serverTLS([]string{"dot"}, tls.VersionTLS12)
	tlsListener := tls.NewListener(listener, serverTLS)
	t.Cleanup(func() { _ = tlsListener.Close() })
	stateCh := make(chan tls.ConnectionState, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		queryWire, err := readFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		if err := expectRequestStreamOpen(conn); err != nil {
			serverErr <- err
			return
		}
		stateCh <- conn.(*tls.Conn).ConnectionState()
		response := testAResponse(query)
		responseWire, err := response.Pack()
		if err == nil {
			err = writeDNSFrame(conn, responseWire)
		}
		serverErr <- err
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	engine := newSecureTestEngine(t, pki.roots)
	result, err := engine.Observe(context.Background(), Endpoint{
		Protocol:   ProtocolDoT,
		Address:    "logical-resolver.invalid",
		ConnectIP:  "127.0.0.1",
		ServerName: "resolver.test",
		Port:       uint16(port),
	}, Query{Name: "example.com", Type: dns.TypeA})
	if err != nil {
		t.Fatalf("DoT observe: %v", err)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("DoT server: %v", err)
	}
	state := <-stateCh
	if state.ServerName != "resolver.test" || state.Version < tls.VersionTLS12 {
		t.Fatalf("DoT TLS state = %+v", state)
	}
	if result.PeerIP != "127.0.0.1" || result.Outcome != OutcomeAnswer {
		t.Fatalf("DoT result = %+v", result)
	}
}

func TestTLSVerificationCannotBeDisabled(t *testing.T) {
	_, err := New(Config{TLSConfig: &tls.Config{InsecureSkipVerify: true}}) //nolint:gosec // rejection test
	if err == nil {
		t.Fatal("New accepted InsecureSkipVerify")
	}
}

func TestDoHUsesPinnedIPHostSNIAndIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	pki := newTestPKI(t)
	address, observations, serverErr := startDoHResolver(t, pki, false, "application/dns-message")
	engine := newSecureTestEngine(t, pki.roots)
	result, err := engine.Observe(context.Background(), Endpoint{
		Protocol:   ProtocolDoH,
		Address:    address,
		ConnectIP:  "127.0.0.1",
		ServerName: "resolver.test",
	}, Query{Name: "example.com", Type: dns.TypeA})
	if err != nil {
		t.Fatalf("DoH observe: %v", err)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("DoH server: %v", err)
	}
	observed := <-observations
	parsedAddress, err := url.Parse(address)
	if err != nil {
		t.Fatalf("parse DoH test address: %v", err)
	}
	wantHost := parsedAddress.Host
	if observed.host != wantHost || observed.serverName != "resolver.test" || observed.method != http.MethodPost || observed.path != "/dns-query" {
		t.Fatalf("DoH request = %+v", observed)
	}
	if result.PeerIP != "127.0.0.1" || result.Outcome != OutcomeAnswer {
		t.Fatalf("DoH result = %+v", result)
	}
}

func TestDoHRejectsRedirectAndWrongContentType(t *testing.T) {
	pki := newTestPKI(t)
	t.Run("redirect", func(t *testing.T) {
		address, _, serverErr := startDoHResolver(t, pki, true, "application/dns-message")
		engine := newSecureTestEngine(t, pki.roots)
		_, err := engine.Observe(context.Background(), Endpoint{Protocol: ProtocolDoH, Address: address, ConnectIP: "127.0.0.1", ServerName: "resolver.test"}, Query{Name: "example.com", Type: dns.TypeA})
		if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
			t.Fatalf("redirect error = %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("redirect server: %v", err)
		}
	})
	t.Run("content type", func(t *testing.T) {
		address, _, serverErr := startDoHResolver(t, pki, false, "application/json")
		engine := newSecureTestEngine(t, pki.roots)
		_, err := engine.Observe(context.Background(), Endpoint{Protocol: ProtocolDoH, Address: address, ConnectIP: "127.0.0.1", ServerName: "resolver.test"}, Query{Name: "example.com", Type: dns.TypeA})
		if err == nil || !strings.Contains(err.Error(), "content type") {
			t.Fatalf("content-type error = %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("content-type server: %v", err)
		}
	})
}

func TestDoQPinsIPUsesZeroIDAndValidatesQuestion(t *testing.T) {
	pki := newTestPKI(t)
	for _, mismatch := range []bool{false, true} {
		name := "valid"
		if mismatch {
			name = "mismatched question"
		}
		t.Run(name, func(t *testing.T) {
			address, queryID, serverErr := startDoQResolver(t, pki, mismatch)
			engine := newSecureTestEngine(t, pki.roots)
			result, err := engine.Observe(context.Background(), Endpoint{
				Protocol:   ProtocolDoQ,
				Address:    "logical-resolver.invalid",
				ConnectIP:  "127.0.0.1",
				ServerName: "resolver.test",
				Port:       address.Port,
			}, Query{Name: "example.com", Type: dns.TypeA})
			if mismatch {
				if !errors.Is(err, ErrResponseMismatch) {
					t.Fatalf("DoQ mismatch error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("DoQ observe: %v", err)
			}
			if id := <-queryID; id != 0 {
				t.Fatalf("DoQ query ID = %d, want 0", id)
			}
			if err := receiveServerError(serverErr); err != nil {
				t.Fatalf("DoQ server: %v", err)
			}
			if !mismatch && (result.PeerIP != "127.0.0.1" || result.Outcome != OutcomeAnswer) {
				t.Fatalf("DoQ result = %+v", result)
			}
		})
	}
}

func TestDoQRejectsTrailingFrameResetAndMissingFIN(t *testing.T) {
	pki := newTestPKI(t)
	for _, test := range []struct {
		name       string
		behavior   string
		wantErr    error
		wantAnyErr bool
	}{
		{name: "trailing byte", behavior: "trailing", wantErr: ErrMalformedResponse},
		{name: "second frame", behavior: "second_frame", wantErr: ErrMalformedResponse},
		{name: "stream reset", behavior: "reset", wantAnyErr: true},
		{name: "missing FIN", behavior: "missing_fin", wantErr: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, serverErr := startInvalidDoQResolver(t, pki, test.behavior)
			engine, err := New(Config{
				Timeout:               250 * time.Millisecond,
				AllowPrivateConnectIP: true,
				TLSConfig:             &tls.Config{RootCAs: pki.roots, MinVersion: tls.VersionTLS12},
				IDGenerator:           func() (uint16, error) { return 0x4321, nil },
			})
			if err != nil {
				t.Fatalf("new DoQ test engine: %v", err)
			}
			_, observeErr := engine.Observe(context.Background(), Endpoint{
				Protocol: ProtocolDoQ, Address: "logical-resolver.invalid", ConnectIP: "127.0.0.1", ServerName: "resolver.test", Port: address.Port,
			}, Query{Name: "example.com", Type: dns.TypeA})
			if test.wantErr != nil && !errors.Is(observeErr, test.wantErr) {
				t.Fatalf("DoQ error = %v, want %v", observeErr, test.wantErr)
			}
			if test.wantAnyErr && observeErr == nil {
				t.Fatal("DoQ stream reset unexpectedly succeeded")
			}
			if err := receiveServerError(serverErr); err != nil {
				t.Fatalf("DoQ server: %v", err)
			}
		})
	}
}

func TestIPv6EncryptedDNSExchanges(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("DoT", func(t *testing.T) {
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback DoT unavailable: %v", err)
		}
		tlsListener := tls.NewListener(listener, pki.serverTLS([]string{"dot"}, tls.VersionTLS12))
		t.Cleanup(func() { _ = tlsListener.Close() })
		serverErr := make(chan error, 1)
		go func() {
			conn, err := tlsListener.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			queryWire, err := readFrame(conn)
			if err != nil {
				serverErr <- err
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(queryWire); err != nil {
				serverErr <- err
				return
			}
			if conn.(*tls.Conn).ConnectionState().ServerName != "resolver.test" {
				serverErr <- fmt.Errorf("IPv6 DoT SNI = %q", conn.(*tls.Conn).ConnectionState().ServerName)
				return
			}
			responseWire, err := testAResponse(query).Pack()
			if err == nil {
				err = writeDNSFrame(conn, responseWire)
			}
			serverErr <- err
		}()
		port := listener.Addr().(*net.TCPAddr).Port
		result, err := newSecureTestEngine(t, pki.roots).Observe(context.Background(), Endpoint{
			Protocol: ProtocolDoT, Address: "resolver.test", ConnectIP: "::1", ServerName: "resolver.test", Port: uint16(port),
		}, Query{Name: "example.com.", Type: dns.TypeA})
		if err != nil {
			t.Fatalf("IPv6 DoT observe: %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("IPv6 DoT resolver: %v", err)
		}
		if result.PeerIP != "::1" || result.Outcome != OutcomeAnswer {
			t.Fatalf("IPv6 DoT result = %+v", result)
		}
	})

	t.Run("DoH", func(t *testing.T) {
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback DoH unavailable: %v", err)
		}
		address, observations, serverErr := serveDoHResolver(t, pki, listener, false, "application/dns-message")
		result, err := newSecureTestEngine(t, pki.roots).Observe(context.Background(), Endpoint{
			Protocol: ProtocolDoH, Address: address, ConnectIP: "::1", ServerName: "resolver.test",
		}, Query{Name: "example.com.", Type: dns.TypeA})
		if err != nil {
			t.Fatalf("IPv6 DoH observe: %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("IPv6 DoH resolver: %v", err)
		}
		observed := <-observations
		parsedAddress, err := url.Parse(address)
		if err != nil {
			t.Fatalf("parse IPv6 DoH address: %v", err)
		}
		if observed.host != parsedAddress.Host || observed.serverName != "resolver.test" {
			t.Fatalf("IPv6 DoH identity = %+v", observed)
		}
		if result.PeerIP != "::1" || result.Outcome != OutcomeAnswer {
			t.Fatalf("IPv6 DoH result = %+v", result)
		}
	})

	t.Run("DoQ", func(t *testing.T) {
		listener, err := quic.ListenAddr("[::1]:0", pki.serverTLS([]string{"doq"}, tls.VersionTLS13), &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
		if err != nil {
			t.Skipf("IPv6 loopback DoQ unavailable: %v", err)
		}
		address, queryID, serverErr := serveDoQResolver(t, listener, false)
		result, err := newSecureTestEngine(t, pki.roots).Observe(context.Background(), Endpoint{
			Protocol: ProtocolDoQ, Address: "resolver.test", ConnectIP: "::1", ServerName: "resolver.test", Port: address.Port,
		}, Query{Name: "example.com.", Type: dns.TypeA})
		if err != nil {
			t.Fatalf("IPv6 DoQ observe: %v", err)
		}
		if id := <-queryID; id != 0 {
			t.Fatalf("IPv6 DoQ query ID = %d", id)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("IPv6 DoQ resolver: %v", err)
		}
		if result.PeerIP != "::1" || result.Outcome != OutcomeAnswer {
			t.Fatalf("IPv6 DoQ result = %+v", result)
		}
	})
}

type testPKI struct {
	certificate tls.Certificate
	roots       *x509.CertPool
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "resolver.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"resolver.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load test key pair: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test root")
	}
	return testPKI{certificate: certificate, roots: roots}
}

func (p testPKI) serverTLS(nextProtos []string, minVersion uint16) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.certificate},
		NextProtos:   append([]string(nil), nextProtos...),
		MinVersion:   minVersion,
	}
}

func newSecureTestEngine(t *testing.T, roots *x509.CertPool) *Engine {
	t.Helper()
	engine, err := New(Config{
		Timeout:               5 * time.Second,
		AllowPrivateConnectIP: true,
		TLSConfig:             &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		IDGenerator:           func() (uint16, error) { return 0x4321, nil },
	})
	if err != nil {
		t.Fatalf("new secure test engine: %v", err)
	}
	return engine
}

type dohObservation struct {
	host       string
	serverName string
	method     string
	path       string
}

func startDoHResolver(t *testing.T, pki testPKI, redirect bool, contentType string) (string, <-chan dohObservation, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DoH: %v", err)
	}
	return serveDoHResolver(t, pki, listener, redirect, contentType)
}

func serveDoHResolver(t *testing.T, pki testPKI, listener net.Listener, redirect bool, contentType string) (string, <-chan dohObservation, <-chan error) {
	t.Helper()
	serverTLS := pki.serverTLS([]string{"http/1.1"}, tls.VersionTLS12)
	tlsListener := tls.NewListener(listener, serverTLS)
	observations := make(chan dohObservation, 1)
	handlerErr := make(chan error, 1)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observation := dohObservation{host: request.Host, method: request.Method, path: request.URL.Path}
		if request.TLS != nil {
			observation.serverName = request.TLS.ServerName
		}
		observations <- observation
		if redirect {
			writer.Header().Set("Location", "https://resolver.test/other")
			writer.WriteHeader(http.StatusFound)
			handlerErr <- nil
			return
		}
		wire, err := io.ReadAll(io.LimitReader(request.Body, 65536))
		if err != nil {
			handlerErr <- err
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			handlerErr <- err
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		responseWire, err := testAResponse(query).Pack()
		if err != nil {
			handlerErr <- err
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", contentType)
		_, err = writer.Write(responseWire)
		handlerErr <- err
	})
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = httpServer.Serve(tlsListener)
	}()
	t.Cleanup(func() {
		_ = httpServer.Close()
		<-serveDone
	})
	port := listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("https://logical-resolver.invalid:%d/dns-query", port), observations, handlerErr
}

type doQAddress struct {
	Port uint16
}

func startDoQResolver(t *testing.T, pki testPKI, mismatch bool) (doQAddress, <-chan uint16, <-chan error) {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", pki.serverTLS([]string{"doq"}, tls.VersionTLS13), &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("listen DoQ: %v", err)
	}
	return serveDoQResolver(t, listener, mismatch)
}

func serveDoQResolver(t *testing.T, listener *quic.Listener, mismatch bool) (doQAddress, <-chan uint16, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	queryID := make(chan uint16, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		queryWire, err := readFrame(stream)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		queryID <- query.Id
		one := make([]byte, 1)
		if _, err := stream.Read(one); err != io.EOF {
			serverErr <- fmt.Errorf("DoQ query stream did not end with FIN: %v", err)
			return
		}
		response := testAResponse(query)
		if mismatch {
			response.Question[0].Name = "other.example."
		}
		responseWire, err := response.Pack()
		if err == nil {
			err = writeDNSFrame(stream, responseWire)
		}
		if closeErr := stream.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			// Keep the connection alive until the client has consumed the response
			// and closed it; closing immediately can discard queued QUIC data.
			<-conn.Context().Done()
		}
		serverErr <- err
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	port := listener.Addr().(*net.UDPAddr).Port
	return doQAddress{Port: uint16(port)}, queryID, serverErr
}

func startInvalidDoQResolver(t *testing.T, pki testPKI, behavior string) (doQAddress, <-chan error) {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", pki.serverTLS([]string{"doq"}, tls.VersionTLS13), &quic.Config{HandshakeIdleTimeout: time.Second})
	if err != nil {
		t.Fatalf("listen invalid DoQ resolver: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		queryWire, err := readFrame(stream)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		var one [1]byte
		if _, err := stream.Read(one[:]); err != io.EOF {
			serverErr <- fmt.Errorf("DoQ query stream did not end with FIN: %v", err)
			return
		}
		responseWire, err := testAResponse(query).Pack()
		if err == nil {
			err = writeDNSFrame(stream, responseWire)
		}
		if err != nil {
			serverErr <- err
			return
		}
		switch behavior {
		case "trailing":
			err = writeAll(stream, []byte{0xff})
			if err == nil {
				err = stream.Close()
			}
		case "second_frame":
			err = writeDNSFrame(stream, responseWire)
			if err == nil {
				err = stream.Close()
			}
		case "reset":
			stream.CancelWrite(quic.StreamErrorCode(42))
		case "missing_fin":
			<-conn.Context().Done()
		default:
			err = fmt.Errorf("unknown DoQ test behavior %q", behavior)
		}
		if err == nil && behavior != "missing_fin" {
			<-conn.Context().Done()
		}
		serverErr <- err
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	port := listener.Addr().(*net.UDPAddr).Port
	return doQAddress{Port: uint16(port)}, serverErr
}

func testAResponse(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: query.Question[0].Qclass, Ttl: 60},
		A:   net.ParseIP("192.0.2.10").To4(),
	}}
	return response
}

func writeDNSFrame(writer io.Writer, wire []byte) error {
	if len(wire) > 65535 {
		return fmt.Errorf("test DNS response too large")
	}
	frame := make([]byte, 2+len(wire))
	frame[0] = byte(len(wire) >> 8)
	frame[1] = byte(len(wire))
	copy(frame[2:], wire)
	return writeAll(writer, frame)
}
