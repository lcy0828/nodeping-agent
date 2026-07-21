package dnsengine

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"nodeping/internal/dnsobs"
	"nodeping/internal/systemdns"

	"github.com/miekg/dns"
)

func TestBuildQueryUsesEDNS1232WithoutECS(t *testing.T) {
	engine := newTestEngine(t, nil)
	message, err := engine.buildQuery(Query{
		Name:             "Example.COM",
		Type:             dns.TypeA,
		RecursionDesired: true,
		DNSSECOK:         true,
	}, ProtocolUDP)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	if message.Id != 0x1234 {
		t.Fatalf("message ID = %#x, want %#x", message.Id, 0x1234)
	}
	if got := message.Question[0].Name; got != "example.com." {
		t.Fatalf("question name = %q", got)
	}
	opt := message.IsEdns0()
	if opt == nil || opt.UDPSize() != DefaultUDPSize || !opt.Do() {
		t.Fatalf("OPT = %#v, want UDP size %d and DO", opt, DefaultUDPSize)
	}
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0SUBNET {
			t.Fatalf("default query unexpectedly contains ECS: %#v", option)
		}
	}

	doq, err := engine.buildQuery(Query{Name: ".", Type: dns.TypeNS}, ProtocolDoQ)
	if err != nil {
		t.Fatalf("build DoQ query: %v", err)
	}
	if doq.Id != 0 {
		t.Fatalf("DoQ query ID = %d, want 0", doq.Id)
	}
}

func TestPrepareMessageRejectsECSByDefault(t *testing.T) {
	engine := newTestEngine(t, nil)
	message := new(dns.Msg)
	message.SetQuestion("example.com.", dns.TypeA)
	message.SetEdns0(DefaultUDPSize, false)
	message.IsEdns0().Option = append(message.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.0").To4(),
	})
	if _, err := engine.prepareMessage(message, ProtocolUDP); !errors.Is(err, ErrECSDisabled) {
		t.Fatalf("prepare ECS query error = %v, want ErrECSDisabled", err)
	}

	allowed := newTestEngine(t, func(config *Config) { config.AllowECS = true })
	if _, err := allowed.prepareMessage(message, ProtocolUDP); err != nil {
		t.Fatalf("explicitly allowed ECS query: %v", err)
	}
}

func TestQueryBoundaryRejectsUnsupportedTypesClassesAndSections(t *testing.T) {
	engine := newTestEngine(t, nil)
	for _, rrType := range []uint16{dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR} {
		if _, err := engine.buildQuery(Query{Name: "example.com.", Type: rrType}, ProtocolUDP); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("query type %d error = %v, want ErrInvalidQuery", rrType, err)
		}
	}
	if _, err := engine.buildQuery(Query{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassCHAOS}, ProtocolUDP); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("CHAOS query error = %v, want ErrInvalidQuery", err)
	}
	if _, err := engine.buildQuery(Query{Name: "example.com.", Type: dns.TypeA, AuthenticatedData: true}, ProtocolUDP); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("AD query error = %v, want ErrInvalidQuery", err)
	}

	base := func() *dns.Msg {
		message := new(dns.Msg)
		message.SetQuestion("example.com.", dns.TypeA)
		return message
	}
	for name, mutate := range map[string]func(*dns.Msg){
		"answer": func(message *dns.Msg) {
			message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}
		},
		"authority": func(message *dns.Msg) {
			message.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.com."}}
		},
		"ordinary additional": func(message *dns.Msg) {
			message.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}
		},
		"multiple OPT": func(message *dns.Msg) {
			message.SetEdns0(1232, false)
			message.Extra = append(message.Extra, &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}})
		},
		"invalid OPT owner": func(message *dns.Msg) {
			message.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeOPT, Class: 1232}}}
		},
		"unsupported OPT CO flag": func(message *dns.Msg) {
			message.SetEdns0(1232, false)
			message.IsEdns0().SetCo()
		},
		"unsupported OPT Z flag": func(message *dns.Msg) {
			message.SetEdns0(1232, false)
			message.IsEdns0().SetZ(1)
		},
		"nil EDNS option": func(message *dns.Msg) {
			message.SetEdns0(1232, false)
			message.IsEdns0().Option = append(message.IsEdns0().Option, nil)
		},
		"AA flag": func(message *dns.Msg) { message.Authoritative = true },
		"TC flag": func(message *dns.Msg) { message.Truncated = true },
		"RA flag": func(message *dns.Msg) { message.RecursionAvailable = true },
		"Z flag":  func(message *dns.Msg) { message.Zero = true },
		"AD flag": func(message *dns.Msg) { message.AuthenticatedData = true },
		"rcode":   func(message *dns.Msg) { message.Rcode = dns.RcodeServerFailure },
	} {
		t.Run(name, func(t *testing.T) {
			message := base()
			mutate(message)
			if _, err := engine.prepareMessage(message, ProtocolUDP); !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("prepare error = %v, want ErrInvalidQuery", err)
			}
		})
	}
}

func TestEndpointRequiresPinnedPublicConnectIP(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   Endpoint
		allowLocal bool
		wantErr    bool
	}{
		{name: "public literal", endpoint: Endpoint{Address: "8.8.8.8"}},
		{name: "hostname pinned public", endpoint: Endpoint{Address: "resolver.example", ConnectIP: "1.1.1.1"}},
		{name: "hostname unpinned", endpoint: Endpoint{Address: "resolver.example"}, wantErr: true},
		{name: "private literal", endpoint: Endpoint{Address: "127.0.0.1"}, wantErr: true},
		{name: "documentation address", endpoint: Endpoint{Address: "192.0.2.1"}, wantErr: true},
		{name: "scoped link local", endpoint: Endpoint{Address: "fe80::53%en0"}, wantErr: true},
		{name: "scoped public address", endpoint: Endpoint{Address: "2001:4860:4860::8888%en0"}, wantErr: true},
		{name: "scoped public connect IP", endpoint: Endpoint{Address: "resolver.example", ConnectIP: "2001:4860:4860::8888%en0"}, wantErr: true},
		{name: "private explicitly allowed", endpoint: Endpoint{Address: "resolver.test", ConnectIP: "127.0.0.1"}, allowLocal: true},
		{name: "DoH hostname unpinned", endpoint: Endpoint{Protocol: ProtocolDoH, Address: "https://resolver.example/dns-query"}, wantErr: true},
		{name: "DoH hostname pinned", endpoint: Endpoint{Protocol: ProtocolDoH, Address: "https://resolver.example/dns-query", ConnectIP: "9.9.9.9", ServerName: "resolver.example"}},
		{name: "DoH missing server name", endpoint: Endpoint{Protocol: ProtocolDoH, Address: "https://resolver.example/dns-query", ConnectIP: "9.9.9.9"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveEndpoint(test.endpoint, test.allowLocal)
			if test.wantErr && !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("resolve error = %v, want ErrInvalidEndpoint", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("resolve endpoint: %v", err)
			}
		})
	}
}

func TestTrustedSystemEndpointRejectsParsedResolverWithoutNativeProvenance(t *testing.T) {
	result, err := systemdns.ParseResolvConf([]byte("nameserver 127.0.0.53\n"))
	if err != nil {
		t.Fatal(err)
	}
	if targets, selectErr := result.SelectTrustedDialTargets(systemdns.Selection{Name: "example.com"}); selectErr == nil || targets != nil {
		t.Fatalf("untrusted parsed snapshot targets = %#v, %v", targets, selectErr)
	}
	if _, err := NewTrustedSystemEndpoint(systemdns.DialTarget{}, ProtocolUDP); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("untrusted system endpoint error = %v", err)
	}
}

func TestScopedPeerIPIsBareForUDPAndTCPObservations(t *testing.T) {
	started := time.Now().UTC()
	for _, test := range []struct {
		name     string
		protocol Protocol
		address  net.Addr
	}{
		{name: "udp", protocol: ProtocolUDP, address: &net.UDPAddr{IP: net.ParseIP("fe80::53"), Port: 53, Zone: "en7"}},
		{name: "tcp", protocol: ProtocolTCP, address: &net.TCPAddr{IP: net.ParseIP("fe80::53"), Port: 53, Zone: "en7"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := peerIP(test.address)
			if peer != "fe80::53" || strings.Contains(peer, "%") {
				t.Fatalf("peerIP(%v) = %q", test.address, peer)
			}
			if err := validatePeer(resolvedEndpoint{connectIP: net.ParseIP("fe80::53")}, test.address); err != nil {
				t.Fatalf("validate scoped peer: %v", err)
			}
			result := &Result{
				Question:       dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				Protocol:       test.protocol,
				PeerIP:         peer,
				StartedAt:      started,
				Duration:       time.Millisecond,
				Attempts:       []Attempt{{Protocol: test.protocol, PeerIP: peer, StartedAt: started, Duration: time.Millisecond, ResponseSize: 32}},
				RCode:          0,
				Flags:          Flags{Response: true},
				Outcome:        OutcomeAnswer,
				ResponseParsed: true,
				ResponseSize:   32,
			}
			envelope := testObservationEnvelope()
			envelope.Endpoint.Protocol = dnsobs.Protocol(test.protocol)
			observation, err := ToObservation(result, nil, envelope)
			if err != nil {
				t.Fatalf("ToObservation: %v", err)
			}
			if observation.PeerIP != "fe80::53" || observation.Attempts[0].PeerIP != "fe80::53" || strings.Contains(observation.PeerIP, "%") {
				t.Fatalf("scoped zone leaked into observation: %+v", observation)
			}
		})
	}
}

func TestEndpointIdentityURLPortAndServerNameRules(t *testing.T) {
	invalid := []Endpoint{
		{Protocol: ProtocolUDP, Address: "8.8.8.8", ConnectIP: "1.1.1.1"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns-query?name=example.com", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns-query#fragment", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://user@dns.google/dns-query", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns query", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns%20query", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: `https://dns.google/dns\query`, ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns%5cquery", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns%00query", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns%E3%80%80query", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns%zzquery", ConnectIP: "8.8.8.8", ServerName: "dns.google"},
		{Protocol: ProtocolDoH, Address: "https://dns.google:444/dns-query", ConnectIP: "8.8.8.8", ServerName: "dns.google", Port: 443},
		{Protocol: ProtocolDoH, Address: "https://dns.google/dns-query", ConnectIP: "8.8.8.8", ServerName: "8.8.8.8"},
		{Protocol: ProtocolDoT, Address: "8.8.8.8", ServerName: ""},
		{Protocol: ProtocolDoT, Address: "dns.google", ConnectIP: "8.8.8.8"},
		{Protocol: ProtocolDoQ, Address: "dns.google", ConnectIP: "8.8.8.8"},
		{Protocol: ProtocolDoQ, Address: "dns.google", ConnectIP: "[2001:4860:4860::8888]", ServerName: "dns.google"},
	}
	for _, endpoint := range invalid {
		if got, err := resolveEndpoint(endpoint, false); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("resolveEndpoint(%+v) = %+v, %v; want ErrInvalidEndpoint", endpoint, got, err)
		}
	}

	doh, err := resolveEndpoint(Endpoint{
		Protocol: ProtocolDoH, Address: "https://DNS.Google:443/dns-query", ConnectIP: "8.8.8.8", ServerName: "DNS.Google.", Port: 443,
	}, false)
	if err != nil {
		t.Fatalf("resolve normalized DoH endpoint: %v", err)
	}
	if doh.serverName != "dns.google" || doh.port != 443 || doh.dohURL.Host != "dns.google:443" || doh.dohURL.Path != "/dns-query" {
		t.Fatalf("normalized DoH endpoint = %+v", doh)
	}
	escaped, err := resolveEndpoint(Endpoint{
		Protocol: ProtocolDoH, Address: "https://dns.google/custom%2Fdns-query", ConnectIP: "8.8.8.8", ServerName: "dns.google",
	}, false)
	if err != nil {
		t.Fatalf("resolve escaped DoH endpoint: %v", err)
	}
	if escaped.dohURL.EscapedPath() != "/custom%2Fdns-query" {
		t.Fatalf("escaped DoH path = %q", escaped.dohURL.EscapedPath())
	}

	ipv6, err := resolveEndpoint(Endpoint{Protocol: ProtocolUDP, Address: "[2001:4860:4860::8888]"}, false)
	if err != nil {
		t.Fatalf("resolve bracketed IPv6 address: %v", err)
	}
	if ipv6.connectIP.String() != "2001:4860:4860::8888" || ipv6.dialAddress != "[2001:4860:4860::8888]:53" {
		t.Fatalf("normalized IPv6 endpoint = %+v", ipv6)
	}
}

func TestDNSObservationDoHEndpointMapsIndependentAuthorityAndSNI(t *testing.T) {
	normalized, err := dnsobs.NormalizeEndpoint(dnsobs.Endpoint{
		Kind:          dnsobs.EndpointPublicAnycast,
		Protocol:      dnsobs.ProtocolDoH,
		ConnectIP:     "8.8.8.8",
		ServerName:    "TLS.Resolver.Example",
		HTTPAuthority: "B\u00dcCHER.Example.",
		Port:          8443,
	})
	if err != nil {
		t.Fatalf("normalize observation endpoint: %v", err)
	}
	resolved, err := resolveEndpoint(Endpoint{
		Protocol:   Protocol(normalized.Protocol),
		Address:    normalized.HTTPAuthority,
		ConnectIP:  normalized.ConnectIP,
		ServerName: normalized.ServerName,
		Port:       uint16(normalized.Port),
	}, false)
	if err != nil {
		t.Fatalf("resolve engine endpoint: %v", err)
	}
	if resolved.dohURL.Host != "xn--bcher-kva.example:8443" || resolved.serverName != "tls.resolver.example" || resolved.port != 8443 || resolved.dohURL.Path != "/dns-query" || resolved.dialAddress != "8.8.8.8:8443" {
		t.Fatalf("resolved DoH endpoint = %+v", resolved)
	}
}

func TestUDPExchangePreservesSectionsFlagsAndEDNS(t *testing.T) {
	endpoint, serverErr := startUDPResolver(t, func(query *dns.Msg) (*dns.Msg, error) {
		opt := query.IsEdns0()
		if opt == nil || opt.UDPSize() != DefaultUDPSize || !opt.Do() {
			return nil, fmt.Errorf("query OPT = %#v", opt)
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Authoritative = true
		response.RecursionAvailable = true
		response.AuthenticatedData = true
		response.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "Example.COM.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: net.ParseIP("192.0.2.10").To4()},
		}
		response.Ns = []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "Example.COM.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "NS1.Example.COM."},
		}
		response.Extra = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "NS1.Example.COM.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.53").To4()},
		}
		response.SetEdns0(DefaultUDPSize, true)
		response.IsEdns0().SetZ(0x21)
		response.IsEdns0().Option = append(response.IsEdns0().Option,
			&dns.EDNS0_EDE{InfoCode: 3, ExtraText: "stale answer"},
			&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "A1B2"},
			&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 16, Address: net.ParseIP("198.51.100.0").To4()},
		)
		return response, nil
	})

	engine := newTestEngine(t, nil)
	result, err := engine.Observe(context.Background(), endpoint, Query{
		Name:             "Example.COM",
		Type:             dns.TypeA,
		RecursionDesired: true,
		DNSSECOK:         true,
	})
	if err != nil {
		t.Fatalf("UDP observe: %v (server: %v)", err, receiveServerError(serverErr))
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("UDP server: %v", err)
	}
	if result.Protocol != ProtocolUDP || result.PeerIP != "127.0.0.1" || len(result.Attempts) != 1 {
		t.Fatalf("transport result = %+v", result)
	}
	if result.Outcome != OutcomeAnswer || !result.Flags.Response || !result.Flags.Authoritative || !result.Flags.AuthenticData || !result.Flags.RecursionAvailable {
		t.Fatalf("semantic result = %+v", result)
	}
	if len(result.Sections.Answer) != 1 || len(result.Sections.Authority) != 1 || len(result.Sections.Additional) != 1 {
		t.Fatalf("sections = %+v", result.Sections)
	}
	answer := result.Sections.Answer[0]
	if answer.Owner != "example.com." || answer.Type != "A" || answer.Class != "IN" || answer.TTL != 90 || answer.DisplayRData != "192.0.2.10" || answer.CanonicalRData != `\# 4 C000020A` {
		t.Fatalf("answer = %+v", answer)
	}
	if !result.EDNS.Present || result.EDNS.UDPSize != DefaultUDPSize || result.EDNS.Flags != 0x8021 || !result.EDNS.DNSSECOK || len(result.EDNS.Options) != 3 {
		t.Fatalf("EDNS = %+v", result.EDNS)
	}
	if len(result.EDNS.EDE) != 1 || result.EDNS.EDE[0].Code != 3 || result.EDNS.EDE[0].Text != "stale answer" || result.EDNS.NSIDHex != "a1b2" {
		t.Fatalf("structured EDNS = %+v", result.EDNS)
	}
	if result.EDNS.ECS == nil || result.EDNS.ECS.Address != "198.51.100.0" || result.EDNS.ECS.SourcePrefix != 24 || result.EDNS.ECS.ScopePrefix != 16 {
		t.Fatalf("ECS = %+v", result.EDNS.ECS)
	}
	for _, option := range result.EDNS.Options {
		if option.DataBase64 == "" {
			t.Fatalf("raw EDNS option missing: %+v", option)
		}
		if _, err := base64.StdEncoding.DecodeString(option.DataBase64); err != nil {
			t.Fatalf("raw EDNS option is not base64: %+v: %v", option, err)
		}
	}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("convert EDNS observation: %v", err)
	}
	if observation.EDNS.Flags != 0x8021 || !observation.EDNS.DNSSECOK {
		t.Fatalf("observation EDNS flags = %+v", observation.EDNS)
	}
}

func TestUDPTruncationFallsBackToTCPWithPartialReads(t *testing.T) {
	endpoint, ids, serverErr := startTruncatedResolver(t)
	engine := newTestEngine(t, nil)
	result, err := engine.Observe(context.Background(), endpoint, Query{Name: "example.com", Type: dns.TypeAAAA, RecursionDesired: true})
	if err != nil {
		t.Fatalf("observe with fallback: %v (server: %v)", err, receiveServerError(serverErr))
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("dual resolver: %v", err)
	}
	queryIDs := <-ids
	if queryIDs[0] != queryIDs[1] || queryIDs[0] != 0x1234 {
		t.Fatalf("UDP/TCP query IDs = %v", queryIDs)
	}
	if !result.UDPToTCPFallback || len(result.Attempts) != 2 || result.Attempts[0].Protocol != ProtocolUDP || !result.Attempts[0].Truncated || result.Attempts[1].Protocol != ProtocolTCP {
		t.Fatalf("fallback attempts = %+v", result.Attempts)
	}
	if result.Protocol != ProtocolUDP || result.Outcome != OutcomeAnswer || result.ResponseTruncated || result.ResultTruncated || len(result.Sections.Answer) != 1 {
		t.Fatalf("fallback result = %+v", result)
	}
	envelope := testObservationEnvelope()
	envelope.Question.Type = "AAAA"
	observation, err := ToObservation(result, nil, envelope)
	if err != nil {
		t.Fatalf("convert fallback observation: %v", err)
	}
	if observation.Protocol != "tcp" || observation.Endpoint.Protocol != "udp" || !observation.UDPToTCPFallback || observation.AttemptCount != 2 {
		t.Fatalf("fallback observation = %+v", observation)
	}
}

func TestMandatoryTCPFallbackSurvivesUDPConversionFailureAndOwnsFinalConversionFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		failCall int
		wantErr  bool
	}{
		{name: "UDP TC body conversion failure still falls back", failCall: 1},
		{name: "final TCP conversion failure drops UDP evidence", failCall: 2, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
			t.Cleanup(func() {
				_ = udpConn.Close()
				_ = tcpListener.Close()
			})
			tcpSize := make(chan int, 1)
			serverErr := make(chan error, 1)
			go func() {
				buffer := make([]byte, 65535)
				n, peer, err := udpConn.ReadFrom(buffer)
				if err != nil {
					serverErr <- err
					return
				}
				query := new(dns.Msg)
				if err := query.Unpack(buffer[:n]); err != nil {
					serverErr <- err
					return
				}
				udpResponse := new(dns.Msg)
				udpResponse.SetReply(query)
				udpResponse.Truncated = true
				udpResponse.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.8").To4()}}
				udpWire, err := udpResponse.Pack()
				if err == nil {
					_, err = udpConn.WriteTo(udpWire, peer)
				}
				if err != nil {
					serverErr <- err
					return
				}
				conn, err := tcpListener.Accept()
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
				tcpQuery := new(dns.Msg)
				if err := tcpQuery.Unpack(queryWire); err != nil {
					serverErr <- err
					return
				}
				tcpResponse := new(dns.Msg)
				tcpResponse.SetReply(tcpQuery)
				tcpResponse.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: tcpQuery.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.9").To4()}}
				tcpWire, err := tcpResponse.Pack()
				if err == nil {
					tcpSize <- len(tcpWire)
					err = writeDNSFrame(conn, tcpWire)
				}
				serverErr <- err
			}()

			engine := newTestEngine(t, nil)
			calls := 0
			engine.resultComposer = func(result *Result, response *dns.Msg) error {
				calls++
				if calls == test.failCall {
					return fmt.Errorf("%w: injected result conversion failure", ErrMalformedResponse)
				}
				return engine.populateResult(result, response)
			}
			result, observeErr := engine.Observe(context.Background(), Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, Query{Name: "example.com.", Type: dns.TypeA})
			if err := receiveServerError(serverErr); err != nil {
				t.Fatalf("fallback resolver: %v", err)
			}
			wantTCPSize := <-tcpSize
			if calls != 2 || result == nil || len(result.Attempts) != 2 || !result.UDPToTCPFallback || result.PeerIP != "127.0.0.1" || result.ResponseSize != wantTCPSize {
				t.Fatalf("fallback result = %+v; calls=%d size=%d", result, calls, wantTCPSize)
			}
			if test.wantErr {
				if !errors.Is(observeErr, ErrMalformedResponse) || result.Outcome != OutcomeMalformed || result.ResponseParsed || result.ResponseHeaderValidated || result.Flags != (Flags{}) || len(result.Sections.Answer) != 0 {
					t.Fatalf("final TCP conversion failure = %+v, %v", result, observeErr)
				}
			} else if observeErr != nil || result.Outcome != OutcomeAnswer || len(result.Sections.Answer) != 1 || !strings.Contains(result.Sections.Answer[0].DisplayRData, "203.0.113.9") {
				t.Fatalf("completed fallback = %+v, %v", result, observeErr)
			}
		})
	}
}

func TestUDPAndTCPFallbackReceiveIndependentAttemptTimeouts(t *testing.T) {
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			serverErr <- err
			return
		}
		time.Sleep(325 * time.Millisecond)
		truncated := new(dns.Msg)
		truncated.SetReply(query)
		truncated.Truncated = true
		wire, err := truncated.Pack()
		if err == nil {
			_, err = udpConn.WriteTo(wire, peer)
		}
		if err != nil {
			serverErr <- err
			return
		}

		conn, err := tcpListener.Accept()
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
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		time.Sleep(325 * time.Millisecond)
		response := testAResponse(tcpQuery)
		responseWire, err := response.Pack()
		if err == nil {
			err = writeDNSFrame(conn, responseWire)
		}
		serverErr <- err
	}()

	engine := newTestEngine(t, func(config *Config) {
		config.Timeout = 500 * time.Millisecond
	})
	started := time.Now()
	result, err := engine.Observe(context.Background(), Endpoint{
		Protocol:  ProtocolUDP,
		Address:   "resolver.test",
		ConnectIP: "127.0.0.1",
		Port:      uint16(port),
	}, Query{Name: "example.com.", Type: dns.TypeA})
	if err != nil {
		t.Fatalf("fallback should receive a fresh attempt timeout: %v", err)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("delayed resolver: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 600*time.Millisecond {
		t.Fatalf("test did not consume most of both attempt windows: %s", elapsed)
	}
	if !result.UDPToTCPFallback || len(result.Attempts) != 2 || result.Outcome != OutcomeAnswer {
		t.Fatalf("fallback result = %+v", result)
	}
}

func TestTCValidationAlwaysFallsBackAndRetainsHeaderEvidence(t *testing.T) {
	for _, udpMode := range []string{"unpack_failure", "invalid_tail"} {
		for _, tcpSuccess := range []bool{true, false} {
			name := fmt.Sprintf("%s/tcp_success_%t", udpMode, tcpSuccess)
			t.Run(name, func(t *testing.T) {
				endpoint, serverErr := startTCValidationResolver(t, udpMode, tcpSuccess)
				engine := newTestEngine(t, nil)
				result, observeErr := engine.Observe(context.Background(), endpoint, Query{Name: "example.com.", Type: dns.TypeA})
				if err := receiveServerError(serverErr); err != nil {
					t.Fatalf("TC resolver: %v", err)
				}
				if !result.UDPToTCPFallback || len(result.Attempts) != 2 {
					t.Fatalf("fallback attempts = %+v", result)
				}
				if tcpSuccess {
					if observeErr != nil || !result.ResponseParsed || result.ResponseHeaderValidated || result.Outcome != OutcomeAnswer {
						t.Fatalf("completed fallback = %+v, %v", result, observeErr)
					}
					return
				}
				if observeErr == nil {
					t.Fatal("failed TCP fallback returned no error")
				}
				if result.ResponseParsed || !result.ResponseHeaderValidated || result.Outcome != OutcomeTruncatedResponse || !result.Flags.Response || !result.Flags.Truncated || !result.ResponseTruncated || result.ResultTruncated {
					t.Fatalf("retained header evidence = %+v", result)
				}
				observation, err := ToObservation(result, observeErr, testObservationEnvelope())
				if err != nil {
					t.Fatalf("convert retained header evidence: %v", err)
				}
				if observation.Outcome != dnsobs.DNSOutcomeTruncatedResponse || observation.RCode == nil || *observation.RCode != 0 || !observation.Flags.Response || !observation.Flags.Truncated || !observation.ResponseTruncated || observation.ResultTruncated {
					t.Fatalf("truncated observation = %+v", observation)
				}
				if observation.Comparison != dnsobs.ComparisonUnknown || observation.DNSSEC.Status != dnsobs.DNSSECIndeterminate || observation.DNSSEC.LocallyValidated || observation.Sections.RecordCount() != 0 || observation.Error == nil {
					t.Fatalf("truncated observation contract = %+v", observation)
				}
			})
		}
	}
}

func TestMalformedTCPFallbackUsesFinalTCPHeaderProvenance(t *testing.T) {
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	tcpResponseSize := make(chan int, 1)
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			serverErr <- err
			return
		}
		udpResponse := new(dns.Msg)
		udpResponse.SetReply(query)
		udpResponse.Rcode = dns.RcodeNameError
		udpResponse.Truncated = true
		udpResponse.RecursionAvailable = true
		udpWire, err := udpResponse.Pack()
		if err == nil {
			_, err = udpConn.WriteTo(udpWire, peer)
		}
		if err != nil {
			serverErr <- err
			return
		}

		conn, err := tcpListener.Accept()
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
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		tcpResponse := new(dns.Msg)
		tcpResponse.SetReply(tcpQuery)
		tcpResponse.Rcode = dns.RcodeRefused
		tcpResponse.Authoritative = true
		tcpResponse.Truncated = true
		tcpResponse.RecursionAvailable = false
		tcpResponse.CheckingDisabled = true
		tcpWire, err := tcpResponse.Pack()
		if err == nil {
			tcpWire = append(tcpWire, 0xa5)
			tcpResponseSize <- len(tcpWire)
			err = writeDNSFrame(conn, tcpWire)
		}
		serverErr <- err
	}()

	result, err := newTestEngine(t, nil).Observe(context.Background(), Endpoint{
		Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port),
	}, Query{Name: "example.com.", Type: dns.TypeA})
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("Observe error = %v, want ErrMalformedResponse", err)
	}
	if serverErr := receiveServerError(serverErr); serverErr != nil {
		t.Fatalf("fallback resolver: %v", serverErr)
	}
	wantSize := <-tcpResponseSize
	if result == nil || result.PeerIP != "127.0.0.1" || result.ResponseSize != wantSize || !result.UDPToTCPFallback || len(result.Attempts) != 2 {
		t.Fatalf("final TCP provenance = %+v, want size %d", result, wantSize)
	}
	if result.RCode != dns.RcodeRefused || !result.Flags.Authoritative || !result.Flags.Truncated || !result.Flags.CheckingDisabled || result.Flags.RecursionAvailable || result.Outcome != OutcomeTruncatedResponse || !result.ResponseHeaderValidated || result.ResponseParsed {
		t.Fatalf("final TCP header evidence = %+v", result)
	}

	observation, convertErr := ToObservation(result, err, testObservationEnvelope())
	if convertErr != nil {
		t.Fatalf("ToObservation: %v", convertErr)
	}
	if observation.Protocol != dnsobs.ProtocolTCP || observation.PeerIP != "127.0.0.1" || observation.ResponseSizeBytes != wantSize || observation.RCode == nil || *observation.RCode != dns.RcodeRefused {
		t.Fatalf("observation provenance = %+v", observation)
	}
	if observation.Outcome != dnsobs.DNSOutcomeTruncatedResponse || !observation.Flags.Authoritative || !observation.Flags.Truncated || !observation.Flags.CheckingDisabled || observation.Flags.RecursionAvailable || observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" || observation.Error.Retryable {
		t.Fatalf("observation header/error = %+v", observation)
	}
}

func TestUnverifiableMalformedTCPFallbackDoesNotMixUDPEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		mode    string
		wantErr error
	}{
		{name: "non-TC trailing byte", mode: "non_tc_trailing", wantErr: ErrMalformedResponse},
		{name: "wrong ID TC", mode: "wrong_id_tc", wantErr: ErrResponseMismatch},
		{name: "short wire", mode: "short_wire", wantErr: ErrMalformedResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, responseSize, serverErr := startUnverifiableTCPFallbackResolver(t, test.mode)
			result, observeErr := newTestEngine(t, nil).Observe(context.Background(), endpoint, Query{Name: "example.com.", Type: dns.TypeA})
			if !errors.Is(observeErr, test.wantErr) {
				t.Fatalf("Observe error = %v, want %v", observeErr, test.wantErr)
			}
			if err := receiveServerError(serverErr); err != nil {
				t.Fatalf("fallback resolver: %v", err)
			}
			wantSize := <-responseSize
			if result == nil || result.PeerIP != "127.0.0.1" || result.ResponseSize != wantSize || !result.UDPToTCPFallback || len(result.Attempts) != 2 {
				t.Fatalf("final TCP provenance = %+v, want size %d", result, wantSize)
			}
			if result.ResponseParsed || result.ResponseHeaderValidated || result.Outcome != OutcomeMalformed || result.Flags != (Flags{}) || len(result.Sections.Answer)+len(result.Sections.Authority)+len(result.Sections.Additional) != 0 || result.EDNS.Present || result.Message != nil || result.ResponseTruncated || result.ResultTruncated {
				t.Fatalf("unverifiable TCP retained DNS evidence = %+v", result)
			}

			observation, err := ToObservation(result, observeErr, testObservationEnvelope())
			if err != nil {
				t.Fatalf("ToObservation: %v", err)
			}
			if observation.TransportStatus != dnsobs.TransportSuccess || observation.Protocol != dnsobs.ProtocolTCP || observation.PeerIP != "127.0.0.1" || observation.ResponseSizeBytes != wantSize || observation.Outcome != dnsobs.DNSOutcomeMalformed || observation.ResponseTruncated || observation.ResultTruncated {
				t.Fatalf("malformed observation provenance = %+v", observation)
			}
			if observation.RCode != nil || observation.ExtendedRCode != nil || observation.Flags != (dnsobs.DNSFlags{}) || observation.Sections.RecordCount() != 0 || observation.EDNS.Present || observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" || observation.Error.Retryable {
				t.Fatalf("malformed observation retained DNS evidence = %+v", observation)
			}
		})
	}
}

func TestDirectTCPExchange(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP resolver: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		wire, err := readFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			serverErr <- err
			return
		}
		if err := expectRequestStreamOpen(conn); err != nil {
			serverErr <- err
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.20").To4()}}
		responseWire, err := response.Pack()
		if err == nil {
			err = writeDNSFrame(conn, responseWire)
		}
		serverErr <- err
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	engine := newTestEngine(t, nil)
	result, err := engine.Observe(context.Background(), Endpoint{Protocol: ProtocolTCP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, Query{Name: "example.com.", Type: dns.TypeA})
	if err != nil {
		t.Fatalf("direct TCP observe: %v", err)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("TCP resolver: %v", err)
	}
	if result.Protocol != ProtocolTCP || result.PeerIP != "127.0.0.1" || result.Outcome != OutcomeAnswer || len(result.Sections.Answer) != 1 {
		t.Fatalf("TCP result = %+v", result)
	}
}

func TestTCPFallbackTimeoutRetainsValidatedUDPEvidence(t *testing.T) {
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	release := make(chan struct{})
	serverErr := make(chan error, 1)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			serverErr <- err
			return
		}
		truncated := new(dns.Msg)
		truncated.SetReply(query)
		truncated.Truncated = true
		wire, err := truncated.Pack()
		if err == nil {
			_, err = udpConn.WriteTo(wire, peer)
		}
		if err != nil {
			serverErr <- err
			return
		}
		conn, err := tcpListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if _, err := readFrame(conn); err != nil {
			serverErr <- err
			return
		}
		<-release
		serverErr <- nil
	}()

	engine := newTestEngine(t, func(config *Config) { config.Timeout = 80 * time.Millisecond })
	result, observeErr := engine.Observe(context.Background(), Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, Query{Name: "example.com.", Type: dns.TypeNS})
	close(release)
	if !errors.Is(observeErr, context.DeadlineExceeded) {
		t.Fatalf("fallback error = %v, want deadline exceeded", observeErr)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("fallback resolver: %v", err)
	}
	if result == nil || !result.ResponseParsed || result.Message == nil || result.Outcome != OutcomeNoData || !result.Flags.Truncated || !result.ResponseTruncated || result.ResultTruncated {
		t.Fatalf("retained UDP evidence = %+v", result)
	}
	if !result.UDPToTCPFallback || len(result.Attempts) != 2 || !result.Attempts[0].Truncated || result.Attempts[1].Protocol != ProtocolTCP || result.Attempts[1].Error == "" {
		t.Fatalf("fallback attempts = %+v", result)
	}
	envelope := testObservationEnvelope()
	envelope.Question.Type = dnsobs.RRTypeNS
	observation, err := ToObservation(result, observeErr, envelope)
	if err != nil {
		t.Fatalf("convert fallback timeout: %v", err)
	}
	udpEvidenceAt := observation.Attempts[0].FinishedAt
	if observation.PeerIP != result.PeerIP || !observation.ObservedAt.Equal(udpEvidenceAt) || observation.DurationMS != result.Duration.Milliseconds() {
		t.Fatalf("fallback operation metadata = %+v, result = %+v", observation, result)
	}
}

func TestIPv6UDPAndTCPExchanges(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		conn, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback UDP unavailable: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		serverErr := make(chan error, 1)
		go func() {
			buffer := make([]byte, 65535)
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				serverErr <- err
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(buffer[:n]); err != nil {
				serverErr <- err
				return
			}
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::20")}}
			wire, err := response.Pack()
			if err == nil {
				_, err = conn.WriteTo(wire, peer)
			}
			serverErr <- err
		}()
		port := conn.LocalAddr().(*net.UDPAddr).Port
		result, err := newTestEngine(t, nil).Observe(context.Background(), Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "::1", Port: uint16(port)}, Query{Name: "example.com.", Type: dns.TypeAAAA})
		if err != nil {
			t.Fatalf("IPv6 UDP observe: %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("IPv6 UDP resolver: %v", err)
		}
		if result.PeerIP != "::1" || result.Outcome != OutcomeAnswer {
			t.Fatalf("IPv6 UDP result = %+v", result)
		}
	})

	t.Run("TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback TCP unavailable: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		serverErr := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			wire, err := readFrame(conn)
			if err != nil {
				serverErr <- err
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(wire); err != nil {
				serverErr <- err
				return
			}
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::21")}}
			responseWire, err := response.Pack()
			if err == nil {
				err = writeDNSFrame(conn, responseWire)
			}
			serverErr <- err
		}()
		port := listener.Addr().(*net.TCPAddr).Port
		result, err := newTestEngine(t, nil).Observe(context.Background(), Endpoint{Protocol: ProtocolTCP, Address: "resolver.test", ConnectIP: "::1", Port: uint16(port)}, Query{Name: "example.com.", Type: dns.TypeAAAA})
		if err != nil {
			t.Fatalf("IPv6 TCP observe: %v", err)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("IPv6 TCP resolver: %v", err)
		}
		if result.PeerIP != "::1" || result.Outcome != OutcomeAnswer {
			t.Fatalf("IPv6 TCP result = %+v", result)
		}
	})
}

func TestResponseIDAndQuestionAreValidated(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*dns.Msg)
	}{
		{name: "ID", mutate: func(response *dns.Msg) { response.Id++ }},
		{name: "question name", mutate: func(response *dns.Msg) { response.Question[0].Name = "other.example." }},
		{name: "question type", mutate: func(response *dns.Msg) { response.Question[0].Qtype = dns.TypeAAAA }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, serverErr := startUDPResolver(t, func(query *dns.Msg) (*dns.Msg, error) {
				response := new(dns.Msg)
				response.SetReply(query)
				test.mutate(response)
				return response, nil
			})
			engine := newTestEngine(t, nil)
			result, err := engine.Observe(context.Background(), endpoint, Query{Name: "example.com", Type: dns.TypeA})
			if !errors.Is(err, ErrResponseMismatch) {
				t.Fatalf("observe error = %v, want ErrResponseMismatch", err)
			}
			if result == nil || result.Outcome != OutcomeMalformed {
				t.Fatalf("result = %+v, want malformed evidence", result)
			}
			if serverErr := receiveServerError(serverErr); serverErr != nil {
				t.Fatalf("UDP server: %v", serverErr)
			}
		})
	}
}

func TestUDPAndTCPRejectTrailingDNSBytes(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen UDP: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		responseSize := make(chan int, 1)
		serverErr := make(chan error, 1)
		go func() {
			buffer := make([]byte, 65535)
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				serverErr <- err
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(buffer[:n]); err != nil {
				serverErr <- err
				return
			}
			wire, err := testAResponse(query).Pack()
			if err == nil {
				wire = append(wire, 0xa5)
				responseSize <- len(wire)
				_, err = conn.WriteTo(wire, peer)
			}
			serverErr <- err
		}()
		port := conn.LocalAddr().(*net.UDPAddr).Port
		result, observeErr := newTestEngine(t, nil).Observe(context.Background(), Endpoint{
			Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port),
		}, Query{Name: "example.com.", Type: dns.TypeA})
		if !errors.Is(observeErr, ErrMalformedResponse) {
			t.Fatalf("Observe error = %v, want ErrMalformedResponse", observeErr)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("UDP resolver: %v", err)
		}
		if result == nil || result.Outcome != OutcomeMalformed || result.ResponseSize != <-responseSize {
			t.Fatalf("malformed UDP result = %+v", result)
		}
	})

	t.Run("TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen TCP: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		responseSize := make(chan int, 1)
		serverErr := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
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
			wire, err := testAResponse(query).Pack()
			if err == nil {
				wire = append(wire, 0xa5)
				responseSize <- len(wire)
				err = writeDNSFrame(conn, wire)
			}
			serverErr <- err
		}()
		port := listener.Addr().(*net.TCPAddr).Port
		result, observeErr := newTestEngine(t, nil).Observe(context.Background(), Endpoint{
			Protocol: ProtocolTCP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port),
		}, Query{Name: "example.com.", Type: dns.TypeA})
		if !errors.Is(observeErr, ErrMalformedResponse) {
			t.Fatalf("Observe error = %v, want ErrMalformedResponse", observeErr)
		}
		if err := receiveServerError(serverErr); err != nil {
			t.Fatalf("TCP resolver: %v", err)
		}
		if result == nil || result.Outcome != OutcomeMalformed || result.ResponseSize != <-responseSize {
			t.Fatalf("malformed TCP result = %+v", result)
		}
	})
}

func TestTimeoutAndCancellation(t *testing.T) {
	endpoint, received, stop := startSilentUDPResolver(t)
	defer stop()
	engine := newTestEngine(t, func(config *Config) { config.Timeout = 40 * time.Millisecond })
	result, err := engine.Observe(context.Background(), endpoint, Query{Name: "example.com", Type: dns.TypeA})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	if result == nil || len(result.Attempts) != 1 || result.Attempts[0].Error == "" {
		t.Fatalf("timeout result = %+v", result)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("silent resolver did not receive query")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = engine.Observe(ctx, endpoint, Query{Name: "example.com", Type: dns.TypeA})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
}

func TestOutcomeNegativeTTLAndAliasClassification(t *testing.T) {
	engine := newTestEngine(t, nil)
	question := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	query := new(dns.Msg)
	query.Question = []dns.Question{question}

	t.Run("NXDOMAIN", func(t *testing.T) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Rcode = dns.RcodeNameError
		response.Ns = []dns.RR{testSOA(600, 300)}
		result := &Result{Question: question}
		if err := engine.populateResult(result, response); err != nil {
			t.Fatalf("populate NXDOMAIN: %v", err)
		}
		if result.Outcome != OutcomeNXDomain || result.NegativeTTL == nil || *result.NegativeTTL != 300 {
			t.Fatalf("NXDOMAIN = %+v", result)
		}
	})

	t.Run("out-of-zone CNAME only is an alias answer", func(t *testing.T) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "Target.Elsewhere."}}
		result := &Result{Question: question}
		if err := engine.populateResult(result, response); err != nil {
			t.Fatalf("populate CNAME-only: %v", err)
		}
		if result.Outcome != OutcomeAnswer || result.NegativeTTL != nil {
			t.Fatalf("CNAME-only result = %+v", result)
		}
		if len(result.AliasChain.Hops) != 1 || result.AliasChain.Hops[0].Type != "CNAME" || result.AliasChain.Hops[0].From != "www.example." || result.AliasChain.Hops[0].To != "target.elsewhere." || result.AliasChain.TerminalName != "target.elsewhere." {
			t.Fatalf("alias chain = %+v", result.AliasChain)
		}
	})

	t.Run("CNAME plus SOA is terminal NODATA", func(t *testing.T) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "Target.Example."}}
		response.Ns = []dns.RR{testSOA(120, 600)}
		result := &Result{Question: question}
		if err := engine.populateResult(result, response); err != nil {
			t.Fatalf("populate CNAME-only: %v", err)
		}
		if result.Outcome != OutcomeNoData || result.NegativeTTL == nil || *result.NegativeTTL != 120 {
			t.Fatalf("CNAME-only result = %+v", result)
		}
		if len(result.AliasChain.Hops) != 1 || result.AliasChain.Hops[0].Type != "CNAME" || result.AliasChain.Hops[0].From != "www.example." || result.AliasChain.Hops[0].To != "target.example." || result.AliasChain.TerminalName != "target.example." {
			t.Fatalf("alias chain = %+v", result.AliasChain)
		}
	})

	t.Run("CNAME terminal answer", func(t *testing.T) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.7").To4()},
		}
		result := &Result{Question: question}
		if err := engine.populateResult(result, response); err != nil {
			t.Fatalf("populate terminal answer: %v", err)
		}
		if result.Outcome != OutcomeAnswer || result.NegativeTTL != nil {
			t.Fatalf("terminal answer = %+v", result)
		}
	})

	for _, row := range []struct {
		rcode int
		want  Outcome
	}{
		{rcode: dns.RcodeServerFailure, want: OutcomeServFail},
		{rcode: dns.RcodeRefused, want: OutcomeRefused},
		{rcode: dns.RcodeFormatError, want: OutcomeOther},
		{rcode: dns.RcodeNotImplemented, want: OutcomeOther},
	} {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Rcode = row.rcode
		result := &Result{Question: question}
		if err := engine.populateResult(result, response); err != nil {
			t.Fatalf("populate rcode %d: %v", row.rcode, err)
		}
		if result.Outcome != row.want {
			t.Fatalf("rcode %d outcome = %q, want %q", row.rcode, result.Outcome, row.want)
		}
	}
}

func TestDNAMEClassificationSynthesisAndSingletons(t *testing.T) {
	engine := newTestEngine(t, nil)
	question := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	query := new(dns.Msg)
	query.Question = []dns.Question{question}
	dname := func(target string) *dns.DNAME {
		return &dns.DNAME{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}
	}
	cname := func(target string) *dns.CNAME {
		return &dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}
	}

	for _, test := range []struct {
		name       string
		target     string
		soa        bool
		cname      string
		wantTarget string
		want       Outcome
	}{
		{name: "DNAME only", target: "elsewhere.", wantTarget: "www.elsewhere.", want: OutcomeAnswer},
		{name: "DNAME plus SOA", target: "elsewhere.", soa: true, wantTarget: "www.elsewhere.", want: OutcomeNoData},
		{name: "DNAME to root", target: ".", wantTarget: "www.", want: OutcomeAnswer},
		{name: "matching synthesized CNAME", target: "elsewhere.", cname: "www.elsewhere.", wantTarget: "www.elsewhere.", want: OutcomeAnswer},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{dname(test.target)}
			if test.cname != "" {
				response.Answer = append(response.Answer, cname(test.cname))
			}
			if test.soa {
				response.Ns = []dns.RR{testSOA(120, 600)}
			}
			result := &Result{Question: question}
			if err := engine.populateResult(result, response); err != nil {
				t.Fatalf("populate DNAME response: %v", err)
			}
			if result.Outcome != test.want || len(result.AliasChain.Hops) != 1 || result.AliasChain.Hops[0].Type != "DNAME" || result.AliasChain.Hops[0].To != test.wantTarget || result.AliasChain.TerminalName != test.wantTarget {
				t.Fatalf("DNAME result = %+v", result)
			}
		})
	}

	conflicts := [][]dns.RR{
		{cname("one.example."), cname("two.example.")},
		{dname("one.example."), dname("two.example.")},
		{dname("elsewhere."), cname("conflict.elsewhere.")},
	}
	for index, records := range conflicts {
		for _, ordered := range [][]dns.RR{records, {records[1], records[0]}} {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = ordered
			result := &Result{Question: question}
			if err := engine.populateResult(result, response); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("conflict %d order %+v error = %v, want ErrMalformedResponse", index, ordered, err)
			}
		}
	}
}

func TestReferralAndWireAliasCrossZoneIsUnknown(t *testing.T) {
	engine := newTestEngine(t, nil)
	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeA)

	referral := new(dns.Msg)
	referral.SetReply(query)
	referral.Authoritative = false
	referral.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.net."}}
	result := &Result{Question: query.Question[0], allowReferral: true}
	if err := engine.populateResult(result, referral); err != nil {
		t.Fatalf("populate referral: %v", err)
	}
	if result.Outcome != OutcomeReferral || result.NegativeTTL != nil {
		t.Fatalf("referral result = %+v", result)
	}
	recursiveResult := &Result{Question: query.Question[0]}
	if err := engine.populateResult(recursiveResult, referral); err != nil {
		t.Fatalf("populate recursive response: %v", err)
	}
	if recursiveResult.Outcome != OutcomeNoData {
		t.Fatalf("recursive authority NS outcome = %q, want NODATA", recursiveResult.Outcome)
	}

	for _, test := range []struct {
		name   string
		target string
	}{
		{name: "same registrable domain", target: "edge.example.com."},
		{name: "different registrable domain", target: "edge.example.net."},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: test.target}}
			aliasResult := &Result{Question: query.Question[0]}
			if err := engine.populateResult(aliasResult, response); err != nil {
				t.Fatalf("populate alias: %v", err)
			}
			if aliasResult.AliasChain.CrossZoneKnown || aliasResult.AliasChain.CrossZone {
				t.Fatalf("wire-only alias claimed a DNS zone cut: %+v", aliasResult.AliasChain)
			}
		})
	}
}

func TestResponseRejectsMisplacedDuplicateAndMalformedOPT(t *testing.T) {
	engine := newTestEngine(t, nil)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	newOPT := func() *dns.OPT {
		return &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}
	}
	for name, mutate := range map[string]func(*dns.Msg){
		"answer":    func(message *dns.Msg) { message.Answer = []dns.RR{newOPT()} },
		"authority": func(message *dns.Msg) { message.Ns = []dns.RR{newOPT()} },
		"duplicate": func(message *dns.Msg) { message.Extra = []dns.RR{newOPT(), newOPT()} },
		"non-root owner": func(message *dns.Msg) {
			opt := newOPT()
			opt.Hdr.Name = "example.com."
			message.Extra = []dns.RR{opt}
		},
		"small UDP size": func(message *dns.Msg) {
			opt := newOPT()
			opt.Hdr.Class = 511
			message.Extra = []dns.RR{opt}
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := new(dns.Msg)
			response.SetReply(query)
			mutate(response)
			result := &Result{Question: query.Question[0]}
			if err := engine.populateResult(result, response); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("populate error = %v, want ErrMalformedResponse", err)
			}
			if result.Outcome != OutcomeMalformed || result.ResponseParsed {
				t.Fatalf("malformed result = %+v", result)
			}
		})
	}
}

func TestExtendedRCodeIsPreserved(t *testing.T) {
	engine := newTestEngine(t, nil)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.SetEdns0(DefaultUDPSize, false)
	response.IsEdns0().SetExtendedRcode(dns.RcodeBadVers)
	result := &Result{Question: query.Question[0]}
	if err := engine.populateResult(result, response); err != nil {
		t.Fatalf("populate BADVERS: %v", err)
	}
	if result.RCode != 0 || result.ExtendedRCode != 1 || result.FullRCode() != dns.RcodeBadVers || result.Outcome != OutcomeOther {
		t.Fatalf("BADVERS result = %+v", result)
	}
}

func TestPerSectionRecordAndWireSizeLimits(t *testing.T) {
	if _, err := New(Config{MaxRecordsPerSection: MaxRecordsPerSection + 1}); err == nil {
		t.Fatal("New accepted record limit above hard maximum")
	}
	engine := newTestEngine(t, func(config *Config) { config.MaxRecordsPerSection = 1 })
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Truncated = true
	response.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1").To4()},
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.2").To4()},
	}
	limited := &Result{Question: query.Question[0]}
	if err := engine.populateResult(limited, response); err != nil {
		t.Fatalf("populate record-limited result: %v", err)
	}
	if !limited.ResultTruncated || !limited.ResponseTruncated || len(limited.Sections.Answer) != 0 {
		t.Fatalf("record-limited result = %+v", limited)
	}
	started := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	limited.Protocol = ProtocolTCP
	limited.PeerIP = "8.8.8.8"
	limited.StartedAt = started
	limited.Duration = time.Millisecond
	limited.ResponseSize = 100
	limited.Attempts = []Attempt{{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 100, Truncated: true}}
	envelope := testObservationEnvelope()
	envelope.Endpoint.Protocol = dnsobs.ProtocolTCP
	observation, err := ToObservation(limited, nil, envelope)
	if err != nil {
		t.Fatalf("convert double-truncated result: %v", err)
	}
	if !observation.ResponseTruncated || !observation.ResultTruncated {
		t.Fatalf("double-truncated observation = %+v", observation)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		if _, err := readFrame(server); err != nil {
			serverDone <- err
			return
		}
		serverDone <- writeAll(server, []byte{0, 200})
	}()
	if _, err := exchangeFramed(client, make([]byte, 12), 100); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("framed size error = %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("framed test server: %v", err)
	}
}

func TestRecordLimitDropsPoisonedRRSetAtomically(t *testing.T) {
	engine := newTestEngine(t, nil)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "Example.COM", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1").To4()},
		&dns.RFC3597{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, Rdata: "C0000202"},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "other.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")},
	}
	result := &Result{Question: query.Question[0]}
	if err := engine.populateResult(result, response); err != nil {
		t.Fatalf("populate poisoned RRset: %v", err)
	}
	if !result.ResultTruncated || result.ResponseTruncated || len(result.Sections.Answer) != 1 ||
		result.Sections.Answer[0].Owner != "other.example.com." || result.Sections.Answer[0].Type != "AAAA" {
		t.Fatalf("poisoned A RRset was partially retained: %+v", result)
	}
}

func TestRecordLimitRetainsOnlyWholeRRSetPrefix(t *testing.T) {
	engine := newTestEngine(t, func(config *Config) { config.MaxRecordsPerSection = 2 })
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1").To4()},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "v6.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.TXT{Hdr: dns.RR_Header{Name: "later.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"later"}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "V6.EXAMPLE.COM", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::2")},
	}
	result := &Result{Question: query.Question[0]}
	if err := engine.populateResult(result, response); err != nil {
		t.Fatalf("populate cross-RRset budget result: %v", err)
	}
	if !result.ResultTruncated || result.ResponseTruncated || len(result.Sections.Answer) != 1 ||
		result.Sections.Answer[0].Owner != "example.com." || result.Sections.Answer[0].Type != "A" {
		t.Fatalf("record budget did not retain the whole RRset prefix: %+v", result)
	}
}

func TestAdditionalOPTDoesNotConsumeRRSetRecordBudget(t *testing.T) {
	engine := newTestEngine(t, func(config *Config) { config.MaxRecordsPerSection = 2 })
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "NS.EXAMPLE.COM", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.53").To4()},
		&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: DefaultUDPSize}},
		&dns.A{Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.54").To4()},
	}
	result := &Result{Question: query.Question[0]}
	if err := engine.populateResult(result, response); err != nil {
		t.Fatalf("populate Additional OPT budget result: %v", err)
	}
	if result.ResultTruncated || result.ResponseTruncated || !result.EDNS.Present || len(result.Sections.Additional) != 2 {
		t.Fatalf("OPT consumed Additional RRset budget: %+v", result)
	}
	for _, record := range result.Sections.Additional {
		if record.Owner != "ns.example.com." || record.Type != "A" || record.RRSetRecordCount != 2 {
			t.Fatalf("Additional RRset was not normalized atomically: %+v", result.Sections.Additional)
		}
	}
}

func TestParsePreservesRRSetRecordCountIncludingDuplicates(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	record := &dns.A{
		Hdr: dns.RR_Header{Name: "EXAMPLE.COM", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1").To4(),
	}
	response.Answer = []dns.RR{record, dns.Copy(record)}
	response.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: DefaultUDPSize}}}

	result := &Result{Question: query.Question[0]}
	if err := newTestEngine(t, nil).populateResult(result, response); err != nil {
		t.Fatalf("populate duplicate RRset: %v", err)
	}
	if len(result.Sections.Answer) != 2 || result.ResultTruncated {
		t.Fatalf("duplicate RRset = %+v", result)
	}
	for _, converted := range result.Sections.Answer {
		if converted.Owner != "example.com." || converted.RRSetRecordCount != 2 {
			t.Fatalf("duplicate count evidence = %+v", result.Sections.Answer)
		}
	}
}

func TestCanonicalRDataNormalizesEmbeddedDomainCase(t *testing.T) {
	assertSame := func(t *testing.T, upper, lower dns.RR) {
		t.Helper()
		upperCanonical, err := canonicalRData(upper)
		if err != nil {
			t.Fatalf("canonical upper: %v", err)
		}
		lowerCanonical, err := canonicalRData(lower)
		if err != nil {
			t.Fatalf("canonical lower: %v", err)
		}
		if upperCanonical != lowerCanonical {
			t.Fatalf("canonical RDATA differs by case: %q != %q", upperCanonical, lowerCanonical)
		}
	}
	for _, pair := range []struct {
		name  string
		upper string
		lower string
	}{
		{name: "NS", upper: "EXAMPLE.COM. 60 IN NS NS1.EXAMPLE.COM.", lower: "example.com. 60 IN NS ns1.example.com."},
		{name: "CNAME", upper: "EXAMPLE.COM. 60 IN CNAME TARGET.EXAMPLE.COM.", lower: "example.com. 60 IN CNAME target.example.com."},
		{name: "DNAME", upper: "EXAMPLE.COM. 60 IN DNAME TARGET.EXAMPLE.COM.", lower: "example.com. 60 IN DNAME target.example.com."},
		{name: "PTR", upper: "EXAMPLE.COM. 60 IN PTR TARGET.EXAMPLE.COM.", lower: "example.com. 60 IN PTR target.example.com."},
		{name: "MX", upper: "EXAMPLE.COM. 60 IN MX 10 MAIL.EXAMPLE.COM.", lower: "example.com. 60 IN MX 10 mail.example.com."},
		{name: "SOA", upper: "EXAMPLE.COM. 60 IN SOA NS1.EXAMPLE.COM. HOSTMASTER.EXAMPLE.COM. 1 3600 600 86400 300", lower: "example.com. 60 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"},
		{name: "SRV", upper: "EXAMPLE.COM. 60 IN SRV 10 20 443 TARGET.EXAMPLE.COM.", lower: "example.com. 60 IN SRV 10 20 443 target.example.com."},
		{name: "RRSIG", upper: "EXAMPLE.COM. 60 IN RRSIG A 13 2 300 20300101000000 20250101000000 12345 SIGNER.EXAMPLE.COM. AQID", lower: "example.com. 60 IN RRSIG A 13 2 300 20300101000000 20250101000000 12345 signer.example.com. AQID"},
		{name: "NSEC", upper: "EXAMPLE.COM. 60 IN NSEC NEXT.EXAMPLE.COM. A RRSIG NSEC", lower: "example.com. 60 IN NSEC next.example.com. A RRSIG NSEC"},
		{name: "SVCB", upper: `EXAMPLE.COM. 60 IN SVCB 1 TARGET.EXAMPLE.COM. alpn="h2"`, lower: `example.com. 60 IN SVCB 1 target.example.com. alpn="h2"`},
		{name: "HTTPS", upper: `EXAMPLE.COM. 60 IN HTTPS 1 TARGET.EXAMPLE.COM. alpn="h2"`, lower: `example.com. 60 IN HTTPS 1 target.example.com. alpn="h2"`},
	} {
		t.Run(pair.name, func(t *testing.T) {
			upper, err := dns.NewRR(pair.upper)
			if err != nil {
				t.Fatalf("parse upper fixture: %v", err)
			}
			lower, err := dns.NewRR(pair.lower)
			if err != nil {
				t.Fatalf("parse lower fixture: %v", err)
			}
			assertSame(t, upper, lower)
		})
	}

	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: "example.com.", Rrtype: rrType, Class: dns.ClassINET, Ttl: 60}
	}
	for _, test := range []struct {
		name   string
		record dns.RR
	}{
		{name: "SSHFP", record: &dns.SSHFP{Hdr: header(dns.TypeSSHFP), Algorithm: 1, Type: 1, FingerPrint: "1234567890abcdef"}},
		{name: "NAPTR", record: &dns.NAPTR{Hdr: header(dns.TypeNAPTR), Order: 10, Preference: 20, Flags: "S", Service: "SIP+D2U", Replacement: "target.example.com."}},
	} {
		t.Run("outside contract "+test.name, func(t *testing.T) {
			canonical, comparable, err := canonicalRDataForFingerprint(test.record)
			if err != nil || comparable || canonical != "" {
				t.Fatalf("outside-contract %s canonical RDATA = %q, comparable=%t, err=%v", test.name, canonical, comparable, err)
			}
		})
	}
}

func TestUnknownRFC3597RDataIsNotFingerprinted(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.90").To4()}}
	response.Extra = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: 65400, Class: dns.ClassINET, Ttl: 60}, Rdata: "00"}}
	result := &Result{Question: query.Question[0]}
	if err := newTestEngine(t, nil).populateResult(result, response); err != nil {
		t.Fatalf("populate unknown RDATA: %v", err)
	}
	if !result.ResultTruncated || result.ResponseTruncated || len(result.Sections.Answer) != 1 || len(result.Sections.Additional) != 0 {
		t.Fatalf("unknown RDATA result = %+v", result)
	}

	started := time.Date(2026, 7, 19, 12, 30, 0, 0, time.UTC)
	result.Protocol = ProtocolUDP
	result.PeerIP = "8.8.8.8"
	result.StartedAt = started
	result.Duration = time.Millisecond
	result.ResponseSize = 100
	result.Attempts = []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 100}}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("convert unknown RDATA result: %v", err)
	}
	if !observation.ResultTruncated || observation.ResponseTruncated || observation.Comparison != dnsobs.ComparisonUnknown || len(observation.Sections.Additional) != 0 {
		t.Fatalf("unknown RDATA observation = %+v", observation)
	}
}

func TestResponseTypesOutsideCanonicalContractAreDroppedAtomically(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.30").To4()}}
	for _, text := range []string{
		"example.com. 60 IN SSHFP 1 1 1234567890abcdef",
		"example.com. 60 IN LOC 52 22 23.000 N 4 53 32.000 E 1.00m",
		`example.com. 60 IN NAPTR 10 20 "S" "SIP+D2U" "" _sip._udp.example.com.`,
	} {
		record, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("parse test RR %q: %v", text, err)
		}
		response.Extra = append(response.Extra, record)
	}

	engine := newTestEngine(t, nil)
	result := &Result{Question: query.Question[0]}
	if err := engine.populateResult(result, response); err != nil {
		t.Fatalf("populate uncommon response types: %v", err)
	}
	if !result.ResultTruncated || result.ResponseTruncated || len(result.Sections.Answer) != 1 || len(result.Sections.Additional) != 0 {
		t.Fatalf("outside-contract RRsets were not dropped atomically: %+v", result)
	}

	started := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	result.Protocol = ProtocolUDP
	result.PeerIP = "8.8.8.8"
	result.StartedAt = started
	result.Duration = time.Millisecond
	result.ResponseSize = 300
	result.Attempts = []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 300}}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("convert uncommon response types: %v", err)
	}
	if observation.ResponseTruncated || !observation.ResultTruncated || observation.Comparison != dnsobs.ComparisonUnknown || len(observation.Sections.Additional) != 0 {
		t.Fatalf("outside-contract RRsets reached the observation: %+v", observation)
	}
	if len(observation.Sections.Answer) != 1 || observation.Sections.Answer[0].RRSetFingerprint == "" {
		t.Fatalf("valid answer evidence was not retained: %+v", observation.Sections.Answer)
	}
}

func TestRawWireRejectsZeroLengthAuditedResponseRData(t *testing.T) {
	for _, rrType := range []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSOA,
		dns.TypeCAA, dns.TypeSRV, dns.TypePTR, dns.TypeDS, dns.TypeDNSKEY, dns.TypeTLSA, dns.TypeSVCB,
		dns.TypeHTTPS, dns.TypeDNAME, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
	} {
		t.Run(dns.TypeToString[rrType], func(t *testing.T) {
			assertRawAdditionalRRRejected(t, rrType, "")
		})
	}
}

func TestRawWireRejectsInvalidSVCBAndHTTPSSemantics(t *testing.T) {
	invalidRData := []struct {
		name string
		hex  string
	}{
		{name: "empty mandatory", hex: "00010000000000"},
		{name: "mandatory duplicate", hex: "000100000000040001000100010003026832"},
		{name: "mandatory key zero", hex: "000100000000020000"},
		{name: "mandatory key absent", hex: "000100000000020003"},
		{name: "mandatory not increasing", hex: "000100000000040003000100010003026832000300020050"},
		{name: "top keys unsorted", hex: "0001000002000000010003026832"},
		{name: "top keys duplicate", hex: "0001000001000302683200010003026833"},
		{name: "no default without alpn", hex: "00010000020000"},
		{name: "empty alpn", hex: "00010000010000"},
		{name: "empty alpn id", hex: "0001000001000100"},
	}
	for _, rrType := range []uint16{dns.TypeSVCB, dns.TypeHTTPS} {
		t.Run(dns.TypeToString[rrType], func(t *testing.T) {
			for _, test := range invalidRData {
				t.Run(test.name, func(t *testing.T) {
					assertRawAdditionalRRRejected(t, rrType, test.hex)
				})
			}
		})
	}
}

func TestRawWireAcceptsAliasModeSVCBAndHTTPSParameters(t *testing.T) {
	for _, rrType := range []uint16{dns.TypeSVCB, dns.TypeHTTPS} {
		t.Run(dns.TypeToString[rrType], func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)
			response := new(dns.Msg)
			response.SetReply(query)
			response.Extra = []dns.RR{&dns.RFC3597{
				Hdr:   dns.RR_Header{Name: "alias.example.", Rrtype: rrType, Class: dns.ClassINET, Ttl: 60},
				Rdata: "000005616C696173076578616D706C650000010003026832",
			}}
			wire, err := response.Pack()
			if err != nil {
				t.Fatalf("pack AliasMode TYPE%d: %v", rrType, err)
			}
			message, err := unpackResponse(wire)
			if err != nil {
				t.Fatalf("unpack AliasMode TYPE%d: %v", rrType, err)
			}
			result := &Result{Question: query.Question[0]}
			if err := newTestEngine(t, nil).populateResult(result, message); err != nil || result.ResultTruncated || len(result.Sections.Additional) != 1 {
				t.Fatalf("AliasMode TYPE%d result=%+v err=%v", rrType, result, err)
			}
		})
	}
}

func assertRawAdditionalRRRejected(t *testing.T, rrType uint16, rdataHex string) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.30").To4(),
	}}
	response.Extra = []dns.RR{&dns.RFC3597{
		Hdr:   dns.RR_Header{Name: "invalid.example.com.", Rrtype: rrType, Class: dns.ClassINET, Ttl: 60},
		Rdata: rdataHex,
	}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatalf("pack raw TYPE%d response: %v", rrType, err)
	}
	message, err := unpackResponse(wire)
	if err != nil {
		return
	}

	result := &Result{Question: query.Question[0]}
	if err := newTestEngine(t, nil).populateResult(result, message); err != nil {
		if !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("reject raw TYPE%d response: %v", rrType, err)
		}
		if len(result.Sections.Answer)+len(result.Sections.Authority)+len(result.Sections.Additional) != 0 {
			t.Fatalf("malformed raw TYPE%d response retained records: %+v", rrType, result.Sections)
		}
		return
	}
	if !result.ResultTruncated || result.ResponseTruncated || len(result.Sections.Answer) != 1 || len(result.Sections.Additional) != 0 {
		t.Fatalf("raw TYPE%d RR was retained: %+v", rrType, result)
	}

	started := time.Date(2026, 7, 19, 12, 45, 0, 0, time.UTC)
	result.Protocol = ProtocolUDP
	result.PeerIP = "8.8.8.8"
	result.StartedAt = started
	result.Duration = time.Millisecond
	result.ResponseSize = len(wire)
	result.Attempts = []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: len(wire)}}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("convert rejected raw TYPE%d response: %v", rrType, err)
	}
	if !observation.ResultTruncated || observation.ResponseTruncated || observation.Comparison != dnsobs.ComparisonUnknown || len(observation.Sections.Additional) != 0 {
		t.Fatalf("raw TYPE%d RR reached observation: %+v", rrType, observation)
	}
	if len(observation.Sections.Answer) != 1 || observation.Sections.Answer[0].RRSetFingerprint == "" {
		t.Fatalf("valid answer was not fingerprinted after rejecting raw TYPE%d RR: %+v", rrType, observation.Sections.Answer)
	}
}

func TestCapabilitiesDoNotClaimIterativeOrDNSSECValidation(t *testing.T) {
	engine := newTestEngine(t, nil)
	capabilities := engine.Capabilities()
	if capabilities.IterativeResolution || capabilities.LocalDNSSECValidation {
		t.Fatalf("engine advertises unimplemented capability: %+v", capabilities)
	}
	if len(capabilities.WireProtocols) != 5 {
		t.Fatalf("wire protocols = %v", capabilities.WireProtocols)
	}
}

func newTestEngine(t *testing.T, mutate func(*Config)) *Engine {
	t.Helper()
	config := Config{
		Timeout:               time.Second,
		AllowPrivateConnectIP: true,
		IDGenerator:           func() (uint16, error) { return 0x1234, nil },
	}
	if mutate != nil {
		mutate(&config)
	}
	engine, err := New(config)
	if err != nil {
		t.Fatalf("new DNS engine: %v", err)
	}
	return engine
}

func startUDPResolver(t *testing.T, handler func(*dns.Msg) (*dns.Msg, error)) (Endpoint, <-chan error) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			done <- err
			return
		}
		response, err := handler(query)
		if err != nil {
			done <- err
			return
		}
		wire, err := response.Pack()
		if err == nil {
			_, err = conn.WriteTo(wire, peer)
		}
		done <- err
	}()
	address := conn.LocalAddr().(*net.UDPAddr)
	return Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(address.Port)}, done
}

func startTruncatedResolver(t *testing.T) (Endpoint, <-chan [2]uint16, <-chan error) {
	t.Helper()
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	ids := make(chan [2]uint16, 1)
	done := make(chan error, 1)
	go func() {
		var observed [2]uint16
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		udpQuery := new(dns.Msg)
		if err := udpQuery.Unpack(buffer[:n]); err != nil {
			done <- err
			return
		}
		observed[0] = udpQuery.Id
		truncated := new(dns.Msg)
		truncated.SetReply(udpQuery)
		truncated.Truncated = true
		truncated.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: udpQuery.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", 200)},
		}}
		wire, err := truncated.Pack()
		if err == nil && len(wire) > 10 {
			wire = wire[:len(wire)-10]
			if _, unpackErr := unpackResponse(wire); unpackErr == nil {
				err = fmt.Errorf("test UDP response was not truncated inside an RR")
			}
		}
		if err == nil {
			_, err = udpConn.WriteTo(wire, peer)
		}
		if err != nil {
			done <- err
			return
		}
		conn, err := tcpListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		queryWire, err := readFrame(conn)
		if err != nil {
			done <- err
			return
		}
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			done <- err
			return
		}
		observed[1] = tcpQuery.Id
		response := new(dns.Msg)
		response.SetReply(tcpQuery)
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: tcpQuery.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		responseWire, err := response.Pack()
		if err != nil {
			done <- err
			return
		}
		frame := make([]byte, 2+len(responseWire))
		binary.BigEndian.PutUint16(frame, uint16(len(responseWire)))
		copy(frame[2:], responseWire)
		for _, value := range frame {
			if _, err := conn.Write([]byte{value}); err != nil {
				done <- err
				return
			}
		}
		ids <- observed
		done <- nil
	}()
	return Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, ids, done
}

func startTCValidationResolver(t *testing.T, udpMode string, tcpSuccess bool) (Endpoint, <-chan error) {
	t.Helper()
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			serverErr <- err
			return
		}
		truncated := new(dns.Msg)
		truncated.SetReply(query)
		truncated.Truncated = true
		switch udpMode {
		case "unpack_failure":
			truncated.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 200)}}}
		case "invalid_tail":
			truncated.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassCHAOS, Ttl: 60}, A: net.ParseIP("192.0.2.80").To4()}}
		default:
			serverErr <- fmt.Errorf("unknown UDP TC mode %q", udpMode)
			return
		}
		wire, err := truncated.Pack()
		if err == nil && udpMode == "unpack_failure" {
			wire = wire[:len(wire)-10]
			if _, unpackErr := unpackResponse(wire); unpackErr == nil {
				err = errors.New("TC fixture unexpectedly remained unpackable")
			}
		}
		if err == nil {
			_, err = udpConn.WriteTo(wire, peer)
		}
		if err != nil {
			serverErr <- err
			return
		}
		conn, err := tcpListener.Accept()
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
		if !tcpSuccess {
			serverErr <- nil
			return
		}
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}
		response := testAResponse(tcpQuery)
		responseWire, err := response.Pack()
		if err == nil {
			err = writeDNSFrame(conn, responseWire)
		}
		serverErr <- err
	}()
	return Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, serverErr
}

func startUnverifiableTCPFallbackResolver(t *testing.T, mode string) (Endpoint, <-chan int, <-chan error) {
	t.Helper()
	udpConn, tcpListener, port := listenUDPAndTCPOnSamePort(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	responseSize := make(chan int, 1)
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			serverErr <- err
			return
		}
		udpResponse := testAResponse(query)
		udpResponse.Truncated = true
		udpResponse.RecursionAvailable = true
		udpWire, err := udpResponse.Pack()
		if err == nil {
			_, err = udpConn.WriteTo(udpWire, peer)
		}
		if err != nil {
			serverErr <- err
			return
		}

		conn, err := tcpListener.Accept()
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
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			serverErr <- err
			return
		}

		var responseWire []byte
		switch mode {
		case "non_tc_trailing":
			response := testAResponse(tcpQuery)
			responseWire, err = response.Pack()
			if err == nil {
				responseWire = append(responseWire, 0xa5)
			}
		case "wrong_id_tc":
			response := new(dns.Msg)
			response.SetReply(tcpQuery)
			response.Id++
			response.Rcode = dns.RcodeNameError
			response.Truncated = true
			responseWire, err = response.Pack()
		case "short_wire":
			responseWire = []byte{0xde, 0xad, 0xbe, 0xef}
		default:
			err = fmt.Errorf("unknown malformed TCP mode %q", mode)
		}
		if err == nil {
			responseSize <- len(responseWire)
			err = writeDNSFrame(conn, responseWire)
		}
		serverErr <- err
	}()
	return Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, responseSize, serverErr
}

func startSilentUDPResolver(t *testing.T) (Endpoint, <-chan struct{}, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent UDP: %v", err)
	}
	received := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 512)
		if _, _, err := conn.ReadFrom(buffer); err == nil {
			received <- struct{}{}
		}
	}()
	stop := func() {
		_ = conn.Close()
		<-done
	}
	address := conn.LocalAddr().(*net.UDPAddr)
	return Endpoint{Protocol: ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(address.Port)}, received, stop
}

func listenUDPAndTCPOnSamePort(t *testing.T) (net.PacketConn, net.Listener, int) {
	t.Helper()
	var lastErr error
	for range 32 {
		udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen UDP fixture: %v", err)
		}
		port := udpConn.LocalAddr().(*net.UDPAddr).Port
		tcpListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return udpConn, tcpListener, port
		}
		lastErr = err
		_ = udpConn.Close()
	}
	t.Fatalf("bind UDP and TCP fixtures to the same port: %v", lastErr)
	return nil, nil, 0
}

func readFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	wire := make([]byte, size)
	_, err := io.ReadFull(reader, wire)
	return wire, err
}

func receiveServerError(errors <-chan error) error {
	select {
	case err := <-errors:
		return err
	case <-time.After(2 * time.Second):
		return fmt.Errorf("test resolver did not finish")
	}
}

func expectRequestStreamOpen(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{})
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 {
		return fmt.Errorf("DNS request contains unexpected trailing bytes")
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("DNS client half-closed the request stream before the response")
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		return fmt.Errorf("waiting for an open DNS request stream: %w", err)
	}
	return nil
}

func testSOA(ttl, minimum uint32) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns1.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minimum,
	}
}

func FuzzUnpackResponseDoesNotPanic(f *testing.F) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	seed, _ := response.Pack()
	f.Add(seed)
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = unpackResponse(wire)
	})
}

func FuzzObservationPipelineDoesNotPanic(f *testing.F) {
	query := new(dns.Msg)
	query.Id = 0x5a5a
	query.SetQuestion("example.com.", dns.TypeA)
	response := testAResponse(query)
	seed, _ := response.Pack()
	f.Add(seed)
	truncated := new(dns.Msg)
	truncated.SetReply(query)
	truncated.Truncated = true
	truncatedWire, _ := truncated.Pack()
	f.Add(truncatedWire)
	f.Add(append(append([]byte(nil), seed...), 0xa5))

	engine := &Engine{maxRecordsPerSection: dnsobs.MaxSectionRecordLimit}
	started := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65535 {
			return
		}
		if wireHasTC(wire) && validateTruncatedResponsePrefix(query, wire) == nil {
			result := &Result{
				Question: query.Question[0], Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started,
				Duration: time.Millisecond, Attempts: []Attempt{
					{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: len(wire), Truncated: true},
					{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: len(wire), Error: ErrMalformedResponse.Error()},
				},
				UDPToTCPFallback: true, ResponseSize: len(wire),
			}
			populateTruncatedResponsePrefix(result, wire)
			_, _ = ToObservation(result, ErrMalformedResponse, testObservationEnvelope())
		}

		message, err := unpackResponse(wire)
		if err != nil || validateResponse(query, message) != nil {
			return
		}
		result := &Result{
			Question: query.Question[0], Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started,
			Duration: time.Millisecond, ResponseSize: len(wire),
			Attempts: []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: len(wire)}},
		}
		if engine.populateResult(result, message) != nil {
			return
		}
		_, _ = ToObservation(result, nil, testObservationEnvelope())
	})
}
