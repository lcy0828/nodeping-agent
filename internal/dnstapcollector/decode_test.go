package dnstapcollector

import (
	"net/netip"
	"testing"
	"time"

	dnstappb "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestDecodeResolverQueryAndResponse(t *testing.T) {
	queryTime := time.Date(2026, time.July, 19, 10, 0, 0, 42, time.UTC)
	queryFrame, responseFrame := resolverFramePair(t, queryTime)
	query, err := decodeFrame(queryFrame, 1)
	if err != nil {
		t.Fatalf("decode query: %v", err)
	}
	response, err := decodeFrame(responseFrame, 2)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if query.Kind != EventResolverQuery || response.Kind != EventResolverResponse {
		t.Fatalf("kinds = %q %q", query.Kind, response.Kind)
	}
	if query.UpstreamIP != "192.0.2.53" || query.LocalIP != "0.0.0.0" || query.LocalPort != 53000 || query.UpstreamPort != 53 {
		t.Fatalf("query addressing = %+v", query)
	}
	if query.Question != (Question{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassINET}) || query.DNSID != 0x4242 {
		t.Fatalf("query DNS identity = id %d question %+v", query.DNSID, query.Question)
	}
	if !query.QueryTime.Equal(response.QueryTime) || !response.ResponseTime.After(response.QueryTime) {
		t.Fatalf("timestamps = query %s response query %s finish %s", query.QueryTime, response.QueryTime, response.ResponseTime)
	}
}

func TestDecodeRejectsUnsupportedOrMalformedEvidence(t *testing.T) {
	queryTime := time.Now().UTC()
	valid := resolverTap(t, dnstappb.Message_RESOLVER_QUERY, queryTime)
	tests := []struct {
		name   string
		mutate func(*dnstappb.Dnstap)
	}{
		{name: "missing envelope type", mutate: func(value *dnstappb.Dnstap) { value.Type = nil }},
		{name: "unsupported message type", mutate: func(value *dnstappb.Dnstap) { value.Message.Type = dnstappb.Message_CLIENT_QUERY.Enum() }},
		{name: "missing family", mutate: func(value *dnstappb.Dnstap) { value.Message.SocketFamily = nil }},
		{name: "DoH protocol", mutate: func(value *dnstappb.Dnstap) { value.Message.SocketProtocol = dnstappb.SocketProtocol_DOH.Enum() }},
		{name: "short upstream address", mutate: func(value *dnstappb.Dnstap) { value.Message.ResponseAddress = []byte{1, 2, 3} }},
		{name: "unspecified upstream", mutate: func(value *dnstappb.Dnstap) { value.Message.ResponseAddress = []byte{0, 0, 0, 0} }},
		{name: "zero local port", mutate: func(value *dnstappb.Dnstap) { value.Message.QueryPort = proto.Uint32(0) }},
		{name: "bad nanoseconds", mutate: func(value *dnstappb.Dnstap) { value.Message.QueryTimeNsec = proto.Uint32(1_000_000_000) }},
		{name: "wrong QR bit", mutate: func(value *dnstappb.Dnstap) {
			message := new(dns.Msg)
			if err := message.Unpack(value.Message.QueryMessage); err != nil {
				panic(err)
			}
			message.Response = true
			value.Message.QueryMessage, _ = message.Pack()
		}},
		{name: "two questions", mutate: func(value *dnstappb.Dnstap) {
			message := new(dns.Msg)
			if err := message.Unpack(value.Message.QueryMessage); err != nil {
				panic(err)
			}
			message.Question = append(message.Question, message.Question[0])
			value.Message.QueryMessage, _ = message.Pack()
		}},
		{name: "malformed zone", mutate: func(value *dnstappb.Dnstap) { value.Message.QueryZone = []byte{3, 'c'} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := proto.Clone(valid).(*dnstappb.Dnstap)
			test.mutate(copy)
			frame, err := (proto.MarshalOptions{AllowPartial: true}).Marshal(copy)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := decodeFrame(frame, 1); err == nil {
				t.Fatal("invalid dnstap evidence was accepted")
			}
		})
	}
}

func TestDecodeRejectsUnknownProtobufFields(t *testing.T) {
	frame, _ := resolverFramePair(t, time.Now().UTC())
	frame = append(frame, 0xa0, 0x06, 0x01) // unknown field 100, varint 1
	if _, err := decodeFrame(frame, 1); err == nil {
		t.Fatal("unknown protobuf field was accepted")
	}
}

func resolverFramePair(t *testing.T, queryTime time.Time) ([]byte, []byte) {
	t.Helper()
	query := resolverTap(t, dnstappb.Message_RESOLVER_QUERY, queryTime)
	response := resolverTap(t, dnstappb.Message_RESOLVER_RESPONSE, queryTime)
	queryFrame, err := proto.Marshal(query)
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	responseFrame, err := proto.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return queryFrame, responseFrame
}

func resolverTap(t *testing.T, messageType dnstappb.Message_Type, queryTime time.Time) *dnstappb.Dnstap {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 0x4242
	query.RecursionDesired = false
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	responseWire, err := response.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	zone := make([]byte, 255)
	zoneLength, err := dns.PackDomainName("com.", zone, 0, nil, false)
	if err != nil {
		t.Fatalf("pack query zone: %v", err)
	}
	querySeconds := uint64(queryTime.Unix())
	queryNanoseconds := uint32(queryTime.Nanosecond())
	message := &dnstappb.Message{
		Type:            messageType.Enum(),
		SocketFamily:    dnstappb.SocketFamily_INET.Enum(),
		SocketProtocol:  dnstappb.SocketProtocol_UDP.Enum(),
		QueryAddress:    netip.MustParseAddr("0.0.0.0").AsSlice(),
		ResponseAddress: netip.MustParseAddr("192.0.2.53").AsSlice(),
		QueryPort:       proto.Uint32(53000),
		ResponsePort:    proto.Uint32(53),
		QueryTimeSec:    &querySeconds,
		QueryTimeNsec:   &queryNanoseconds,
		QueryZone:       zone[:zoneLength],
	}
	if messageType == dnstappb.Message_RESOLVER_QUERY {
		message.QueryMessage = queryWire
	} else {
		responseTime := queryTime.Add(15 * time.Millisecond)
		responseSeconds := uint64(responseTime.Unix())
		responseNanoseconds := uint32(responseTime.Nanosecond())
		message.QueryMessage = queryWire
		message.ResponseTimeSec = &responseSeconds
		message.ResponseTimeNsec = &responseNanoseconds
		message.ResponseMessage = responseWire
	}
	return &dnstappb.Dnstap{Type: dnstappb.Dnstap_MESSAGE.Enum(), Message: message}
}
