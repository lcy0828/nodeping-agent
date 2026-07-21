package dnstapcollector

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"time"

	dnstappb "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	"nodeping/internal/dnsobs"
)

func decodeFrame(frame []byte, sequence uint64) (Event, error) {
	if len(frame) == 0 {
		return Event{}, fmt.Errorf("dnstap frame is empty")
	}
	var envelope dnstappb.Dnstap
	if err := (proto.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: 16}).Unmarshal(frame, &envelope); err != nil {
		return Event{}, fmt.Errorf("decode dnstap protobuf: %w", err)
	}
	if len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return Event{}, fmt.Errorf("dnstap envelope contains unknown fields")
	}
	if len(envelope.Identity) > maxIdentityBytes || len(envelope.Version) > maxVersionBytes || len(envelope.Extra) > maxExtraBytes {
		return Event{}, fmt.Errorf("dnstap metadata exceeds its limit")
	}
	if envelope.Type == nil || envelope.GetType() != dnstappb.Dnstap_MESSAGE || envelope.Message == nil {
		return Event{}, fmt.Errorf("dnstap envelope is not a MESSAGE")
	}
	message := envelope.Message
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return Event{}, fmt.Errorf("dnstap message contains unknown fields")
	}

	event := Event{Sequence: sequence, FrameBytes: len(frame)}
	if err := decodeMessageMetadata(message, &event); err != nil {
		return Event{}, err
	}
	if err := decodeMessageEvidence(message, &event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func decodeMessageMetadata(message *dnstappb.Message, event *Event) error {
	if message.Type == nil {
		return fmt.Errorf("dnstap message type is required")
	}
	switch message.GetType() {
	case dnstappb.Message_RESOLVER_QUERY:
		event.Kind = EventResolverQuery
	case dnstappb.Message_RESOLVER_RESPONSE:
		event.Kind = EventResolverResponse
	default:
		return fmt.Errorf("dnstap message type %s is not allowed", message.GetType())
	}

	if message.SocketFamily == nil {
		return fmt.Errorf("dnstap socket family is required")
	}
	var addressBytes int
	switch message.GetSocketFamily() {
	case dnstappb.SocketFamily_INET:
		event.Family = FamilyIPv4
		addressBytes = 4
	case dnstappb.SocketFamily_INET6:
		event.Family = FamilyIPv6
		addressBytes = 16
	default:
		return fmt.Errorf("dnstap socket family %s is not allowed", message.GetSocketFamily())
	}

	if message.SocketProtocol == nil {
		return fmt.Errorf("dnstap socket protocol is required")
	}
	switch message.GetSocketProtocol() {
	case dnstappb.SocketProtocol_UDP:
		event.Protocol = ProtocolUDP
	case dnstappb.SocketProtocol_TCP:
		event.Protocol = ProtocolTCP
	default:
		return fmt.Errorf("dnstap socket protocol %s is not allowed", message.GetSocketProtocol())
	}

	localIP, err := decodeAddress(message.QueryAddress, addressBytes, false)
	if err != nil {
		return fmt.Errorf("invalid dnstap query address: %w", err)
	}
	upstreamIP, err := decodeAddress(message.ResponseAddress, addressBytes, true)
	if err != nil {
		return fmt.Errorf("invalid dnstap response address: %w", err)
	}
	event.LocalIP = localIP
	event.UpstreamIP = upstreamIP

	if message.QueryPort == nil || message.GetQueryPort() == 0 || message.GetQueryPort() > math.MaxUint16 {
		return fmt.Errorf("dnstap query port must be from 1 to 65535")
	}
	if message.ResponsePort == nil || message.GetResponsePort() == 0 || message.GetResponsePort() > math.MaxUint16 {
		return fmt.Errorf("dnstap response port must be from 1 to 65535")
	}
	event.LocalPort = uint16(message.GetQueryPort())
	event.UpstreamPort = uint16(message.GetResponsePort())

	queryTime, err := decodeTimestamp(message.QueryTimeSec, message.QueryTimeNsec, "query")
	if err != nil {
		return err
	}
	event.QueryTime = queryTime
	if event.Kind == EventResolverResponse {
		responseTime, err := decodeTimestamp(message.ResponseTimeSec, message.ResponseTimeNsec, "response")
		if err != nil {
			return err
		}
		if responseTime.Before(queryTime) {
			return fmt.Errorf("dnstap response time precedes query time")
		}
		event.ResponseTime = responseTime
	}

	zone, err := decodeWireName(message.QueryZone)
	if err != nil {
		return fmt.Errorf("invalid dnstap query zone: %w", err)
	}
	event.QueryZone = zone
	return nil
}

func decodeMessageEvidence(message *dnstappb.Message, event *Event) error {
	var evidence []byte
	expectResponse := event.Kind == EventResolverResponse
	if expectResponse {
		evidence = message.ResponseMessage
	} else {
		evidence = message.QueryMessage
	}
	question, id, err := decodeDNSMessage(evidence, expectResponse)
	if err != nil {
		return err
	}
	event.Question = question
	event.DNSID = id
	if expectResponse {
		event.ResponseWire = bytes.Clone(evidence)
		if len(message.QueryMessage) != 0 {
			queryQuestion, queryID, err := decodeDNSMessage(message.QueryMessage, false)
			if err != nil {
				return fmt.Errorf("invalid echoed dnstap query message: %w", err)
			}
			if queryID != id || queryQuestion != question {
				return fmt.Errorf("echoed dnstap query does not match its response")
			}
			event.QueryWire = bytes.Clone(message.QueryMessage)
		}
	} else {
		event.QueryWire = bytes.Clone(evidence)
	}
	return nil
}

func decodeAddress(value []byte, wantBytes int, required bool) (string, error) {
	if len(value) == 0 && !required {
		return "", nil
	}
	if len(value) != wantBytes {
		return "", fmt.Errorf("address must contain %d bytes", wantBytes)
	}
	address, ok := netip.AddrFromSlice(value)
	if !ok || !address.IsValid() || address.Is4In6() {
		return "", fmt.Errorf("address is not valid for its socket family")
	}
	if required && (address.IsUnspecified() || address.IsMulticast()) {
		return "", fmt.Errorf("upstream address must be unicast and specified")
	}
	return address.String(), nil
}

func decodeTimestamp(seconds *uint64, nanoseconds *uint32, field string) (time.Time, error) {
	if seconds == nil || nanoseconds == nil {
		return time.Time{}, fmt.Errorf("dnstap %s timestamp is required", field)
	}
	if *seconds > math.MaxInt64 || *nanoseconds >= 1_000_000_000 {
		return time.Time{}, fmt.Errorf("dnstap %s timestamp is invalid", field)
	}
	return time.Unix(int64(*seconds), int64(*nanoseconds)).UTC(), nil
}

func decodeWireName(wire []byte) (string, error) {
	if len(wire) == 0 || len(wire) > 255 {
		return "", fmt.Errorf("wire name length must be from 1 to 255")
	}
	name, next, err := dns.UnpackDomainName(wire, 0)
	if err != nil || next != len(wire) {
		return "", fmt.Errorf("wire name is malformed")
	}
	return dnsobs.NormalizeWireName(name)
}

func decodeDNSMessage(wire []byte, expectResponse bool) (Question, uint16, error) {
	if len(wire) == 0 || len(wire) > maxDNSWireBytes {
		return Question{}, 0, fmt.Errorf("DNS wire length must be from 1 to 65535")
	}
	var message dns.Msg
	if err := message.Unpack(wire); err != nil {
		return Question{}, 0, fmt.Errorf("unpack DNS wire: %w", err)
	}
	if message.Response != expectResponse {
		return Question{}, 0, fmt.Errorf("DNS QR bit does not match dnstap event type")
	}
	if len(message.Question) != 1 {
		return Question{}, 0, fmt.Errorf("DNS message must contain exactly one question")
	}
	name, err := dnsobs.NormalizeWireName(message.Question[0].Name)
	if err != nil {
		return Question{}, 0, fmt.Errorf("normalize DNS question name: %w", err)
	}
	return Question{Name: name, Type: message.Question[0].Qtype, Class: message.Question[0].Qclass}, message.Id, nil
}
