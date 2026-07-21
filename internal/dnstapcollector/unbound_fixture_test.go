package dnstapcollector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	dnstappb "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

const unboundFixtureSHA256 = "1d5808f68adac8b66c2c0d51fc2bfbb29b40b62fbd5e47df1afd07db67da9dc2"

type capturedFrame struct {
	raw          []byte
	payload      []byte
	control      bool
	controlType  uint32
	contentTypes [][]byte
}

func TestUnbound1251FixtureReplaysHandshakeEvidenceAndPairing(t *testing.T) {
	capture := loadUnboundFixture(t)
	frames := splitCapturedFrames(t, capture)
	if len(frames) != 5 {
		t.Fatalf("fixture frames = %d, want 5", len(frames))
	}
	wantTypes := []uint32{
		framestream.CONTROL_READY,
		framestream.CONTROL_START,
		0,
		0,
		framestream.CONTROL_STOP,
	}
	for index, want := range wantTypes {
		if frames[index].controlType != want {
			t.Fatalf("frame %d control type = %d, want %d", index, frames[index].controlType, want)
		}
	}
	for _, index := range []int{0, 1} {
		if len(frames[index].contentTypes) != 1 || string(frames[index].contentTypes[0]) != ContentType {
			t.Fatalf("frame %d content types = %q", index, frames[index].contentTypes)
		}
	}
	assertUnboundFixtureEnvelope(t, frames[2].payload, dnstappb.Message_RESOLVER_QUERY)
	assertUnboundFixtureEnvelope(t, frames[3].payload, dnstappb.Message_RESOLVER_RESPONSE)

	result, producerErr := replayProducerCapture(t, capture)
	if producerErr != nil {
		t.Fatalf("replay producer: %v", producerErr)
	}
	if !result.Complete || result.Status != CollectionComplete || result.Error != nil {
		t.Fatalf("result = %+v", result)
	}
	if result.FrameCount != 2 || len(result.Events) != 2 || len(result.Exchanges) != 1 {
		t.Fatalf("evidence = frames %d events %+v exchanges %+v pairing %+v", result.FrameCount, result.Events, result.Exchanges, result.Pairing)
	}
	if result.Pairing != (PairingSummary{Integrity: PairingExact, Matched: 1}) {
		t.Fatalf("pairing = %+v", result.Pairing)
	}
	query, response := result.Events[0], result.Events[1]
	if query.Kind != EventResolverQuery || response.Kind != EventResolverResponse {
		t.Fatalf("event kinds = %s, %s", query.Kind, response.Kind)
	}
	if query.Question != (Question{Name: "fixture.nodeping.test.", Type: dns.TypeA, Class: dns.ClassINET}) {
		t.Fatalf("question = %+v", query.Question)
	}
	if query.QueryZone != "nodeping.test." || query.Protocol != ProtocolUDP || query.Family != FamilyIPv4 {
		t.Fatalf("query provenance = %+v", query)
	}
	if query.LocalIP != "0.0.0.0" || query.UpstreamIP != "127.0.0.1" || query.LocalPort == 0 || query.UpstreamPort == 0 {
		t.Fatalf("query endpoints = %+v", query)
	}
	if response.DNSID != query.DNSID || response.Question != query.Question ||
		response.LocalPort != query.LocalPort || response.UpstreamPort != query.UpstreamPort ||
		!response.QueryTime.Equal(query.QueryTime) || !response.ResponseTime.After(query.QueryTime) {
		t.Fatalf("response does not echo query identity: query=%+v response=%+v", query, response)
	}
	var dnsResponse dns.Msg
	if err := dnsResponse.Unpack(response.ResponseWire); err != nil {
		t.Fatalf("unpack fixture response: %v", err)
	}
	if len(dnsResponse.Answer) != 1 || dnsResponse.Answer[0].String() != "fixture.nodeping.test.\t60\tIN\tA\t192.0.2.123" {
		t.Fatalf("fixture DNS answer = %v", dnsResponse.Answer)
	}
}

func TestUnbound1251QueryFixtureRetainsNoResponseEvidence(t *testing.T) {
	frames := splitCapturedFrames(t, loadUnboundFixture(t))
	queryOnly := make([]byte, 0, len(frames[0].raw)+len(frames[1].raw)+len(frames[2].raw)+len(frames[4].raw))
	for _, index := range []int{0, 1, 2, 4} {
		queryOnly = append(queryOnly, frames[index].raw...)
	}
	result, producerErr := replayProducerCapture(t, queryOnly)
	if producerErr != nil {
		t.Fatalf("replay producer: %v", producerErr)
	}
	if !result.Complete || result.Status != CollectionComplete || result.Error != nil {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Events) != 1 || len(result.Exchanges) != 1 || result.Exchanges[0].Status != PairNoResponse {
		t.Fatalf("partial evidence = events %d exchanges %+v", len(result.Events), result.Exchanges)
	}
	if result.Pairing.NoResponse != 1 || result.Pairing.Matched != 0 {
		t.Fatalf("pairing = %+v", result.Pairing)
	}
}

func loadUnboundFixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile("testdata/unbound-1.25.1-resolver-pair.fstrm.b64")
	if err != nil {
		t.Fatalf("read Unbound fixture: %v", err)
	}
	capture, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode Unbound fixture: %v", err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(capture))
	if hash != unboundFixtureSHA256 {
		t.Fatalf("fixture SHA-256 = %s, want %s", hash, unboundFixtureSHA256)
	}
	return capture
}

func splitCapturedFrames(t *testing.T, capture []byte) []capturedFrame {
	t.Helper()
	var frames []capturedFrame
	for offset := 0; offset < len(capture); {
		if len(capture)-offset < 4 {
			t.Fatalf("short frame length at offset %d", offset)
		}
		start := offset
		length := int(binary.BigEndian.Uint32(capture[offset : offset+4]))
		offset += 4
		if length > 0 {
			if length > len(capture)-offset {
				t.Fatalf("short data frame at offset %d", start)
			}
			frames = append(frames, capturedFrame{
				raw: bytes.Clone(capture[start : offset+length]), payload: bytes.Clone(capture[offset : offset+length]),
			})
			offset += length
			continue
		}
		if len(capture)-offset < 4 {
			t.Fatalf("short control frame length at offset %d", start)
		}
		controlLength := int(binary.BigEndian.Uint32(capture[offset : offset+4]))
		if controlLength < 4 || controlLength > framestream.CONTROL_FRAME_LENGTH_MAX || 4+controlLength > len(capture)-offset {
			t.Fatalf("invalid control frame length %d at offset %d", controlLength, start)
		}
		offset += 4 + controlLength
		raw := bytes.Clone(capture[start:offset])
		var control framestream.ControlFrame
		reader := bytes.NewReader(raw)
		if err := control.DecodeEscape(reader); err != nil || reader.Len() != 0 {
			t.Fatalf("decode control frame at offset %d: err=%v trailing=%d", start, err, reader.Len())
		}
		frames = append(frames, capturedFrame{
			raw: raw, control: true, controlType: control.ControlType, contentTypes: control.ContentTypes,
		})
	}
	return frames
}

func assertUnboundFixtureEnvelope(t *testing.T, payload []byte, messageType dnstappb.Message_Type) {
	t.Helper()
	var envelope dnstappb.Dnstap
	if err := proto.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode fixture envelope: %v", err)
	}
	if string(envelope.Identity) != "nodeping-unbound-fixture" || string(envelope.Version) != "unbound-1.25.1" {
		t.Fatalf("fixture producer = identity %q version %q", envelope.Identity, envelope.Version)
	}
	if envelope.Message == nil || envelope.Message.GetType() != messageType {
		t.Fatalf("fixture message type = %v, want %v", envelope.Message.GetType(), messageType)
	}
}

func replayProducerCapture(t *testing.T, capture []byte) (Result, error) {
	t.Helper()
	frames := splitCapturedFrames(t, capture)
	if len(frames) < 3 || frames[0].controlType != framestream.CONTROL_READY || frames[len(frames)-1].controlType != framestream.CONTROL_STOP {
		t.Fatal("capture does not contain a READY ... STOP producer flow")
	}
	collectorConnection, producerConnection := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	producerDone := make(chan error, 1)
	go func() {
		defer producerConnection.Close()
		if _, err := io.Copy(producerConnection, bytes.NewReader(frames[0].raw)); err != nil {
			producerDone <- err
			return
		}
		var accept framestream.ControlFrame
		if err := accept.DecodeTypeEscape(producerConnection, framestream.CONTROL_ACCEPT); err != nil {
			producerDone <- fmt.Errorf("decode ACCEPT: %w", err)
			return
		}
		if len(accept.ContentTypes) != 1 || string(accept.ContentTypes[0]) != ContentType {
			producerDone <- fmt.Errorf("ACCEPT content types = %q", accept.ContentTypes)
			return
		}
		if _, err := io.Copy(producerConnection, bytes.NewReader(capture[len(frames[0].raw):])); err != nil {
			producerDone <- err
			return
		}
		var finish framestream.ControlFrame
		if err := finish.DecodeTypeEscape(producerConnection, framestream.CONTROL_FINISH); err != nil {
			producerDone <- fmt.Errorf("decode FINISH: %w", err)
			return
		}
		producerDone <- nil
	}()
	result := NewDefault().Collect(ctx, collectorConnection)
	return result, <-producerDone
}
