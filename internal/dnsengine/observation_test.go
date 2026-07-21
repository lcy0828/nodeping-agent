package dnsengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

func TestToObservationConvertsSuccessfulResult(t *testing.T) {
	started := time.Date(2026, 7, 19, 9, 30, 0, 0, time.UTC)
	result := &Result{
		Question:       dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol:       ProtocolUDP,
		PeerIP:         "8.8.8.8",
		StartedAt:      started,
		Duration:       25 * time.Millisecond,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 25 * time.Millisecond, ResponseSize: 45}},
		RCode:          0,
		Flags:          Flags{Response: true, RecursionAvailable: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   45,
		Sections: Sections{Answer: []ResourceRecord{{
			Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
			DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
		}}},
	}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation: %v", err)
	}
	if observation.TransportStatus != dnsobs.TransportSuccess || observation.Protocol != dnsobs.ProtocolUDP || observation.AttemptCount != 1 || observation.Outcome != dnsobs.DNSOutcomeAnswer {
		t.Fatalf("observation status = %+v", observation)
	}
	if observation.ResponseAttempt != 1 || len(observation.Attempts) != 1 || observation.Attempts[0].TransportStatus != dnsobs.TransportSuccess || observation.Attempts[0].ResponseSizeBytes != 45 {
		t.Fatalf("observation attempt transcript = %+v", observation)
	}
	if observation.RCode == nil || *observation.RCode != 0 || len(observation.Sections.Answer) != 1 || observation.Sections.Answer[0].RRSetFingerprint == "" {
		t.Fatalf("observation evidence = %+v", observation)
	}
	if observation.ExtendedRCode != nil {
		t.Fatalf("response without EDNS has extended rcode %d", *observation.ExtendedRCode)
	}
	if observation.ResponseTruncated || observation.ResultTruncated || observation.Comparison != dnsobs.ComparisonMatchExpected || observation.Error != nil {
		t.Fatalf("observation comparability = %+v", observation)
	}
	if !observation.StartedAt.Equal(started) || !observation.ObservedAt.Equal(started.Add(25*time.Millisecond)) || !observation.FinishedAt.Equal(started.Add(25*time.Millisecond)) {
		t.Fatalf("observation timeline = %s/%s/%s", observation.StartedAt, observation.ObservedAt, observation.FinishedAt)
	}
}

func TestToObservationPublishesMessageFreeAttemptTranscript(t *testing.T) {
	started := time.Date(2026, 7, 19, 9, 45, 0, 0, time.UTC)
	secret := "dial failed with credential=do-not-publish"
	result := &Result{
		Question:  dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol:  ProtocolUDP,
		PeerIP:    "8.8.8.8",
		StartedAt: started,
		Duration:  10 * time.Millisecond,
		Attempts: []Attempt{
			{Protocol: ProtocolUDP, StartedAt: started, Duration: 2 * time.Millisecond, Error: secret},
			{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started.Add(4 * time.Millisecond), Duration: 3 * time.Millisecond, ResponseSize: 45},
		},
		RCode: 0, Flags: Flags{Response: true}, Outcome: OutcomeAnswer, ResponseParsed: true, ResponseSize: 45,
		Sections: Sections{Answer: []ResourceRecord{{
			Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
			DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
		}}},
	}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation: %v", err)
	}
	if observation.AttemptCount != 2 || observation.ResponseAttempt != 2 || observation.Attempts[0].Error == nil || observation.Attempts[0].Error.Code != "NETWORK_ERROR" || !observation.Attempts[0].Error.Retryable || observation.Attempts[1].Error != nil {
		t.Fatalf("public attempt transcript = %+v", observation.Attempts)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("credential")) {
		t.Fatalf("attempt error message leaked: %s", raw)
	}
}

func TestToObservationKeepsWireErrorWhenRetryGapTerminates(t *testing.T) {
	for _, terminal := range []struct {
		err    error
		status dnsobs.TransportStatus
		code   string
	}{
		{err: context.Canceled, status: dnsobs.TransportCancelled, code: "CANCELLED"},
		{err: context.DeadlineExceeded, status: dnsobs.TransportTimeout, code: "TIMEOUT"},
	} {
		started := time.Date(2026, 7, 19, 9, 50, 0, 0, time.UTC)
		wireErr := errors.New("route unavailable")
		result := &Result{
			Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 8 * time.Millisecond,
			Attempts: []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, Error: wireErr.Error()}},
		}
		envelope := testObservationEnvelope()
		envelope.TerminalError = terminal.err
		observation, err := ToObservation(result, wireErr, envelope)
		if err != nil {
			t.Fatalf("terminal %s: %v", terminal.status, err)
		}
		if observation.TransportStatus != terminal.status || observation.Error == nil || observation.Error.Code != terminal.code || observation.Attempts[0].TransportStatus != dnsobs.TransportNetworkError || observation.Attempts[0].Error == nil || observation.Attempts[0].Error.Code != "NETWORK_ERROR" || observation.ResponseAttempt != 0 || !observation.ObservedAt.Equal(observation.FinishedAt) {
			t.Fatalf("gap observation = %+v", observation)
		}
	}
}

func TestToObservationPreservesTruncatedUDPWhenTCPFallbackFails(t *testing.T) {
	udpStarted := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	tcpStarted := udpStarted.Add(12 * time.Millisecond)
	result := &Result{
		Question:          dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET},
		Protocol:          ProtocolUDP,
		PeerIP:            "8.8.8.8",
		StartedAt:         udpStarted,
		Duration:          42 * time.Millisecond,
		Attempts:          []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: udpStarted, Duration: 10 * time.Millisecond, ResponseSize: 70, Truncated: true}, {Protocol: ProtocolTCP, StartedAt: tcpStarted, Duration: 30 * time.Millisecond, Error: context.DeadlineExceeded.Error()}},
		UDPToTCPFallback:  true,
		RCode:             0,
		Flags:             Flags{Response: true, Truncated: true, RecursionAvailable: true},
		Outcome:           OutcomeNoData,
		ResponseParsed:    true,
		ResponseSize:      70,
		ResponseTruncated: true,
	}
	envelope := testObservationEnvelope()
	envelope.Question.Type = dnsobs.RRTypeNS
	observation, err := ToObservation(result, context.DeadlineExceeded, envelope)
	if err != nil {
		t.Fatalf("ToObservation fallback failure: %v", err)
	}
	if observation.TransportStatus != dnsobs.TransportTimeout || observation.Protocol != dnsobs.ProtocolTCP || observation.AttemptCount != 2 || observation.PeerIP != "8.8.8.8" {
		t.Fatalf("final attempt metadata = %+v", observation)
	}
	if !observation.StartedAt.Equal(udpStarted) || !observation.ObservedAt.Equal(udpStarted.Add(10*time.Millisecond)) || !observation.FinishedAt.Equal(udpStarted.Add(42*time.Millisecond)) || observation.DurationMS != 42 {
		t.Fatalf("operation timing = %s/%s/%s/%d", observation.StartedAt, observation.ObservedAt, observation.FinishedAt, observation.DurationMS)
	}
	if observation.Outcome != dnsobs.DNSOutcomeNoData || observation.RCode == nil || !observation.Flags.Truncated || !observation.ResponseTruncated || observation.ResultTruncated {
		t.Fatalf("retained UDP evidence = %+v", observation)
	}
	if observation.Comparison != dnsobs.ComparisonUnknown || observation.Error == nil || observation.Error.Code != "TIMEOUT" {
		t.Fatalf("fallback error = %+v", observation)
	}

	if malformedFallback, err := ToObservation(result, ErrMalformedResponse, envelope); err == nil {
		t.Fatalf("mixed UDP evidence and malformed TCP response was accepted: %+v", malformedFallback)
	}

	if completedTC, err := ToObservation(result, nil, envelope); err == nil {
		t.Fatalf("failed final TCP attempt was accepted as a successful response: %+v", completedTC)
	}
}

func TestToObservationBindsThreeAttemptFallbackSuccessToFinalTCP(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 5, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		attempts []Attempt
	}{
		{
			name: "UDP retry before TC",
			attempts: []Attempt{
				{Protocol: ProtocolUDP, PeerIP: "1.1.1.1", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 45, Error: "temporary UDP failure"},
				{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started.Add(3 * time.Millisecond), Duration: 2 * time.Millisecond, ResponseSize: 70, Truncated: true},
				{Protocol: ProtocolTCP, PeerIP: "1.1.1.1", StartedAt: started.Add(7 * time.Millisecond), Duration: 3 * time.Millisecond, ResponseSize: 45},
			},
		},
		{
			name: "TCP retry after TC",
			attempts: []Attempt{
				{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 70, Truncated: true},
				{Protocol: ProtocolTCP, StartedAt: started.Add(3 * time.Millisecond), Duration: 2 * time.Millisecond, Error: "temporary TCP failure"},
				{Protocol: ProtocolTCP, PeerIP: "1.1.1.1", StartedAt: started.Add(7 * time.Millisecond), Duration: 3 * time.Millisecond, ResponseSize: 45},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := &Result{
				Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				Protocol: ProtocolUDP, PeerIP: "1.1.1.1", StartedAt: started, Duration: 12 * time.Millisecond,
				Attempts: test.attempts, UDPToTCPFallback: true,
				RCode: 0, Flags: Flags{Response: true}, Outcome: OutcomeAnswer, ResponseParsed: true, ResponseSize: 45,
				Sections: Sections{Answer: []ResourceRecord{{
					Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
					DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
				}}},
			}
			observation, err := ToObservation(result, nil, testObservationEnvelope())
			if err != nil {
				t.Fatalf("ToObservation: %v", err)
			}
			final := test.attempts[len(test.attempts)-1]
			if observation.Protocol != dnsobs.ProtocolTCP || observation.PeerIP != final.PeerIP || observation.ResponseSizeBytes != final.ResponseSize || !observation.ObservedAt.Equal(final.StartedAt.Add(final.Duration)) {
				t.Fatalf("final TCP provenance = %+v", observation)
			}
		})
	}
}

func TestToObservationRetainsExactUDPAcrossThreeAttemptFallbackFailure(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 10, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		attempts   []Attempt
		ownerIndex int
	}{
		{
			name: "UDP retry before TC",
			attempts: []Attempt{
				{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 70, Error: context.DeadlineExceeded.Error()},
				{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started.Add(3 * time.Millisecond), Duration: 2 * time.Millisecond, ResponseSize: 70, Truncated: true},
				{Protocol: ProtocolTCP, StartedAt: started.Add(7 * time.Millisecond), Duration: 3 * time.Millisecond, Error: context.DeadlineExceeded.Error()},
			},
			ownerIndex: 1,
		},
		{
			name: "TCP retry after TC",
			attempts: []Attempt{
				{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 70, Truncated: true},
				{Protocol: ProtocolTCP, StartedAt: started.Add(3 * time.Millisecond), Duration: 2 * time.Millisecond, Error: context.DeadlineExceeded.Error()},
				{Protocol: ProtocolTCP, StartedAt: started.Add(7 * time.Millisecond), Duration: 3 * time.Millisecond, Error: context.DeadlineExceeded.Error()},
			},
			ownerIndex: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := &Result{
				Question: dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET},
				Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 12 * time.Millisecond,
				Attempts: test.attempts, UDPToTCPFallback: true,
				RCode: 0, Flags: Flags{Response: true, Truncated: true}, Outcome: OutcomeNoData,
				ResponseParsed: true, ResponseSize: 70, ResponseTruncated: true,
			}
			envelope := testObservationEnvelope()
			envelope.Question.Type = dnsobs.RRTypeNS
			observation, err := ToObservation(result, context.DeadlineExceeded, envelope)
			if err != nil {
				t.Fatalf("ToObservation: %v", err)
			}
			owner := test.attempts[test.ownerIndex]
			if observation.PeerIP != owner.PeerIP || observation.ResponseSizeBytes != owner.ResponseSize || !observation.ObservedAt.Equal(owner.StartedAt.Add(owner.Duration)) || !observation.ResponseTruncated {
				t.Fatalf("retained UDP provenance = %+v", observation)
			}
		})
	}
}

func TestToObservationUsesResponseDecisionTimeForSlowQuery(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 20, 0, 0, time.UTC)
	duration := 4*time.Second + 250*time.Millisecond
	result := &Result{
		Question:       dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol:       ProtocolUDP,
		PeerIP:         "8.8.8.8",
		StartedAt:      started,
		Duration:       duration,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: duration, ResponseSize: 45}},
		RCode:          0,
		Flags:          Flags{Response: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   45,
		Sections: Sections{Answer: []ResourceRecord{{
			Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
			DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
		}}},
	}
	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation: %v", err)
	}
	if want := started.Add(duration); !observation.ObservedAt.Equal(want) || !observation.FinishedAt.Equal(want) || observation.DurationMS != duration.Milliseconds() {
		t.Fatalf("observation timing = %s/%s/%d, want %s/%d", observation.ObservedAt, observation.FinishedAt, observation.DurationMS, want, duration.Milliseconds())
	}
}

func TestToObservationPreservesHeaderOnlyTCWhenMalformedTCPFallbackArrives(t *testing.T) {
	udpStarted := time.Date(2026, 7, 19, 10, 15, 0, 0, time.UTC)
	tcpStarted := udpStarted.Add(10 * time.Millisecond)
	result := &Result{
		Question:                dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol:                ProtocolUDP,
		PeerIP:                  "8.8.8.8",
		StartedAt:               udpStarted,
		Duration:                15 * time.Millisecond,
		Attempts:                []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: udpStarted, Duration: 8 * time.Millisecond, ResponseSize: 28, Truncated: true}, {Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: tcpStarted, Duration: 5 * time.Millisecond, ResponseSize: 40, Truncated: true}},
		UDPToTCPFallback:        true,
		RCode:                   3,
		Flags:                   Flags{Response: true, Truncated: true, RecursionAvailable: true},
		Outcome:                 OutcomeTruncatedResponse,
		ResponseSize:            40,
		ResponseHeaderValidated: true,
		ResponseTruncated:       true,
	}
	observation, err := ToObservation(result, ErrMalformedResponse, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation header-only fallback: %v", err)
	}
	if observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeTruncatedResponse || observation.RCode == nil || *observation.RCode != 3 || observation.ExtendedRCode != nil {
		t.Fatalf("header-only observation = %+v", observation)
	}
	if observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" || observation.Comparison != dnsobs.ComparisonUnknown || observation.DNSSEC.Status != dnsobs.DNSSECIndeterminate {
		t.Fatalf("header-only fallback status = %+v", observation)
	}
	if !observation.ObservedAt.Equal(tcpStarted.Add(5 * time.Millisecond)) {
		t.Fatalf("final TCP evidence time = %s", observation.ObservedAt)
	}

	oldUDPHeader := *result
	oldUDPHeader.ResponseSize = 28
	oldUDPHeader.Attempts[1].ResponseSize = 7
	oldUDPHeader.Attempts[1].Truncated = false
	if mixed, err := ToObservation(&oldUDPHeader, ErrMalformedResponse, testObservationEnvelope()); err == nil {
		t.Fatalf("old UDP header mixed with malformed TCP was accepted: %+v", mixed)
	}
}

func TestToObservationDoesNotTrustRawMalformedTCBit(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 18, 0, 0, time.UTC)
	tcpStarted := started.Add(4 * time.Millisecond)
	result := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol: ProtocolUDP, PeerIP: "1.1.1.1", StartedAt: started, Duration: 10 * time.Millisecond,
		Attempts: []Attempt{
			{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 28, Truncated: true},
			{Protocol: ProtocolTCP, PeerIP: "1.1.1.1", StartedAt: tcpStarted, Duration: 3 * time.Millisecond, ResponseSize: 40, Truncated: true},
		},
		UDPToTCPFallback: true,
		Outcome:          OutcomeMalformed,
		ResponseSize:     40,
	}
	observation, err := ToObservation(result, ErrResponseMismatch, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation raw malformed TCP: %v", err)
	}
	if observation.Outcome != dnsobs.DNSOutcomeMalformed || observation.PeerIP != "1.1.1.1" || observation.ResponseSizeBytes != 40 || observation.ResponseTruncated || observation.Flags.Truncated {
		t.Fatalf("raw malformed response = %+v", observation)
	}
	if !observation.ObservedAt.Equal(tcpStarted.Add(3 * time.Millisecond)) {
		t.Fatalf("raw malformed evidence time = %s", observation.ObservedAt)
	}
}

func TestToObservationClassifiesTransportAndMalformedErrors(t *testing.T) {
	for _, test := range []struct {
		name        string
		err         error
		wantStatus  dnsobs.TransportStatus
		wantOutcome dnsobs.DNSOutcome
		wantCode    string
	}{
		{name: "timeout", err: context.DeadlineExceeded, wantStatus: dnsobs.TransportTimeout, wantOutcome: dnsobs.DNSOutcomeNotObserved, wantCode: "TIMEOUT"},
		{name: "refused", err: syscall.ECONNREFUSED, wantStatus: dnsobs.TransportRefused, wantOutcome: dnsobs.DNSOutcomeNotObserved, wantCode: "CONNECTION_REFUSED"},
		{name: "network", err: errors.New("route unavailable"), wantStatus: dnsobs.TransportNetworkError, wantOutcome: dnsobs.DNSOutcomeNotObserved, wantCode: "NETWORK_ERROR"},
		{name: "cancelled", err: context.Canceled, wantStatus: dnsobs.TransportCancelled, wantOutcome: dnsobs.DNSOutcomeNotObserved, wantCode: "CANCELLED"},
		{name: "malformed", err: ErrMalformedResponse, wantStatus: dnsobs.TransportSuccess, wantOutcome: dnsobs.DNSOutcomeMalformed, wantCode: "MALFORMED_DNS"},
		{name: "mismatch", err: ErrResponseMismatch, wantStatus: dnsobs.TransportSuccess, wantOutcome: dnsobs.DNSOutcomeMalformed, wantCode: "MALFORMED_DNS"},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)
			result := &Result{
				Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 5 * time.Millisecond,
				Attempts:     []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 5 * time.Millisecond, ResponseSize: 20, Error: test.err.Error()}},
				ResponseSize: 20,
			}
			observation, err := ToObservation(result, test.err, testObservationEnvelope())
			if err != nil {
				t.Fatalf("ToObservation: %v", err)
			}
			if observation.TransportStatus != test.wantStatus || observation.Outcome != test.wantOutcome || observation.Error == nil || observation.Error.Code != test.wantCode {
				t.Fatalf("classified observation = %+v", observation)
			}
		})
	}
}

func TestToObservationRejectsImpossibleAttemptSequences(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 40, 0, 0, time.UTC)
	base := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 3 * time.Millisecond,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45}},
		RCode:          0,
		Flags:          Flags{Response: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   45,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "three UDP attempts without fallback", mutate: func(result *Result) {
			result.Attempts = append(result.Attempts, result.Attempts[0], result.Attempts[0])
		}},
		{name: "two clean attempts without fallback", mutate: func(result *Result) {
			result.Attempts = append(result.Attempts, result.Attempts[0])
		}},
		{name: "fallback trigger has an error", mutate: func(result *Result) {
			result.UDPToTCPFallback = true
			result.Attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started, Truncated: true, Error: "UDP failed"},
				{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45},
			}
		}},
		{name: "UDP retry has no preceding error", mutate: func(result *Result) {
			result.UDPToTCPFallback = true
			result.Attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started},
				{Protocol: ProtocolUDP, StartedAt: started, Truncated: true},
				{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45},
			}
		}},
		{name: "TCP retry has no preceding error", mutate: func(result *Result) {
			result.UDPToTCPFallback = true
			result.Attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started, Truncated: true},
				{Protocol: ProtocolTCP, StartedAt: started},
				{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45},
			}
		}},
		{name: "foreign middle protocol in fallback", mutate: func(result *Result) {
			result.UDPToTCPFallback = true
			result.Attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started},
				{Protocol: ProtocolDoH, StartedAt: started},
				{Protocol: ProtocolTCP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45},
			}
		}},
		{name: "TCP before UDP", mutate: func(result *Result) {
			result.UDPToTCPFallback = true
			result.Attempts = []Attempt{{Protocol: ProtocolTCP, StartedAt: started}, {Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: time.Millisecond, ResponseSize: 45}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := *base
			result.Attempts = append([]Attempt(nil), base.Attempts...)
			test.mutate(&result)
			if observation, err := ToObservation(&result, nil, testObservationEnvelope()); err == nil {
				t.Fatalf("impossible sequence was accepted: %+v", observation)
			}
		})
	}
}

func TestToObservationRejectsInvalidResponseAttemptProvenance(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 45, 0, 0, time.UTC)
	base := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 5 * time.Millisecond,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 4 * time.Millisecond, ResponseSize: 45}},
		RCode:          0,
		Flags:          Flags{Response: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   45,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "zero attempt start", mutate: func(result *Result) { result.Attempts[0].StartedAt = time.Time{} }},
		{name: "negative attempt duration", mutate: func(result *Result) { result.Attempts[0].Duration = -time.Millisecond }},
		{name: "attempt before operation", mutate: func(result *Result) { result.Attempts[0].StartedAt = started.Add(-time.Millisecond) }},
		{name: "attempt ends after decision", mutate: func(result *Result) { result.Attempts[0].Duration = 6 * time.Millisecond }},
		{name: "response size mismatch", mutate: func(result *Result) { result.Attempts[0].ResponseSize = 44 }},
		{name: "response peer mismatch", mutate: func(result *Result) { result.Attempts[0].PeerIP = "1.1.1.1" }},
		{name: "response TC mismatch", mutate: func(result *Result) { result.Attempts[0].Truncated = true }},
		{name: "successful final attempt has error", mutate: func(result *Result) { result.Attempts[0].Error = "late transport error" }},
		{name: "older attempt happens to match", mutate: func(result *Result) {
			result.Attempts = []Attempt{
				{Protocol: ProtocolUDP, PeerIP: result.PeerIP, StartedAt: started, Duration: time.Millisecond, ResponseSize: result.ResponseSize, Error: "temporary failure"},
				{Protocol: ProtocolUDP, PeerIP: "1.1.1.1", StartedAt: started.Add(2 * time.Millisecond), Duration: 2 * time.Millisecond, ResponseSize: result.ResponseSize},
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := *base
			result.Attempts = append([]Attempt(nil), base.Attempts...)
			test.mutate(&result)
			if observation, err := ToObservation(&result, nil, testObservationEnvelope()); err == nil {
				t.Fatalf("invalid provenance was accepted: %+v", observation)
			}
		})
	}
}

func TestToObservationRejectsInvalidFailedFallbackProvenance(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 50, 0, 0, time.UTC)
	base := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET},
		Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 8 * time.Millisecond,
		Attempts: []Attempt{
			{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 70, Truncated: true},
			{Protocol: ProtocolTCP, StartedAt: started.Add(3 * time.Millisecond), Duration: 3 * time.Millisecond, Error: context.DeadlineExceeded.Error()},
		},
		UDPToTCPFallback: true,
		RCode:            0, Flags: Flags{Response: true, Truncated: true}, Outcome: OutcomeNoData,
		ResponseParsed: true, ResponseSize: 70, ResponseTruncated: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "UDP peer mismatch", mutate: func(result *Result) { result.Attempts[0].PeerIP = "1.1.1.1" }},
		{name: "UDP size mismatch", mutate: func(result *Result) { result.Attempts[0].ResponseSize-- }},
		{name: "UDP TC missing", mutate: func(result *Result) { result.Attempts[0].Truncated = false }},
		{name: "UDP attempt has error", mutate: func(result *Result) { result.Attempts[0].Error = "UDP failed" }},
		{name: "UDP starts before operation", mutate: func(result *Result) { result.Attempts[0].StartedAt = started.Add(-time.Millisecond) }},
		{name: "final TCP error missing", mutate: func(result *Result) { result.Attempts[1].Error = "" }},
		{name: "final TCP error mismatch", mutate: func(result *Result) { result.Attempts[1].Error = syscall.ECONNREFUSED.Error() }},
		{name: "final TCP contains TC evidence", mutate: func(result *Result) { result.Attempts[1].Truncated = true }},
		{name: "result TC marker missing", mutate: func(result *Result) { result.ResponseTruncated = false }},
		{name: "flags TC marker missing", mutate: func(result *Result) { result.Flags.Truncated = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := *base
			result.Attempts = append([]Attempt(nil), base.Attempts...)
			test.mutate(&result)
			envelope := testObservationEnvelope()
			envelope.Question.Type = dnsobs.RRTypeNS
			if observation, err := ToObservation(&result, context.DeadlineExceeded, envelope); err == nil {
				t.Fatalf("invalid failed fallback provenance was accepted: %+v", observation)
			}
		})
	}
}

func TestToObservationRejectsInvalidHeaderOnlyTCPProvenance(t *testing.T) {
	started := time.Date(2026, 7, 19, 10, 55, 0, 0, time.UTC)
	base := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol: ProtocolUDP, PeerIP: "1.1.1.1", StartedAt: started, Duration: 8 * time.Millisecond,
		Attempts: []Attempt{
			{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 2 * time.Millisecond, ResponseSize: 28, Truncated: true},
			{Protocol: ProtocolTCP, PeerIP: "1.1.1.1", StartedAt: started.Add(3 * time.Millisecond), Duration: 3 * time.Millisecond, ResponseSize: 40, Truncated: true},
		},
		UDPToTCPFallback: true,
		RCode:            0, Flags: Flags{Response: true, Truncated: true}, Outcome: OutcomeTruncatedResponse,
		ResponseHeaderValidated: true, ResponseSize: 40, ResponseTruncated: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "final peer mismatch", mutate: func(result *Result) { result.Attempts[1].PeerIP = "9.9.9.9" }},
		{name: "final size mismatch", mutate: func(result *Result) { result.Attempts[1].ResponseSize-- }},
		{name: "final TC missing", mutate: func(result *Result) { result.Attempts[1].Truncated = false }},
		{name: "final timing outside operation", mutate: func(result *Result) { result.Attempts[1].Duration = 6 * time.Millisecond }},
		{name: "final transport error", mutate: func(result *Result) { result.Attempts[1].Error = ErrMalformedResponse.Error() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := *base
			result.Attempts = append([]Attempt(nil), base.Attempts...)
			test.mutate(&result)
			if observation, err := ToObservation(&result, ErrMalformedResponse, testObservationEnvelope()); err == nil {
				t.Fatalf("invalid header-only TCP provenance was accepted: %+v", observation)
			}
		})
	}
}

func TestToObservationBoundsLargeTXTAndDNSKEYEvidence(t *testing.T) {
	started := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	records := make([]ResourceRecord, 0, dnsobs.MaxSectionRecordLimit)
	for index := 0; index < dnsobs.MaxSectionRecordLimit; index++ {
		rrType := "TXT"
		payload := strings.Repeat(string(rune('a'+index%26)), 900)
		var record dns.RR = &dns.TXT{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: txtChunksForObservationTest(payload),
		}
		if index%2 != 0 {
			rrType = "DNSKEY"
			record = &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60},
				Flags:     257,
				Protocol:  3,
				Algorithm: 13,
				PublicKey: base64.StdEncoding.EncodeToString([]byte(payload)),
			}
		}
		display, canonical := canonicalRecordDataForObservationTest(t, record)
		records = append(records, ResourceRecord{
			Owner: "example.com.", Type: rrType, Class: "IN", TTL: 60,
			DisplayRData: display, CanonicalRData: canonical,
			RRSetRecordCount: dnsobs.MaxSectionRecordLimit / 2,
		})
	}
	for index := range records {
		if records[index].Type == "TXT" {
			records[index].RRSetRecordCount++
		}
	}
	records = append(records, ResourceRecord{
		Owner: "example.com.", Type: "TXT", Class: "IN", TTL: 60,
		DisplayRData: strings.Repeat("x", dnsobs.MaxRDataBytes+1), CanonicalRData: strings.Repeat("x", dnsobs.MaxRDataBytes+1),
		RRSetRecordCount: dnsobs.MaxSectionRecordLimit/2 + 1,
	})
	rawOption := make([]byte, dnsobs.MaxRDataBytes)
	oversizedOption := make([]byte, dnsobs.MaxRDataBytes+1)
	result := &Result{
		Question:       dns.Question{Name: "example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		Protocol:       ProtocolUDP,
		PeerIP:         "8.8.8.8",
		StartedAt:      started,
		Duration:       20 * time.Millisecond,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 20 * time.Millisecond, ResponseSize: 65535}},
		RCode:          0,
		Flags:          Flags{Response: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   65535,
		EDNS: EDNS{Present: true, UDPSize: 1232, Options: []EDNSOption{
			{Code: 65001, DataBase64: base64.StdEncoding.EncodeToString(rawOption)},
			{Code: 65002, DataBase64: base64.StdEncoding.EncodeToString(oversizedOption)},
		}},
		Sections: Sections{Answer: records},
	}
	envelope := testObservationEnvelope()
	envelope.Question.Type = dnsobs.RRTypeTXT
	observation, err := ToObservation(result, nil, envelope)
	if err != nil {
		t.Fatalf("ToObservation oversized evidence: %v", err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	if len(raw) > dnsobs.MaxObservationBytes {
		t.Fatalf("encoded observation = %d bytes, limit %d", len(raw), dnsobs.MaxObservationBytes)
	}
	if observation.ResponseTruncated || !observation.ResultTruncated || observation.Comparison != dnsobs.ComparisonUnknown {
		t.Fatalf("oversized evidence was not marked truncated: %+v", observation)
	}
	if len(observation.EDNS.Options) != 0 {
		t.Fatalf("raw EDNS options were not dropped first: %d", len(observation.EDNS.Options))
	}
	retainedByType := map[dnsobs.RRType]int{}
	for _, record := range observation.Sections.Answer {
		retainedByType[record.Type]++
	}
	for _, rrType := range []dnsobs.RRType{dnsobs.RRTypeTXT, dnsobs.RRTypeDNSKEY} {
		if count := retainedByType[rrType]; count != 0 && count != dnsobs.MaxSectionRecordLimit/2 {
			t.Fatalf("RRset %s was partially retained: %d of %d records", rrType, count, dnsobs.MaxSectionRecordLimit/2)
		}
	}
	if len(observation.Sections.Answer) >= dnsobs.MaxSectionRecordLimit {
		t.Fatalf("oversized answer was not cropped: %d records", len(observation.Sections.Answer))
	}
	for _, record := range observation.Sections.Answer {
		if len(record.DisplayRData) > dnsobs.MaxRDataBytes || len(record.CanonicalRData) > dnsobs.MaxRDataBytes || record.RRSetFingerprint == "" {
			t.Fatalf("unbounded converted record = %+v", record)
		}
	}
}

func TestToObservationConvergesWithMaximumOptionalEvidence(t *testing.T) {
	started := time.Date(2026, 7, 19, 11, 30, 0, 0, time.UTC)
	longSuffix := strings.Join([]string{
		strings.Repeat("a", 48), strings.Repeat("b", 48),
		strings.Repeat("c", 48), strings.Repeat("d", 48),
	}, ".") + "."
	names := make([]string, dnsobs.MaxAliasChainDepth+1)
	names[0] = "example.com."
	for index := 1; index < len(names); index++ {
		names[index] = fmt.Sprintf("alias-%02d.%s", index, longSuffix)
	}
	hops := make([]AliasHop, dnsobs.MaxAliasChainDepth)
	answers := make([]ResourceRecord, dnsobs.MaxAliasChainDepth)
	for index := range hops {
		hops[index] = AliasHop{Type: "CNAME", From: names[index], To: names[index+1]}
		answers[index] = cnameRecordForObservationTest(names[index], names[index+1])
	}
	ede := make([]ExtendedDNSError, dnsobs.MaxExtendedDNSErrors)
	for index := range ede {
		ede[index] = ExtendedDNSError{Code: uint16(index), Text: strings.Repeat("e", dnsobs.MaxErrorMessageBytes)}
	}
	result := &Result{
		Question:       dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol:       ProtocolUDP,
		PeerIP:         "8.8.8.8",
		StartedAt:      started,
		Duration:       20 * time.Millisecond,
		Attempts:       []Attempt{{Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 20 * time.Millisecond, ResponseSize: 512}},
		RCode:          0,
		Flags:          Flags{Response: true},
		Outcome:        OutcomeAnswer,
		ResponseParsed: true,
		ResponseSize:   512,
		EDNS: EDNS{
			Present: true, UDPSize: 1232,
			NSIDHex: strings.Repeat("ab", dnsobs.MaxRDataBytes),
			EDE:     ede,
		},
		Sections:   Sections{Answer: answers},
		AliasChain: AliasChain{Hops: hops, TerminalName: names[len(names)-1]},
	}

	observation, err := ToObservation(result, nil, testObservationEnvelope())
	if err != nil {
		t.Fatalf("ToObservation maximum optional evidence: %v", err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	if len(raw) > dnsobs.MaxObservationBytes {
		t.Fatalf("encoded observation = %d bytes, limit %d", len(raw), dnsobs.MaxObservationBytes)
	}
	if observation.ResponseTruncated || !observation.ResultTruncated || observation.Comparison != dnsobs.ComparisonUnknown || observation.DNSSEC.Status != dnsobs.DNSSECIndeterminate || observation.DNSSEC.LocallyValidated {
		t.Fatalf("cropped classification = %+v", observation)
	}
	if observation.EDNS.NSIDHex != "" && len(observation.EDNS.EDE) == dnsobs.MaxExtendedDNSErrors && len(observation.AliasChain.Hops) == dnsobs.MaxAliasChainDepth {
		t.Fatal("oversized optional evidence was not removed")
	}
}

func TestConvertRecordsForObservationTreatsRRSetAsAtomic(t *testing.T) {
	t.Run("invalid member poisons normalized RRset", func(t *testing.T) {
		records := []ResourceRecord{
			{Owner: "SET.Example.com", Type: "TYPE1", Class: " in ", TTL: 60, DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 2},
			{Owner: "set.example.COM.", Type: "A", Class: "IN", TTL: 60, DisplayRData: "", CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 2},
			{Owner: "other.example.com.", Type: "A", Class: "IN", TTL: 60, DisplayRData: "192.0.2.3", CanonicalRData: `\# 4 C0000203`, RRSetRecordCount: 1},
		}
		converted, dropped := convertRecordsForObservation(records, false)
		if !dropped || len(converted) != 1 || converted[0].Owner != "other.example.com." {
			t.Fatalf("converted poisoned RRset = dropped %t, records %+v", dropped, converted)
		}
	})

	t.Run("invalid count evidence drops the whole source RRset", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			records []ResourceRecord
		}{
			{name: "missing", records: []ResourceRecord{{Owner: "set.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`}}},
			{name: "negative", records: []ResourceRecord{{Owner: "set.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: -1}}},
			{name: "over limit", records: []ResourceRecord{{Owner: "set.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: dnsobs.MaxSectionRecordLimit + 1}}},
			{name: "half group", records: []ResourceRecord{{Owner: "set.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 2}}},
			{name: "inconsistent", records: []ResourceRecord{
				{Owner: "set.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 2},
				{Owner: "SET.EXAMPLE.COM", Type: "TYPE1", Class: "in", DisplayRData: "192.0.2.2", CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 1},
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				test.records = append(test.records, ResourceRecord{
					Owner: "survivor.example.com.", Type: "A", Class: "IN", DisplayRData: "192.0.2.9",
					CanonicalRData: `\# 4 C0000209`, RRSetRecordCount: 1,
				})
				converted, dropped := convertRecordsForObservation(test.records, false)
				if !dropped || len(converted) != 1 || converted[0].Owner != "survivor.example.com." || converted[0].RRSetRecordCount != 1 {
					t.Fatalf("converted count attack = dropped %t, records %+v", dropped, converted)
				}
			})
		}
	})

	t.Run("record budget closes at first non-fitting RRset", func(t *testing.T) {
		records := make([]ResourceRecord, 0, dnsobs.MaxSectionRecordLimit+2)
		for index := 0; index < dnsobs.MaxSectionRecordLimit-2; index++ {
			value := fmt.Sprintf("value-%03d", index)
			records = append(records, ResourceRecord{Owner: "prefix.example.com.", Type: "TXT", Class: "IN", TTL: 60, DisplayRData: value, CanonicalRData: value, RRSetRecordCount: dnsobs.MaxSectionRecordLimit - 2})
		}
		for index := 0; index < 3; index++ {
			owner := "OVERFLOW.example.com"
			rrType := "TYPE1"
			if index%2 != 0 {
				owner = "overflow.EXAMPLE.com."
				rrType = "A"
			}
			value := fmt.Sprintf("overflow-%d", index)
			records = append(records, ResourceRecord{Owner: owner, Type: rrType, Class: " in ", TTL: 60, DisplayRData: value, CanonicalRData: value, RRSetRecordCount: 3})
		}
		records = append(records, ResourceRecord{Owner: "later.example.com.", Type: "A", Class: "IN", TTL: 60, DisplayRData: "later", CanonicalRData: "later", RRSetRecordCount: 1})

		converted, dropped := convertRecordsForObservation(records, false)
		if !dropped || len(converted) != dnsobs.MaxSectionRecordLimit-2 {
			t.Fatalf("bounded records = dropped %t, count %d", dropped, len(converted))
		}
		for _, record := range converted {
			if record.Owner == "overflow.example.com." || record.Owner == "later.example.com." {
				t.Fatalf("record after closed RRset prefix was retained: %+v", record)
			}
		}
	})
}

func TestFitObservationTreatsRRSetAsAtomicAboveContractLimit(t *testing.T) {
	started := time.Date(2026, 7, 19, 11, 45, 0, 0, time.UTC)
	largeDNSKEYs := []dnsobs.ResourceRecord{
		dnskeyRecordForObservationTest(t, "ATOMIC.example.com", 0xAA, 8184, 3),
		dnskeyRecordForObservationTest(t, "atomic.EXAMPLE.com.", 0xBB, 8184, 3),
		dnskeyRecordForObservationTest(t, "Atomic.Example.COM", 0xCC, 8184, 3),
	}
	largeDNSKEYs[0].Type = dnsobs.RRType("type48")
	largeDNSKEYs[0].Class = dnsobs.DNSClass(" in ")
	observation := dnsobs.Observation{
		Schema:          dnsobs.SchemaV1,
		RoundID:         "round-fit-over-contract",
		OperationID:     "operation-fit-over-contract",
		Question:        dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:        dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
		TransportStatus: dnsobs.TransportSuccess,
		AttemptCount:    1,
		Attempts: []dnsobs.WireAttempt{{
			Protocol: dnsobs.ProtocolUDP, TransportStatus: dnsobs.TransportSuccess,
			StartedAt: started, FinishedAt: started.Add(time.Millisecond), DurationMS: 1,
			PeerIP: "8.8.8.8", ResponseSizeBytes: 45,
		}},
		ResponseAttempt:   1,
		PeerIP:            "8.8.8.8",
		Protocol:          dnsobs.ProtocolUDP,
		StartedAt:         started,
		ObservedAt:        started.Add(time.Millisecond),
		FinishedAt:        started.Add(time.Millisecond),
		DurationMS:        1,
		ResponseSizeBytes: 45,
		RCode:             bytePointerEngineTest(0),
		Flags:             dnsobs.DNSFlags{Response: true},
		Outcome:           dnsobs.DNSOutcomeAnswer,
		Comparison:        dnsobs.ComparisonUnknown,
		DNSSEC:            dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		Sections: dnsobs.Sections{
			Answer: []dnsobs.ResourceRecord{{
				Owner: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN, TTL: 60,
				DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
			}},
			Additional: largeDNSKEYs,
		},
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal oversized fixture: %v", err)
	}
	if len(raw) <= dnsobs.MaxObservationBytes {
		t.Fatalf("fixture is only %d bytes, want more than %d", len(raw), dnsobs.MaxObservationBytes)
	}
	if _, err := dnsobs.NormalizeObservation(observation); err == nil || !observationTooLarge(err) {
		t.Fatalf("fixture did not reach the contract limit: %v", err)
	}

	fitted, dropped, err := FitObservationToBytes(observation, dnsobs.MaxObservationBytes)
	if err != nil {
		t.Fatalf("FitObservationToBytes: %v", err)
	}
	if !dropped || !fitted.ResultTruncated || len(fitted.Sections.Additional) != 0 {
		t.Fatalf("oversized canonical RRset was partially retained: dropped %t, observation %+v", dropped, fitted)
	}
}

func TestFitObservationTreatsCanonicalRRSetAsAtomic(t *testing.T) {
	dnskeyRRSet := []dnsobs.ResourceRecord{
		dnskeyRecordForObservationTest(t, "SET.example.com", 0xAA, 446, 2),
		dnskeyRecordForObservationTest(t, "set.EXAMPLE.com.", 0xBB, 446, 2),
	}
	dnskeyRRSet[0].Type = dnsobs.RRType("type48")
	dnskeyRRSet[0].Class = dnsobs.DNSClass(" in ")
	observation := dnsobs.Observation{
		Schema:          dnsobs.SchemaV1,
		RoundID:         "round-fit-atomic",
		OperationID:     "operation-fit-atomic",
		Question:        dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:        dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
		TransportStatus: dnsobs.TransportSuccess,
		AttemptCount:    1,
		Attempts: []dnsobs.WireAttempt{{
			Protocol: dnsobs.ProtocolUDP, TransportStatus: dnsobs.TransportSuccess,
			StartedAt: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 7, 19, 12, 0, 0, int(time.Millisecond), time.UTC), DurationMS: 1,
			PeerIP: "192.168.1.1", ResponseSizeBytes: 45,
		}},
		ResponseAttempt:   1,
		PeerIP:            "192.168.1.1",
		Protocol:          dnsobs.ProtocolUDP,
		StartedAt:         time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC),
		ObservedAt:        time.Date(2026, 7, 19, 12, 0, 0, int(time.Millisecond), time.UTC),
		FinishedAt:        time.Date(2026, 7, 19, 12, 0, 0, int(time.Millisecond), time.UTC),
		DurationMS:        1,
		ResponseSizeBytes: 45,
		RCode:             bytePointerEngineTest(0),
		Flags:             dnsobs.DNSFlags{Response: true},
		Outcome:           dnsobs.DNSOutcomeAnswer,
		Comparison:        dnsobs.ComparisonUnknown,
		DNSSEC:            dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		Sections: dnsobs.Sections{
			Answer: []dnsobs.ResourceRecord{{
				Owner: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN, TTL: 60,
				DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
			}},
			Additional: dnskeyRRSet,
		},
	}
	single := observation
	single.ResultTruncated = true
	single.Sections.Additional = single.Sections.Additional[:1]
	singleRaw, err := json.Marshal(single)
	if err != nil {
		t.Fatalf("marshal one-member budget fixture: %v", err)
	}

	fitted, dropped, err := FitObservationToBytes(observation, len(singleRaw))
	if err != nil {
		t.Fatalf("FitObservationToBytes: %v", err)
	}
	if !dropped || !fitted.ResultTruncated || fitted.ResponseTruncated {
		t.Fatalf("fit markers = dropped %t observation %+v", dropped, fitted)
	}
	if fitted.ResponseAttempt != observation.ResponseAttempt || !reflect.DeepEqual(fitted.Attempts, observation.Attempts) {
		t.Fatalf("fit changed immutable transcript: before=%+v/%d after=%+v/%d", observation.Attempts, observation.ResponseAttempt, fitted.Attempts, fitted.ResponseAttempt)
	}
	if count := len(fitted.Sections.Additional); count != 0 && count != 2 {
		t.Fatalf("canonical RRset was split after owner normalization: retained %d of 2", count)
	}
	for _, record := range fitted.Sections.Additional {
		if record.RRSetRecordCount != 2 {
			t.Fatalf("retained RRset count evidence = %d, want 2", record.RRSetRecordCount)
		}
	}

	wireTruncated := observation
	wireTruncated.Endpoint.Protocol = dnsobs.ProtocolTCP
	wireTruncated.Protocol = dnsobs.ProtocolTCP
	wireTruncated.Attempts[0].Protocol = dnsobs.ProtocolTCP
	wireTruncated.Attempts[0].ResponseTruncated = true
	wireTruncated.Flags.Truncated = true
	wireTruncated.ResponseTruncated = true
	doubleTruncated, _, err := FitObservationToBytes(wireTruncated, len(singleRaw))
	if err != nil {
		t.Fatalf("fit wire-truncated observation: %v", err)
	}
	if !doubleTruncated.ResponseTruncated || !doubleTruncated.ResultTruncated {
		t.Fatalf("fit lost independent truncation states: %+v", doubleTruncated)
	}
}

func TestFitObservationFailsWhenImmutableTranscriptExceedsBudget(t *testing.T) {
	started := time.Date(2026, 7, 19, 12, 15, 0, 0, time.UTC)
	rcode := uint8(0)
	observation, err := dnsobs.NormalizeObservation(dnsobs.Observation{
		Schema: dnsobs.SchemaV1, RoundID: "round-fit-transcript", OperationID: "operation-fit-transcript",
		Question:        dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:        dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolTCP, Port: 53},
		TransportStatus: dnsobs.TransportSuccess, AttemptCount: 2,
		Attempts: []dnsobs.WireAttempt{
			{Protocol: dnsobs.ProtocolTCP, TransportStatus: dnsobs.TransportTimeout, StartedAt: started, FinishedAt: started.Add(time.Millisecond), DurationMS: 1, Error: &dnsobs.AttemptError{Code: "TIMEOUT", Retryable: true}},
			{Protocol: dnsobs.ProtocolTCP, TransportStatus: dnsobs.TransportSuccess, StartedAt: started.Add(2 * time.Millisecond), FinishedAt: started.Add(3 * time.Millisecond), DurationMS: 1, PeerIP: "8.8.8.8", ResponseSizeBytes: 12},
		},
		ResponseAttempt: 2, PeerIP: "8.8.8.8", Protocol: dnsobs.ProtocolTCP,
		StartedAt: started, ObservedAt: started.Add(3 * time.Millisecond), FinishedAt: started.Add(3 * time.Millisecond), DurationMS: 3,
		RCode: &rcode, Flags: dnsobs.DNSFlags{Response: true}, Outcome: dnsobs.DNSOutcomeNoData,
		Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}, ResponseSizeBytes: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	const immutableBudget = 256
	if len(raw) <= immutableBudget {
		t.Fatalf("fixture is only %d bytes", len(raw))
	}
	if _, _, err := FitObservationToBytes(observation, immutableBudget); err == nil {
		t.Fatal("fit removed or rewrote the immutable attempt transcript")
	}
}

func cnameRecordForObservationTest(owner string, target string) ResourceRecord {
	wire := make([]byte, 255)
	offset, err := dns.PackDomainName(target, wire, 0, nil, false)
	if err != nil {
		panic(err)
	}
	return ResourceRecord{
		Owner: owner, Type: "CNAME", Class: "IN", TTL: 60,
		DisplayRData: target, CanonicalRData: fmt.Sprintf(`\# %d %X`, offset, wire[:offset]), RRSetRecordCount: 1,
	}
}

func bytePointerEngineTest(value uint8) *uint8 {
	return &value
}

func txtChunksForObservationTest(value string) []string {
	chunks := make([]string, 0, len(value)/255+1)
	for len(value) > 255 {
		chunks = append(chunks, value[:255])
		value = value[255:]
	}
	return append(chunks, value)
}

func canonicalRecordDataForObservationTest(t testing.TB, record dns.RR) (string, string) {
	t.Helper()
	display, canonical, comparable, err := dnsobs.CanonicalRecordDataForRR(record)
	if err != nil || !comparable {
		t.Fatalf("canonicalize %T observation fixture: comparable=%t err=%v", record, comparable, err)
	}
	return display, canonical
}

func dnskeyRecordForObservationTest(t testing.TB, owner string, marker byte, keyBytes, count int) dnsobs.ResourceRecord {
	t.Helper()
	record := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60},
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{marker}, keyBytes)),
	}
	display, canonical := canonicalRecordDataForObservationTest(t, record)
	return dnsobs.ResourceRecord{
		Owner: owner, Type: dnsobs.RRTypeDNSKEY, Class: dnsobs.DNSClassIN, TTL: 60,
		DisplayRData: display, CanonicalRData: canonical, RRSetRecordCount: count,
	}
}

func testObservationEnvelope() ObservationEnvelope {
	return ObservationEnvelope{
		RoundID:     "round-01",
		OperationID: "operation-01",
		Question:    dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:    dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
		Comparison:  dnsobs.ComparisonMatchExpected,
		DNSSEC:      dnsobs.DNSSECResult{Status: dnsobs.DNSSECInsecure, LocallyValidated: true},
	}
}
