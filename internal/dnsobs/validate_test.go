package dnsobs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIsPublicDNSAddressRejectsUnsafeAndNAT64TranslationRanges(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1",
		"192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1",
		"64:ff9b::c000:201", "64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001:db8::1",
		"2002:c000:0201::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if IsPublicDNSAddress(netip.MustParseAddr(value)) {
			t.Errorf("IsPublicDNSAddress(%s) = true, want false", value)
		}
	}
}

func TestIsPublicDNSAddressAllowsRegistryReachableRanges(t *testing.T) {
	for _, value := range []string{
		"1.1.1.1", "8.8.8.8", "192.0.0.9", "192.0.0.10", "192.31.196.1", "192.52.193.1", "192.175.48.1",
		"2001:1::1", "2001:1::2", "2001:1::3", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1",
		"2001:4860:4860::8888", "2606:4700:4700::1111", "2620:4f:8000::1",
	} {
		if !IsPublicDNSAddress(netip.MustParseAddr(value)) {
			t.Errorf("IsPublicDNSAddress(%s) = false, want true", value)
		}
	}
}

func TestNormalizeRequestAppliesDefaultsAndCanonicalNames(t *testing.T) {
	request := Request{
		Schema:  SchemaV1,
		RoundID: " 01KROUND ",
		Operations: []Operation{{
			OperationID: "01KOP",
			Mode:        "RECURSIVE",
			Question:    Question{Name: "b\u00fccher.example", Type: "ns"},
			Endpoint:    Endpoint{Kind: EndpointSystem, Protocol: "UDP"},
			Flags:       QueryFlags{RecursionDesired: true, DNSSECOK: true},
		}},
	}
	got, err := NormalizeRequest(request)
	if err != nil {
		t.Fatalf("NormalizeRequest: %v", err)
	}
	if got.RoundID != "01KROUND" || got.Operations[0].Question.Name != "xn--bcher-kva.example." || got.Operations[0].Question.Type != RRTypeNS || got.Operations[0].Question.Class != DNSClassIN {
		t.Fatalf("normalized request = %+v", got)
	}
	if got.Limits != (Limits{Parallel: DefaultParallel, AttemptTimeoutMS: DefaultAttemptTimeoutMS, MaxAttempts: DefaultMaxAttempts}) {
		t.Fatalf("limits = %+v", got.Limits)
	}
	if got.Operations[0].Endpoint.Port != 53 || got.Operations[0].Flags.EDNSUDPSize != DefaultEDNSUDPSize {
		t.Fatalf("operation defaults = %+v", got.Operations[0])
	}
}

func TestNormalizeSystemEndpointPortIsOnlyTheSystemResolverMarker(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolUDP, ProtocolTCP} {
		for _, port := range []int{0, 53} {
			endpoint, err := NormalizeEndpoint(Endpoint{Kind: EndpointSystem, Protocol: protocol, Port: port})
			if err != nil || endpoint.Port != 53 {
				t.Fatalf("NormalizeEndpoint(protocol=%q port=%d) = %+v, %v", protocol, port, endpoint, err)
			}
		}
	}

	for _, port := range []int{1, 52, 54, 5353, 65535} {
		_, err := NormalizeEndpoint(Endpoint{Kind: EndpointSystem, Protocol: ProtocolUDP, Port: port})
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) || validationErr.Code != "INVALID_SYSTEM_DNS_PORT" {
			t.Errorf("system port %d error = %#v", port, err)
		}
	}

	rootHints, err := NormalizeEndpoint(Endpoint{Kind: EndpointRootHints, Protocol: ProtocolUDP, Port: 5353})
	if err != nil || rootHints.Port != 5353 {
		t.Fatalf("RootHints port behavior changed: %+v, %v", rootHints, err)
	}
}

func TestNormalizeRequestRejectsSchemaQuestionAndIdentityErrors(t *testing.T) {
	base := validRequest()
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "unknown schema", mutate: func(request *Request) { request.Schema = "dns-observation/v2" }},
		{name: "missing round", mutate: func(request *Request) { request.RoundID = "" }},
		{name: "duplicate operation", mutate: func(request *Request) { request.Operations = append(request.Operations, request.Operations[0]) }},
		{name: "ANY", mutate: func(request *Request) { request.Operations[0].Question.Type = "ANY" }},
		{name: "CHAOS", mutate: func(request *Request) { request.Operations[0].Question.Class = "CH" }},
		{name: "private connect IP", mutate: func(request *Request) {
			request.Operations[0].Endpoint = Endpoint{Kind: EndpointCatalog, Protocol: ProtocolUDP, ConnectIP: "192.168.1.1"}
		}},
		{name: "documentation connect IP", mutate: func(request *Request) {
			request.Operations[0].Endpoint = Endpoint{Kind: EndpointCatalog, Protocol: ProtocolUDP, ConnectIP: "192.0.2.1"}
		}},
		{name: "bracketed connect IP", mutate: func(request *Request) {
			request.Operations[0].Endpoint = Endpoint{Kind: EndpointCatalog, Protocol: ProtocolUDP, ConnectIP: "[8.8.8.8]"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.Operations = append([]Operation(nil), base.Operations...)
			test.mutate(&request)
			if normalized, err := NormalizeRequest(request); err == nil {
				t.Fatalf("NormalizeRequest = %+v, want error", normalized)
			}
		})
	}
}

func TestEndpointKindsPreserveResolverLensEvidence(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		endpoint Endpoint
		wantKind EndpointKind
	}{
		{name: "legacy resolver alias", mode: ModeRecursive, endpoint: Endpoint{Kind: "resolver", Protocol: ProtocolUDP, ConnectIP: "8.8.8.8"}, wantKind: EndpointCatalog},
		{name: "catalog", mode: ModeRecursive, endpoint: Endpoint{Kind: EndpointCatalog, Protocol: ProtocolUDP, ConnectIP: "8.8.8.8"}, wantKind: EndpointCatalog},
		{name: "public anycast", mode: ModeRecursive, endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolUDP, ConnectIP: "1.1.1.1"}, wantKind: EndpointPublicAnycast},
		{name: "parent authority", mode: ModeAuthoritative, endpoint: Endpoint{Kind: EndpointParentAuthority, Protocol: ProtocolUDP, ConnectIP: "8.8.4.4"}, wantKind: EndpointParentAuthority},
		{name: "child authority", mode: ModeAuthoritative, endpoint: Endpoint{Kind: EndpointChildAuthority, Protocol: ProtocolTCP, ConnectIP: "8.8.4.4"}, wantKind: EndpointChildAuthority},
		{name: "root hints", mode: ModeIterative, endpoint: Endpoint{Kind: EndpointRootHints, Protocol: ProtocolUDP}, wantKind: EndpointRootHints},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			request.Operations[0].Mode = test.mode
			request.Operations[0].Endpoint = test.endpoint
			request.Operations[0].Flags.RecursionDesired = test.mode == ModeRecursive
			got, err := NormalizeRequest(request)
			if err != nil {
				t.Fatalf("NormalizeRequest: %v", err)
			}
			if got.Operations[0].Endpoint.Kind != test.wantKind {
				t.Fatalf("kind = %q, want %q", got.Operations[0].Endpoint.Kind, test.wantKind)
			}
		})
	}
	request := validRequest()
	request.Operations[0].Mode = ModeAuthoritative
	request.Operations[0].Flags.RecursionDesired = false
	request.Operations[0].Endpoint = Endpoint{Kind: "authoritative", Protocol: ProtocolUDP, ConnectIP: "8.8.8.8"}
	if _, err := NormalizeRequest(request); err == nil {
		t.Fatal("ambiguous authoritative endpoint alias was accepted")
	}
}

func TestNormalizeDoHEndpointPinsConnectIPAndHost(t *testing.T) {
	endpoint, err := NormalizeEndpoint(Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "DNS.Google"})
	if err != nil {
		t.Fatalf("NormalizeEndpoint: %v", err)
	}
	if endpoint.Port != 443 || endpoint.ServerName != "dns.google" || endpoint.HTTPAuthority != "dns.google" || endpoint.HTTPPath != "/dns-query" {
		t.Fatalf("endpoint = %+v", endpoint)
	}
	encoded, err := NormalizeEndpoint(Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/custom%2Fdns-query"})
	if err != nil {
		t.Fatalf("NormalizeEndpoint escaped path: %v", err)
	}
	if encoded.HTTPPath != "/custom%2Fdns-query" {
		t.Fatalf("escaped HTTP path = %q", encoded.HTTPPath)
	}
	for _, test := range []struct {
		name     string
		endpoint Endpoint
	}{
		{name: "missing server name", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8"}},
		{name: "server name IP", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "8.8.8.8"}},
		{name: "server name trailing-dot IP", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "8.8.8.8."}},
		{name: "URL path", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "https://dns.google/dns-query"}},
		{name: "malformed percent escape", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/%zz"}},
		{name: "NUL", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns\x00query"}},
		{name: "encoded NUL", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns%00query"}},
		{name: "backslash", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: `/dns\query`}},
		{name: "encoded backslash", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns%5cquery"}},
		{name: "space", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns query"}},
		{name: "leading space", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: " /dns-query"}},
		{name: "trailing space", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns-query "}},
		{name: "encoded space", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns%20query"}},
		{name: "query", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns-query?x=1"}},
		{name: "fragment", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "/dns-query#fragment"}},
		{name: "network path", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPPath: "//other.example/dns-query"}},
		{name: "authority on UDP", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolUDP, ConnectIP: "8.8.8.8", HTTPAuthority: "dns.google"}},
		{name: "authority on DoT", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoT, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "dns.google"}},
		{name: "authority with port", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "dns.google:8443"}},
		{name: "authority with scheme", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "https://dns.google"}},
		{name: "authority IP", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "8.8.8.8"}},
		{name: "authority trailing-dot IP", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "8.8.8.8."}},
		{name: "authority underscore", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "_dns.google"}},
		{name: "authority wildcard", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "*.dns.google"}},
		{name: "authority invalid IDNA", endpoint: Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolDoH, ConnectIP: "8.8.8.8", ServerName: "dns.google", HTTPAuthority: "\u200d.example"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := NormalizeEndpoint(test.endpoint); err == nil {
				t.Errorf("NormalizeEndpoint(%+v) = %+v, want error", test.endpoint, got)
			}
		})
	}

	request := validRequest()
	request.Operations[0].Endpoint = Endpoint{
		Kind:          EndpointPublicAnycast,
		Protocol:      ProtocolDoH,
		ConnectIP:     "8.8.8.8",
		ServerName:    "TLS.Resolver.Example",
		HTTPAuthority: "B\u00dcCHER.Example.",
		Port:          8443,
	}
	normalized, err := NormalizeRequest(request)
	if err != nil {
		t.Fatalf("NormalizeRequest with separate DoH identities: %v", err)
	}
	got := normalized.Operations[0].Endpoint
	if got.ServerName != "tls.resolver.example" || got.HTTPAuthority != "xn--bcher-kva.example" || got.Port != 8443 || got.HTTPPath != "/dns-query" {
		t.Fatalf("normalized DoH identities = %+v", got)
	}
}

func TestNormalizeBatchResultForRequestOrdersAndBindsObservations(t *testing.T) {
	request := requestWithTwoOperations()
	first := observationForOperation(request.RoundID, request.Operations[0])
	second := observationForOperation(request.RoundID, request.Operations[1])
	batch := BatchResult{Schema: SchemaV1, RoundID: " 01KROUND ", Observations: []Observation{second, first}}

	got, err := NormalizeBatchResultForRequest(request, batch)
	if err != nil {
		t.Fatalf("NormalizeBatchResultForRequest: %v", err)
	}
	if got.Schema != SchemaV1 || got.RoundID != request.RoundID || len(got.Observations) != 2 {
		t.Fatalf("normalized batch = %+v", got)
	}
	if got.Observations[0].OperationID != request.Operations[0].OperationID || got.Observations[1].OperationID != request.Operations[1].OperationID {
		t.Fatalf("observations were not restored to request order: %+v", got.Observations)
	}
	if got.Observations[1].Question.Name != "www.example.com." || got.Observations[0].Sections.Answer[0].RRSetFingerprint == "" {
		t.Fatalf("observations were not normalized: %+v", got.Observations)
	}
	if batch.Observations[1].Sections.Answer[0].RRSetFingerprint != "" {
		t.Fatal("NormalizeBatchResultForRequest mutated its input")
	}
}

func TestNormalizeBatchResultAcceptsCancelledOperationBeforeFirstAttempt(t *testing.T) {
	request := requestWithTwoOperations()
	completed := observationForOperation(request.RoundID, request.Operations[0])
	cancelled := observationForOperation(request.RoundID, request.Operations[1])
	cancelled.TransportStatus = TransportCancelled
	cancelled.AttemptCount = 0
	cancelled.Attempts = []WireAttempt{}
	cancelled.ResponseAttempt = 0
	cancelled.PeerIP = ""
	cancelled.ResponseSizeBytes = 0
	cancelled.DurationMS = 0
	cancelled.Outcome = DNSOutcomeNotObserved
	cancelled.Comparison = ""
	cancelled.RCode = nil
	cancelled.Flags = DNSFlags{}
	cancelled.Sections = Sections{}
	cancelled.Error = &ObservationError{Code: "CANCELLED", Message: "operation cancelled before execution"}
	cancelled.StartedAt = cancelled.ObservedAt
	cancelled.FinishedAt = cancelled.ObservedAt

	got, err := NormalizeBatchResultForRequest(request, BatchResult{
		Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{completed, cancelled},
	})
	if err != nil {
		t.Fatalf("NormalizeBatchResultForRequest cancelled operation: %v", err)
	}
	if got.Observations[1].TransportStatus != TransportCancelled || got.Observations[1].AttemptCount != 0 || got.Observations[1].Outcome != DNSOutcomeNotObserved || got.Observations[1].Comparison != ComparisonUnknown {
		t.Fatalf("normalized cancelled observation = %+v", got.Observations[1])
	}
}

func TestNormalizeBatchResultBindsObservationAttemptsToRequestLimit(t *testing.T) {
	for _, test := range []struct {
		name        string
		maxAttempts int
		protocol    Protocol
		mutate      func(*Observation)
	}{
		{name: "ordinary retry", maxAttempts: 1, protocol: ProtocolTCP, mutate: setSameProtocolRetrySuccess},
		{name: "UDP TCP fallback retry", maxAttempts: 2, protocol: ProtocolUDP, mutate: func(observation *Observation) {
			*observation = threeAttemptFallbackObservation(false)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			request.Limits.MaxAttempts = test.maxAttempts
			request.Operations[0].Endpoint.Protocol = test.protocol
			observation := observationForOperation(request.RoundID, request.Operations[0])
			test.mutate(&observation)
			observation.RoundID = request.RoundID
			observation.OperationID = request.Operations[0].OperationID
			observation.Question = request.Operations[0].Question
			observation.Endpoint = request.Operations[0].Endpoint
			_, err := NormalizeBatchResultForRequest(request, BatchResult{
				Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{observation},
			})
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) || validationErr.Code != "ATTEMPT_LIMIT_EXCEEDED" {
				t.Fatalf("error = %#v, want ATTEMPT_LIMIT_EXCEEDED", err)
			}
		})
	}
}

func TestObservationRejectsThirdAttemptWithoutUDPToTCPFallback(t *testing.T) {
	observation := validObservation()
	observation.AttemptCount = 3
	firstFinished := observation.StartedAt.Add(2 * time.Millisecond)
	secondStarted := firstFinished.Add(time.Millisecond)
	secondFinished := secondStarted.Add(2 * time.Millisecond)
	thirdStarted := secondFinished.Add(time.Millisecond)
	observation.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: observation.StartedAt, FinishedAt: firstFinished, DurationMS: 2, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: secondStarted, FinishedAt: secondFinished, DurationMS: 2, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: thirdStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(thirdStarted).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes},
	}
	observation.ResponseAttempt = 3
	_, err := NormalizeObservation(observation)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "INVALID_RETRY_SEQUENCE" {
		t.Fatalf("third non-fallback attempt error = %#v", err)
	}
}

func TestBatchReferralRequiresIterativeParentOperation(t *testing.T) {
	request := validRequest()
	referral := observationWithOutcome(DNSOutcomeReferral)
	referral.RoundID = request.RoundID
	referral.OperationID = request.Operations[0].OperationID
	referral.Question = request.Operations[0].Question
	referral.Endpoint = request.Operations[0].Endpoint
	_, err := NormalizeBatchResultForRequest(request, BatchResult{Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{referral}})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "REFERRAL_MODE_MISMATCH" {
		t.Fatalf("recursive referral error = %#v", err)
	}

	request.Operations[0].Mode = ModeIterative
	request.Operations[0].Endpoint = Endpoint{Kind: EndpointRootHints, Protocol: ProtocolUDP, Port: 53}
	request.Operations[0].Flags.RecursionDesired = false
	referral.Endpoint = request.Operations[0].Endpoint
	if _, err := NormalizeBatchResultForRequest(request, BatchResult{Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{referral}}); err != nil {
		t.Fatalf("iterative parent referral: %v", err)
	}
}

func TestUnstartedCancellationRejectsAnyExecutionEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*Observation){
		"peer":          func(value *Observation) { value.PeerIP = "192.168.1.1" },
		"response size": func(value *Observation) { value.ResponseSizeBytes = 12 },
		"duration":      func(value *Observation) { value.DurationMS = 1 },
		"response truncated": func(value *Observation) {
			value.ResponseTruncated = true
			value.Flags.Truncated = true
		},
		"result truncated": func(value *Observation) { value.ResultTruncated = true },
		"fallback": func(value *Observation) {
			value.UDPToTCPFallback = true
			value.Protocol = ProtocolTCP
		},
		"flags":         func(value *Observation) { value.Flags.Response = true },
		"secure DNSSEC": func(value *Observation) { value.DNSSEC = DNSSECResult{Status: DNSSECSecure, LocallyValidated: true} },
		"wrong code":    func(value *Observation) { value.Error.Code = "ABORTED" },
		"retryable":     func(value *Observation) { value.Error.Retryable = true },
		"distinct evidence time": func(value *Observation) {
			value.ObservedAt = value.StartedAt.Add(time.Nanosecond)
			value.FinishedAt = value.ObservedAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := unstartedCancellationObservation()
			mutate(&observation)
			if _, err := NormalizeObservation(observation); err == nil {
				t.Fatalf("unstarted cancellation with %s was accepted", name)
			}
		})
	}
}

func TestObservationTimelineContract(t *testing.T) {
	input := validObservation()
	input.StartedAt = time.Date(2026, time.July, 19, 17, 59, 59, 988*int(time.Millisecond), time.FixedZone("CST", 8*60*60))
	input.ObservedAt = input.StartedAt.Add(10 * time.Millisecond)
	input.FinishedAt = input.StartedAt.Add(12 * time.Millisecond)
	input.Attempts[0].StartedAt = input.StartedAt
	input.Attempts[0].FinishedAt = input.ObservedAt
	input.Attempts[0].DurationMS = input.ObservedAt.Sub(input.StartedAt).Milliseconds()
	normalized, err := NormalizeObservation(input)
	if err != nil {
		t.Fatalf("NormalizeObservation timeline: %v", err)
	}
	if normalized.StartedAt.Location() != time.UTC || normalized.ObservedAt.Location() != time.UTC || normalized.FinishedAt.Location() != time.UTC {
		t.Fatalf("timeline was not normalized to UTC: %s/%s/%s", normalized.StartedAt, normalized.ObservedAt, normalized.FinishedAt)
	}
	if !normalized.StartedAt.Before(normalized.ObservedAt) || !normalized.ObservedAt.Before(normalized.FinishedAt) {
		t.Fatalf("normalized timeline order = %s/%s/%s", normalized.StartedAt, normalized.ObservedAt, normalized.FinishedAt)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Observation)
	}{
		{name: "missing started", mutate: func(value *Observation) { value.StartedAt = time.Time{} }},
		{name: "missing observed", mutate: func(value *Observation) { value.ObservedAt = time.Time{} }},
		{name: "missing finished", mutate: func(value *Observation) { value.FinishedAt = time.Time{} }},
		{name: "observed before start", mutate: func(value *Observation) { value.ObservedAt = value.StartedAt.Add(-time.Nanosecond) }},
		{name: "observed after finish", mutate: func(value *Observation) { value.ObservedAt = value.FinishedAt.Add(time.Nanosecond) }},
		{name: "finish before start", mutate: func(value *Observation) {
			value.FinishedAt = value.StartedAt.Add(-time.Nanosecond)
			value.ObservedAt = value.FinishedAt
		}},
		{name: "duration mismatch", mutate: func(value *Observation) { value.DurationMS++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			test.mutate(&observation)
			if _, err := NormalizeObservation(observation); err == nil {
				t.Fatalf("invalid timeline was accepted: %+v", observation)
			}
		})
	}
}

func TestNormalizeBatchResultRejectsBrokenRequestBindings(t *testing.T) {
	request := requestWithTwoOperations()
	first := observationForOperation(request.RoundID, request.Operations[0])
	second := observationForOperation(request.RoundID, request.Operations[1])
	valid := BatchResult{Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{first, second}}

	for _, test := range []struct {
		name   string
		mutate func(*BatchResult)
		code   string
	}{
		{name: "batch schema", mutate: func(batch *BatchResult) { batch.Schema = "dns-observation/v2" }, code: "UNSUPPORTED_SCHEMA"},
		{name: "batch cross round", mutate: func(batch *BatchResult) { batch.RoundID = "01KOTHER" }, code: "ROUND_ID_MISMATCH"},
		{name: "observation cross round", mutate: func(batch *BatchResult) { batch.Observations[1].RoundID = "01KOTHER" }, code: "OBSERVATION_ROUND_MISMATCH"},
		{name: "duplicate", mutate: func(batch *BatchResult) { batch.Observations[1] = batch.Observations[0] }, code: "DUPLICATE_OBSERVATION"},
		{name: "missing", mutate: func(batch *BatchResult) { batch.Observations = batch.Observations[:1] }, code: "MISSING_OBSERVATION"},
		{name: "extra", mutate: func(batch *BatchResult) {
			extra := batch.Observations[0]
			extra.OperationID = "01KEXTRA"
			batch.Observations = append(batch.Observations, extra)
		}, code: "UNKNOWN_OPERATION_ID"},
		{name: "question", mutate: func(batch *BatchResult) { batch.Observations[1].Question.Name = "other.example" }, code: "QUESTION_MISMATCH"},
		{name: "endpoint", mutate: func(batch *BatchResult) { batch.Observations[1].Endpoint.Kind = EndpointRootHints }, code: "ENDPOINT_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := valid
			batch.Observations = append([]Observation(nil), valid.Observations...)
			test.mutate(&batch)
			_, err := NormalizeBatchResultForRequest(request, batch)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) || validationErr.Code != test.code {
				t.Fatalf("error = %#v, want validation code %s", err, test.code)
			}
		})
	}
}

func TestNormalizeBatchResultEnforcesEncodedTaskLimit(t *testing.T) {
	request := validRequest()
	request.Operations = make([]Operation, 64)
	observations := make([]Observation, len(request.Operations))
	for i := range request.Operations {
		operation := validRequest().Operations[0]
		operation.OperationID = fmt.Sprintf("op-%03d", i)
		request.Operations[i] = operation
		observation := observationForOperation(request.RoundID, operation)
		observation.Sections.Answer = []ResourceRecord{
			largeDNSKEYRecordForTest(0xAA, 2),
			largeDNSKEYRecordForTest(0xBB, 2),
		}
		observations[i] = observation
	}
	_, err := NormalizeBatchResultForRequest(request, BatchResult{Schema: SchemaV1, RoundID: request.RoundID, Observations: observations})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "TASK_RESULT_TOO_LARGE" {
		t.Fatalf("error = %#v, want TASK_RESULT_TOO_LARGE", err)
	}
}

func largeDNSKEYRecordForTest(marker byte, count int) ResourceRecord {
	record := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60},
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 8184)),
	}
	display, canonical, comparable, err := CanonicalRecordDataForRR(record)
	if err != nil || !comparable {
		panic(fmt.Sprintf("canonicalize large DNSKEY fixture: comparable=%t err=%v", comparable, err))
	}
	return ResourceRecord{
		Owner: record.Hdr.Name, Type: RRTypeDNSKEY, Class: DNSClassIN, TTL: record.Hdr.Ttl,
		DisplayRData: display, CanonicalRData: canonical, RRSetRecordCount: count,
	}
}

func TestNormalizeObservationBuildsFingerprintsWithoutMutatingInput(t *testing.T) {
	input := validObservation()
	input.StartedAt = time.Date(2026, time.July, 19, 17, 59, 59, 988*int(time.Millisecond), time.FixedZone("CST", 8*60*60))
	input.ObservedAt = time.Date(2026, time.July, 19, 18, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	input.FinishedAt = input.ObservedAt
	input.Attempts[0].StartedAt = input.StartedAt
	input.Attempts[0].FinishedAt = input.ObservedAt
	input.Attempts[0].DurationMS = input.ObservedAt.Sub(input.StartedAt).Milliseconds()
	got, err := NormalizeObservation(input)
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if got.Sections.Answer[0].RRSetFingerprint == "" || !ValidRRSetFingerprint(got.Sections.Answer[0].RRSetFingerprint) {
		t.Fatalf("fingerprint = %q", got.Sections.Answer[0].RRSetFingerprint)
	}
	if input.Sections.Answer[0].RRSetFingerprint != "" {
		t.Fatal("NormalizeObservation mutated its input")
	}
	if got.Comparison != ComparisonUnknown || got.DNSSEC.Status != DNSSECIndeterminate {
		t.Fatalf("default classifications = %q, %q", got.Comparison, got.DNSSEC.Status)
	}
	if got.ObservedAt.Location() != time.UTC || got.ObservedAt.Hour() != 10 {
		t.Fatalf("normalized observed_at = %s", got.ObservedAt)
	}
}

func TestDNSOutcomeCoversEveryRCodeClassWithoutMalformed(t *testing.T) {
	tests := []struct {
		name     string
		base     uint8
		extended uint8
		outcome  DNSOutcome
	}{
		{name: "NOERROR answer", base: 0, outcome: DNSOutcomeAnswer},
		{name: "NOERROR NODATA", base: 0, outcome: DNSOutcomeNoData},
		{name: "FORMERR", base: 1, outcome: DNSOutcomeRCodeError},
		{name: "SERVFAIL", base: 2, outcome: DNSOutcomeServFail},
		{name: "NXDOMAIN", base: 3, outcome: DNSOutcomeNXDomain},
		{name: "NOTIMP", base: 4, outcome: DNSOutcomeRCodeError},
		{name: "REFUSED", base: 5, outcome: DNSOutcomeRefused},
		{name: "YXDOMAIN", base: 6, outcome: DNSOutcomeRCodeError},
		{name: "BADVERS extended", base: 0, extended: 1, outcome: DNSOutcomeRCodeError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			observation.RCode = bytePointer(test.base)
			if test.extended != 0 {
				observation.ExtendedRCode = bytePointer(test.extended)
				observation.EDNS = EDNS{Present: true, UDPSize: DefaultEDNSUDPSize}
			}
			observation.Outcome = test.outcome
			if test.outcome != DNSOutcomeAnswer {
				observation.Sections.Answer = nil
			}
			if _, err := NormalizeObservation(observation); err != nil {
				t.Fatalf("NormalizeObservation: %v", err)
			}
		})
	}
	bad := validObservation()
	bad.RCode = bytePointer(4)
	bad.Outcome = DNSOutcomeMalformed
	bad.Error = &ObservationError{Code: "MALFORMED_DNS", Message: "bad message"}
	if _, err := NormalizeObservation(bad); err == nil {
		t.Fatal("parsed NOTIMP response was accepted as malformed")
	}
}

func TestTransportFailureIsNotADNSFailure(t *testing.T) {
	observation := validObservation()
	observation.TransportStatus = TransportTimeout
	observation.AttemptCount = 2
	observation.PeerIP = ""
	observation.ResponseSizeBytes = 0
	observation.ResponseAttempt = 0
	middle := observation.StartedAt.Add(5 * time.Millisecond)
	observation.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: observation.StartedAt, FinishedAt: middle, DurationMS: 5, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: middle.Add(time.Millisecond), FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(middle.Add(time.Millisecond)).Milliseconds(), Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
	}
	observation.ObservedAt = observation.FinishedAt
	observation.RCode = nil
	observation.Flags = DNSFlags{}
	observation.Outcome = DNSOutcomeNotObserved
	observation.Sections = Sections{}
	observation.Error = &ObservationError{Code: "TIMEOUT", Message: "attempt timed out", Retryable: true}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("NormalizeObservation timeout: %v", err)
	}
	observation.Error = nil
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("transport failure without structured error was accepted")
	}
	observation.Error = &ObservationError{Code: "TIMEOUT", Message: "attempt timed out", Retryable: true}
	observation.Outcome = ""
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("transport failure without not_observed outcome was accepted")
	}
	observation.Outcome = DNSOutcomeNotObserved
	observation.Comparison = ComparisonMatchExpected
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("failed transport with comparable status was accepted")
	}

	withParsedResponse := validObservation()
	withParsedResponse.TransportStatus = TransportTimeout
	withParsedResponse.Outcome = DNSOutcomeNotObserved
	withParsedResponse.Comparison = ComparisonUnknown
	withParsedResponse.Error = &ObservationError{Code: "TIMEOUT", Message: "attempt timed out", Retryable: true}
	if _, err := NormalizeObservation(withParsedResponse); err == nil {
		t.Fatal("not_observed failure with parsed DNS fields was accepted")
	}
}

func TestCancelledTransportRequiresCanonicalNonRetryableError(t *testing.T) {
	observation := observationWithOutcome(DNSOutcomeNotObserved)
	observation.TransportStatus = TransportCancelled
	observation.Error = &ObservationError{Code: "CANCELLED", Message: "operation cancelled"}
	observation.Attempts[0].TransportStatus = TransportCancelled
	observation.Attempts[0].Error = &AttemptError{Code: "CANCELLED"}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("canonical cancellation: %v", err)
	}

	for _, mutate := range []func(*Observation){
		func(value *Observation) { value.Error.Code = "ABORTED" },
		func(value *Observation) { value.Error.Retryable = true },
	} {
		invalid := observation
		invalid.Error = &ObservationError{Code: observation.Error.Code, Message: observation.Error.Message}
		mutate(&invalid)
		if _, err := NormalizeObservation(invalid); err == nil {
			t.Fatalf("invalid cancellation error was accepted: %+v", invalid.Error)
		}
	}
}

func TestFailedTCPFallbackMayRetainValidatedTruncatedUDP(t *testing.T) {
	observation := validObservation()
	observation.Endpoint.Protocol = ProtocolUDP
	observation.Protocol = ProtocolTCP
	observation.TransportStatus = TransportTimeout
	setFailedFallback(&observation, TransportTimeout, AttemptError{Code: "TIMEOUT", Retryable: true})
	observation.Comparison = ""
	observation.Error = &ObservationError{Code: "TIMEOUT", Message: "TCP fallback timed out", Retryable: true}
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("NormalizeObservation retained fallback: %v", err)
	}
	if normalized.Comparison != ComparisonUnknown {
		t.Fatalf("default fallback comparison = %q, want %q", normalized.Comparison, ComparisonUnknown)
	}

	for name, mutate := range map[string]func(*Observation){
		"endpoint is not UDP":       func(value *Observation) { value.Endpoint.Protocol = ProtocolTCP },
		"final protocol is not TCP": func(value *Observation) { value.Protocol = ProtocolUDP },
		"one attempt":               func(value *Observation) { value.AttemptCount = 1 },
		"TC missing":                func(value *Observation) { value.Flags.Truncated = false },
		"not declared truncated":    func(value *Observation) { value.ResponseTruncated = false },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := observation
			mutate(&invalid)
			if _, err := NormalizeObservation(invalid); err == nil {
				t.Fatalf("invalid fallback was accepted: %+v", invalid)
			}
		})
	}
}

func TestTruncatedResponseContract(t *testing.T) {
	observation := validObservation()
	observation.Endpoint.Protocol = ProtocolUDP
	observation.Protocol = ProtocolTCP
	observation.TransportStatus = TransportNetworkError
	setFailedFallback(&observation, TransportNetworkError, AttemptError{Code: "NETWORK_ERROR", Retryable: true})
	observation.Outcome = DNSOutcomeTruncatedResponse
	observation.Comparison = ""
	observation.DNSSEC = DNSSECResult{}
	observation.Sections = Sections{}
	observation.ResponseSizeBytes = 40
	observation.Attempts[0].ResponseSizeBytes = 40
	observation.Error = &ObservationError{Code: "NETWORK_ERROR", Message: "TCP fallback failed", Retryable: true}
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("NormalizeObservation truncated response: %v", err)
	}
	if normalized.Comparison != ComparisonUnknown || normalized.DNSSEC.Status != DNSSECIndeterminate || normalized.ExtendedRCode != nil {
		t.Fatalf("normalized truncated response = %+v", normalized)
	}
	doubleTruncated := observation
	doubleTruncated.ResultTruncated = true
	if normalizedDouble, err := NormalizeObservation(doubleTruncated); err != nil {
		t.Fatalf("wire and result truncation together: %v", err)
	} else if !normalizedDouble.ResponseTruncated || !normalizedDouble.ResultTruncated {
		t.Fatalf("double truncation was lost: %+v", normalizedDouble)
	}

	malformedFallback := observation
	malformedFallback.TransportStatus = TransportSuccess
	malformedFallback.Error = &ObservationError{Code: "MALFORMED_DNS", Message: "TCP fallback response was malformed"}
	malformedFallback.Attempts[1].TransportStatus = TransportSuccess
	malformedFallback.Attempts[1].Error = nil
	malformedFallback.Attempts[1].PeerIP = malformedFallback.PeerIP
	malformedFallback.Attempts[1].ResponseSizeBytes = malformedFallback.ResponseSizeBytes
	malformedFallback.Attempts[1].ResponseTruncated = true
	malformedFallback.ResponseAttempt = 2
	malformedFallback.ObservedAt = malformedFallback.Attempts[1].FinishedAt
	if _, err := NormalizeObservation(malformedFallback); err != nil {
		t.Fatalf("received malformed TCP fallback: %v", err)
	}
	malformedFallback.Error.Retryable = true
	if _, err := NormalizeObservation(malformedFallback); err == nil {
		t.Fatal("received malformed TCP fallback was accepted as retryable")
	}

	for name, mutate := range map[string]func(*Observation){
		"missing fallback":      func(value *Observation) { value.UDPToTCPFallback = false },
		"missing error":         func(value *Observation) { value.Error = nil },
		"short response":        func(value *Observation) { value.ResponseSizeBytes = 11 },
		"extended rcode":        func(value *Observation) { value.ExtendedRCode = bytePointer(1) },
		"EDNS body":             func(value *Observation) { value.EDNS = EDNS{Present: true, UDPSize: 1232} },
		"answer body":           func(value *Observation) { value.Sections = validObservation().Sections },
		"validated DNSSEC":      func(value *Observation) { value.DNSSEC = DNSSECResult{Status: DNSSECSecure, LocallyValidated: true} },
		"comparable response":   func(value *Observation) { value.Comparison = ComparisonMatchExpected },
		"missing response flag": func(value *Observation) { value.Flags.Response = false },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := observation
			mutate(&invalid)
			if _, err := NormalizeObservation(invalid); err == nil {
				t.Fatalf("invalid truncated response was accepted: %+v", invalid)
			}
		})
	}
}

func TestObservationJSONUsesExplicitTruncationFields(t *testing.T) {
	observation := validObservation()
	observation.ResultTruncated = true
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(raw, &topLevel); err != nil {
		t.Fatalf("decode observation object: %v", err)
	}
	if _, ok := topLevel["response_truncated"]; !ok {
		t.Fatal("response_truncated is missing from observation JSON")
	}
	if _, ok := topLevel["result_truncated"]; !ok {
		t.Fatal("result_truncated is missing from observation JSON")
	}
	if _, ok := topLevel["truncated"]; ok {
		t.Fatal("legacy ambiguous truncated field remains in observation JSON")
	}
}

func TestObservationProtocolMustDescribeAValidFallback(t *testing.T) {
	observation := validObservation()
	observation.Endpoint.Protocol = ProtocolUDP
	observation.Protocol = ProtocolTCP
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("protocol mismatch without fallback was accepted")
	}
	setSuccessfulFallback(&observation)
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("valid successful fallback: %v", err)
	}
	observation.AttemptCount = 1
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("fallback with one attempt was accepted")
	}
	observation.AttemptCount = 3
	udpFailureFinished := observation.StartedAt.Add(time.Millisecond)
	udpTCStarted := udpFailureFinished.Add(time.Millisecond)
	udpTCFinished := udpTCStarted.Add(2 * time.Millisecond)
	tcpStarted := udpTCFinished.Add(time.Millisecond)
	observation.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: observation.StartedAt, FinishedAt: udpFailureFinished, DurationMS: 1, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: udpTCStarted, FinishedAt: udpTCFinished, DurationMS: 2, PeerIP: observation.PeerIP, ResponseSizeBytes: 28, ResponseTruncated: true},
		{Protocol: ProtocolTCP, TransportStatus: TransportSuccess, StartedAt: tcpStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(tcpStarted).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes},
	}
	observation.ResponseAttempt = 3
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("fallback with one physical retry: %v", err)
	}
}

func TestObservationComparisonAndTruncationGuards(t *testing.T) {
	successfulNotObserved := validObservation()
	successfulNotObserved.Outcome = DNSOutcomeNotObserved
	if _, err := NormalizeObservation(successfulNotObserved); err == nil {
		t.Fatal("successful not_observed outcome was accepted")
	}

	observation := validObservation()
	observation.ResultTruncated = true
	observation.Comparison = ComparisonMatchExpected
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("truncated matching observation was accepted")
	}
	observation.Comparison = ComparisonUnknown
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("truncated unknown observation: %v", err)
	}
	observation.ResponseTruncated = false
	observation.Flags.Truncated = true
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("TC response without contract truncation was accepted")
	}

	malformed := validObservation()
	malformed.RCode = nil
	malformed.Flags = DNSFlags{}
	malformed.Outcome = DNSOutcomeMalformed
	malformed.Sections = Sections{}
	malformed.Comparison = ComparisonMatchExpected
	malformed.Error = &ObservationError{Code: "MALFORMED_DNS", Message: "response could not be parsed"}
	if _, err := NormalizeObservation(malformed); err == nil {
		t.Fatal("comparable malformed observation was accepted")
	}
	malformed.Comparison = ""
	normalized, err := NormalizeObservation(malformed)
	if err != nil {
		t.Fatalf("malformed observation with default comparison: %v", err)
	}
	if normalized.Comparison != ComparisonUnknown {
		t.Fatalf("default malformed comparison = %q, want %q", normalized.Comparison, ComparisonUnknown)
	}
}

func TestObservationDNSSECOutcomeMatrix(t *testing.T) {
	tests := []struct {
		name       string
		outcome    DNSOutcome
		dnssec     DNSSECResult
		truncated  bool
		wantAccept bool
	}{
		{name: "secure answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}, wantAccept: true},
		{name: "insecure NODATA", outcome: DNSOutcomeNoData, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}, wantAccept: true},
		{name: "secure NXDOMAIN", outcome: DNSOutcomeNXDomain, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}, wantAccept: true},
		{name: "bogus SERVFAIL", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECBogus, LocallyValidated: true, ReasonCode: "SIGNATURE_EXPIRED"}, wantAccept: true},
		{name: "indeterminate answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, wantAccept: true},
		{name: "secure SERVFAIL", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}},
		{name: "insecure REFUSED", outcome: DNSOutcomeRefused, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}},
		{name: "secure referral", outcome: DNSOutcomeReferral, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}},
		{name: "insecure rcode error", outcome: DNSOutcomeRCodeError, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}},
		{name: "secure malformed", outcome: DNSOutcomeMalformed, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}},
		{name: "insecure not observed", outcome: DNSOutcomeNotObserved, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}},
		{name: "bogus answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECBogus, LocallyValidated: true, ReasonCode: "SIGNATURE_EXPIRED"}},
		{name: "bogus missing reason", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECBogus, LocallyValidated: true}},
		{name: "bogus not locally validated", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECBogus, ReasonCode: "SIGNATURE_EXPIRED"}},
		{name: "secure cropped answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}, truncated: true},
		{name: "insecure cropped NXDOMAIN", outcome: DNSOutcomeNXDomain, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}, truncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := observationWithOutcome(test.outcome)
			observation.DNSSEC = test.dnssec
			observation.ResultTruncated = observation.ResultTruncated || test.truncated
			_, err := NormalizeObservation(observation)
			if test.wantAccept && err != nil {
				t.Fatalf("NormalizeObservation: %v", err)
			}
			if !test.wantAccept && err == nil {
				t.Fatalf("invalid DNSSEC shape was accepted: %+v", observation)
			}
		})
	}
}

func TestObservationComparisonMatrix(t *testing.T) {
	for _, test := range []struct {
		name       string
		outcome    DNSOutcome
		dnssec     DNSSECResult
		comparison Comparison
		wantAccept bool
	}{
		{name: "secure answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}, comparison: ComparisonMatchExpected, wantAccept: true},
		{name: "insecure NODATA", outcome: DNSOutcomeNoData, dnssec: DNSSECResult{Status: DNSSECInsecure, LocallyValidated: true}, comparison: ComparisonDivergent, wantAccept: true},
		{name: "secure NXDOMAIN", outcome: DNSOutcomeNXDomain, dnssec: DNSSECResult{Status: DNSSECSecure, LocallyValidated: true}, comparison: ComparisonMatchExpected, wantAccept: true},
		{name: "indeterminate answer", outcome: DNSOutcomeAnswer, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonMatchExpected},
		{name: "bogus SERVFAIL", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECBogus, LocallyValidated: true, ReasonCode: "SIGNATURE_EXPIRED"}, comparison: ComparisonMatchExpected},
		{name: "SERVFAIL", outcome: DNSOutcomeServFail, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonMatchExpected},
		{name: "REFUSED", outcome: DNSOutcomeRefused, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonDivergent},
		{name: "referral", outcome: DNSOutcomeReferral, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonMatchExpected},
		{name: "rcode error", outcome: DNSOutcomeRCodeError, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonDivergent},
		{name: "malformed", outcome: DNSOutcomeMalformed, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonMatchExpected},
		{name: "not observed", outcome: DNSOutcomeNotObserved, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonDivergent},
		{name: "truncated", outcome: DNSOutcomeTruncatedResponse, dnssec: DNSSECResult{Status: DNSSECIndeterminate}, comparison: ComparisonMatchExpected},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := observationWithOutcome(test.outcome)
			observation.DNSSEC = test.dnssec
			observation.Comparison = test.comparison
			_, err := NormalizeObservation(observation)
			if test.wantAccept && err != nil {
				t.Fatalf("NormalizeObservation: %v", err)
			}
			if !test.wantAccept && err == nil {
				t.Fatalf("non-comparable observation was accepted: %+v", observation)
			}
		})
	}
}

func TestObservationValidatesEDNSDNSSECAliasAndNegativeTTL(t *testing.T) {
	observation := observationWithCNAMEChain(1)
	observation.EDNS = EDNS{
		Present:  true,
		UDPSize:  1232,
		Flags:    0x8001,
		DNSSECOK: true,
		ECS:      &ClientSubnet{Address: "203.0.113.0", SourcePrefix: 24, ScopePrefix: 0},
		EDE:      []ExtendedDNSError{{Code: 15, Text: "Blocked"}},
		NSIDHex:  "A0ff",
		Options:  []EDNSOption{{Code: 65001, DataBase64: base64.StdEncoding.EncodeToString([]byte("opaque"))}},
	}
	observation.AliasChain = AliasChain{
		Hops:         []AliasHop{{Type: "cname", From: "EXAMPLE.COM", To: "ALIAS-1.example.com"}},
		TerminalName: "ALIAS-1.example.com",
	}
	got, err := NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}
	if got.EDNS.NSIDHex != "a0ff" || got.AliasChain.Hops[0].From != "example.com." || got.AliasChain.TerminalName != "alias-1.example.com." {
		t.Fatalf("normalized evidence = %+v, %+v", got.EDNS, got.AliasChain)
	}

	invalid := validObservation()
	invalid.NegativeTTL = uint32Pointer(60)
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("negative TTL on answer was accepted")
	}
	for _, status := range []DNSSECStatus{DNSSECSecure, DNSSECInsecure} {
		invalid = validObservation()
		invalid.DNSSEC = DNSSECResult{Status: status}
		if _, err := NormalizeObservation(invalid); err == nil {
			t.Errorf("%s status without local validation was accepted", status)
		}
		invalid.DNSSEC.LocallyValidated = true
		if _, err := NormalizeObservation(invalid); err != nil {
			t.Errorf("locally validated %s status: %v", status, err)
		}
	}
	invalid = observationWithOutcome(DNSOutcomeServFail)
	invalid.DNSSEC = DNSSECResult{Status: DNSSECBogus, LocallyValidated: true}
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("bogus status without a local reason code was accepted")
	}
	invalid = validObservation()
	invalid.DNSSEC = DNSSECResult{Status: DNSSECIndeterminate, LocallyValidated: true}
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("indeterminate status with completed local validation was accepted")
	}
	invalid = validObservation()
	invalid.EDNS = EDNS{DNSSECOK: true}
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("EDNS fields with present=false were accepted")
	}
	invalid = validObservation()
	invalid.EDNS = EDNS{Present: true, UDPSize: 1232, DNSSECOK: true}
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("EDNS DO convenience field without raw DO flag was accepted")
	}
	invalid.EDNS = EDNS{Present: true, UDPSize: 1232, Flags: 0x8000}
	if _, err := NormalizeObservation(invalid); err == nil {
		t.Fatal("raw EDNS DO flag without convenience field was accepted")
	}
}

func TestEDNSECSCanonicalizesAddressBySourcePrefix(t *testing.T) {
	for _, test := range []struct {
		name         string
		address      string
		sourcePrefix uint8
		scopePrefix  uint8
		want         string
	}{
		{name: "IPv4", address: "192.0.2.129", sourcePrefix: 24, scopePrefix: 17, want: "192.0.2.0"},
		{name: "IPv6", address: "2001:db8:abcd:1234::dead", sourcePrefix: 48, scopePrefix: 77, want: "2001:db8:abcd::"},
		{name: "IPv4 zero prefix", address: "203.0.113.9", sourcePrefix: 0, scopePrefix: 32, want: "0.0.0.0"},
		{name: "IPv6 zero prefix", address: "2001:db8::1", sourcePrefix: 0, scopePrefix: 128, want: "::"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			observation.EDNS = EDNS{
				Present: true,
				UDPSize: DefaultEDNSUDPSize,
				ECS: &ClientSubnet{
					Address: test.address, SourcePrefix: test.sourcePrefix, ScopePrefix: test.scopePrefix,
				},
			}
			normalized, err := NormalizeObservation(observation)
			if err != nil {
				t.Fatalf("NormalizeObservation: %v", err)
			}
			if normalized.EDNS.ECS.Address != test.want || normalized.EDNS.ECS.SourcePrefix != test.sourcePrefix || normalized.EDNS.ECS.ScopePrefix != test.scopePrefix {
				t.Fatalf("normalized ECS = %+v", normalized.EDNS.ECS)
			}
			again, err := NormalizeObservation(normalized)
			if err != nil {
				t.Fatalf("renormalize observation: %v", err)
			}
			if *again.EDNS.ECS != *normalized.EDNS.ECS {
				t.Fatalf("ECS normalization is not idempotent: %+v then %+v", normalized.EDNS.ECS, again.EDNS.ECS)
			}
		})
	}
}

func TestExtendedRCodeRequiresEDNS(t *testing.T) {
	observation := observationWithOutcome(DNSOutcomeRCodeError)
	observation.RCode = bytePointer(0)
	observation.ExtendedRCode = bytePointer(1)
	observation.EDNS = EDNS{Present: true, UDPSize: DefaultEDNSUDPSize}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("extended rcode with EDNS: %v", err)
	}
	observation.EDNS = EDNS{}
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("extended rcode without EDNS was accepted")
	}
}

func TestObservationPeerMustMatchPinnedConnectIP(t *testing.T) {
	observation := validObservation()
	observation.Endpoint = Endpoint{Kind: EndpointPublicAnycast, Protocol: ProtocolUDP, ConnectIP: "::ffff:8.8.8.8", Port: 53}
	observation.PeerIP = "::ffff:8.8.8.8"
	observation.Attempts[0].PeerIP = "::ffff:8.8.8.8"
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("mapped peer and endpoint: %v", err)
	}
	if normalized.Endpoint.ConnectIP != "8.8.8.8" || normalized.PeerIP != "8.8.8.8" {
		t.Fatalf("mapped addresses = %q/%q", normalized.Endpoint.ConnectIP, normalized.PeerIP)
	}
	observation.PeerIP = "1.1.1.1"
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("peer differing from pinned connect_ip was accepted")
	}
}

func TestAliasCrossZoneRequiresDelegationEvidence(t *testing.T) {
	observation := observationWithCNAMEChain(1)
	observation.AliasChain.CrossZone = true
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("cross_zone=true without known evidence was accepted")
	}
	observation.AliasChain.CrossZoneKnown = true
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("known cross-zone alias: %v", err)
	}
}

func TestAliasTruncationRequiresTopLevelTruncation(t *testing.T) {
	observation := observationWithCNAMEChain(MaxAliasChainDepth + 1)
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("truncated alias chain without top-level truncation was accepted")
	}
	observation.ResultTruncated = true
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("declared alias-chain truncation: %v", err)
	}
}

func TestAliasChainMustBeCompletelyDerivedFromAnswer(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Observation)
	}{
		{name: "first hop differs from question", mutate: func(value *Observation) {
			value.AliasChain.Hops[0].From = "other.example.com."
		}},
		{name: "discontinuous hop", mutate: func(value *Observation) {
			value.AliasChain.Hops[1].From = "other.example.com."
		}},
		{name: "wrong terminal", mutate: func(value *Observation) {
			value.AliasChain.TerminalName = "other.example.com."
		}},
		{name: "missing answer evidence", mutate: func(value *Observation) {
			value.Sections.Answer = nil
		}},
		{name: "partial chain", mutate: func(value *Observation) {
			value.AliasChain.Hops = value.AliasChain.Hops[:1]
			value.AliasChain.TerminalName = value.AliasChain.Hops[0].To
		}},
		{name: "display canonical conflict", mutate: func(value *Observation) {
			value.Sections.Answer[0].DisplayRData = "other.example.com."
		}},
		{name: "compressed canonical target", mutate: func(value *Observation) {
			value.Sections.Answer[0].DisplayRData = "www."
			value.Sections.Answer[0].CanonicalRData = `\# 7 C0020377777700`
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := observationWithCNAMEChain(2)
			test.mutate(&observation)
			if _, err := NormalizeObservation(observation); err == nil {
				t.Fatalf("unproven alias chain was accepted: %+v", observation.AliasChain)
			}
		})
	}
}

func TestAliasDerivationIsAnswerOrderIndependent(t *testing.T) {
	forward := observationWithCNAMEChain(3)
	reversed := observationWithCNAMEChain(3)
	for left, right := 0, len(reversed.Sections.Answer)-1; left < right; left, right = left+1, right-1 {
		reversed.Sections.Answer[left], reversed.Sections.Answer[right] = reversed.Sections.Answer[right], reversed.Sections.Answer[left]
	}
	forwardResult, err := NormalizeObservation(forward)
	if err != nil {
		t.Fatalf("normalize forward answer: %v", err)
	}
	reversedResult, err := NormalizeObservation(reversed)
	if err != nil {
		t.Fatalf("normalize reversed answer: %v", err)
	}
	if fmt.Sprint(forwardResult.AliasChain) != fmt.Sprint(reversedResult.AliasChain) {
		t.Fatalf("answer order changed alias chain: %+v vs %+v", forwardResult.AliasChain, reversedResult.AliasChain)
	}
}

func TestAliasChainDerivesDNAMEAndChecksSynthesizedCNAME(t *testing.T) {
	observation := validObservation()
	observation.Question.Name = "www.sub.example.com."
	observation.Sections.Answer = []ResourceRecord{
		aliasRecordForTest("example.com.", RRTypeDNAME, "elsewhere.net."),
		aliasRecordForTest("www.sub.example.com.", RRTypeCNAME, "www.sub.elsewhere.net."),
	}
	observation.AliasChain = AliasChain{
		Hops:         []AliasHop{{Type: RRTypeDNAME, From: "www.sub.example.com.", To: "www.sub.elsewhere.net."}},
		TerminalName: "www.sub.elsewhere.net.",
	}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("DNAME-derived alias chain: %v", err)
	}

	conflict := observation
	conflict.Sections.Answer = append([]ResourceRecord(nil), observation.Sections.Answer...)
	conflict.Sections.Answer[1] = aliasRecordForTest("www.sub.example.com.", RRTypeCNAME, "wrong.example.")
	if _, err := NormalizeObservation(conflict); err == nil {
		t.Fatal("DNAME with conflicting synthesized CNAME was accepted")
	}

	rootTarget := observation
	rootTarget.Sections.Answer = []ResourceRecord{aliasRecordForTest("example.com.", RRTypeDNAME, ".")}
	rootTarget.AliasChain = AliasChain{
		Hops:         []AliasHop{{Type: RRTypeDNAME, From: "www.sub.example.com.", To: "www.sub."}},
		TerminalName: "www.sub.",
	}
	if _, err := NormalizeObservation(rootTarget); err != nil {
		t.Fatalf("standards-valid root DNAME target: %v", err)
	}
}

func TestCroppedObservationMayOnlyOmitWholeAliasChain(t *testing.T) {
	observation := observationWithCNAMEChain(2)
	observation.ResultTruncated = true
	observation.AliasChain = AliasChain{}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("cropped observation with omitted alias chain: %v", err)
	}
	observation.AliasChain = observationWithCNAMEChain(2).AliasChain
	observation.AliasChain.Hops = observation.AliasChain.Hops[:1]
	observation.AliasChain.TerminalName = observation.AliasChain.Hops[0].To
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("cropped observation retained an unproven partial alias chain")
	}
}

func TestObservationEnforcesSectionAndEncodedSizeLimits(t *testing.T) {
	observation := validObservation()
	record := observation.Sections.Answer[0]
	observation.Sections.Answer = make([]ResourceRecord, MaxSectionRecordLimit+1)
	for i := range observation.Sections.Answer {
		observation.Sections.Answer[i] = record
	}
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("oversized DNS section was accepted")
	}

	observation = validObservation()
	record.DisplayRData = strings.Repeat("x", MaxRDataBytes)
	record.CanonicalRData = strings.Repeat("x", MaxRDataBytes)
	record.RRSetRecordCount = 2
	observation.Sections.Answer = []ResourceRecord{record, record}
	if _, err := NormalizeObservation(observation); err == nil {
		t.Fatal("oversized encoded observation was accepted")
	}
}

func TestObservationEnforcesRRSetRecordCountContract(t *testing.T) {
	secondA := ResourceRecord{
		Owner: "EXAMPLE.COM", Type: RRTypeA, Class: DNSClassIN, TTL: 60,
		DisplayRData: "192.0.2.2", CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 2,
	}
	tests := []struct {
		name      string
		mutate    func(*Observation)
		wantCode  string
		wantField string
	}{
		{
			name: "missing", wantCode: "MISSING_RRSET_RECORD_COUNT", wantField: "sections.answer[0].rrset_record_count",
			mutate: func(observation *Observation) { observation.Sections.Answer[0].RRSetRecordCount = 0 },
		},
		{
			name: "negative", wantCode: "INVALID_RRSET_RECORD_COUNT", wantField: "sections.answer[0].rrset_record_count",
			mutate: func(observation *Observation) { observation.Sections.Answer[0].RRSetRecordCount = -1 },
		},
		{
			name: "over limit", wantCode: "INVALID_RRSET_RECORD_COUNT", wantField: "sections.answer[0].rrset_record_count",
			mutate: func(observation *Observation) {
				observation.Sections.Answer[0].RRSetRecordCount = MaxSectionRecordLimit + 1
			},
		},
		{
			name: "inconsistent", wantCode: "INCONSISTENT_RRSET_RECORD_COUNT", wantField: "sections.answer[1].rrset_record_count",
			mutate: func(observation *Observation) {
				observation.Sections.Answer[0].RRSetRecordCount = 2
				inconsistent := secondA
				inconsistent.RRSetRecordCount = 1
				observation.Sections.Answer = append(observation.Sections.Answer, inconsistent)
			},
		},
		{
			name: "half group", wantCode: "RRSET_RECORD_COUNT_MISMATCH", wantField: "sections.answer[0].rrset_record_count",
			mutate: func(observation *Observation) { observation.Sections.Answer[0].RRSetRecordCount = 2 },
		},
		{
			name: "RRSIG is validated", wantCode: "RRSET_RECORD_COUNT_MISMATCH", wantField: "sections.authority[0].rrset_record_count",
			mutate: func(observation *Observation) {
				rrsig := rrsigRecordForTest()
				rrsig.RRSetRecordCount = 2
				observation.Sections.Authority = []ResourceRecord{rrsig}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			test.mutate(&observation)
			_, err := NormalizeObservation(observation)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) || validationErr.Code != test.wantCode || validationErr.Field != test.wantField {
				t.Fatalf("error = %#v, want code %s field %s", err, test.wantCode, test.wantField)
			}
		})
	}

	complete := validObservation()
	complete.Sections.Answer[0].RRSetRecordCount = 2
	complete.Sections.Answer = append(complete.Sections.Answer, secondA)
	complete.Sections.Authority = []ResourceRecord{rrsigRecordForTest()}
	additional := complete.Sections.Answer[0]
	additional.RRSetRecordCount = 1
	complete.Sections.Additional = []ResourceRecord{additional}
	normalized, err := NormalizeObservation(complete)
	if err != nil {
		t.Fatalf("normalize complete count evidence: %v", err)
	}
	if normalized.Sections.Answer[0].RRSetFingerprint == "" || normalized.Sections.Additional[0].RRSetFingerprint == "" ||
		normalized.Sections.Answer[0].RRSetFingerprint == normalized.Sections.Additional[0].RRSetFingerprint {
		t.Fatalf("section-isolated semantic fingerprints = answer %q additional %q", normalized.Sections.Answer[0].RRSetFingerprint, normalized.Sections.Additional[0].RRSetFingerprint)
	}
	if normalized.Sections.Authority[0].RRSetFingerprint != "" || normalized.Sections.Authority[0].RRSetRecordCount != 1 {
		t.Fatalf("RRSIG fingerprint/count = %+v", normalized.Sections.Authority[0])
	}
}

func validRequest() Request {
	return Request{
		Schema:  SchemaV1,
		RoundID: "01KROUND",
		Operations: []Operation{{
			OperationID: "01KOP",
			Mode:        ModeRecursive,
			Question:    Question{Name: "example.com", Type: RRTypeA, Class: DNSClassIN},
			Endpoint:    Endpoint{Kind: EndpointSystem, Protocol: ProtocolUDP, Port: 53},
			Flags:       QueryFlags{RecursionDesired: true, DNSSECOK: true, EDNSUDPSize: DefaultEDNSUDPSize},
		}},
		Limits: Limits{Parallel: 1, AttemptTimeoutMS: DefaultAttemptTimeoutMS, MaxAttempts: DefaultMaxAttempts},
	}
}

func requestWithTwoOperations() Request {
	request := validRequest()
	second := request.Operations[0]
	second.OperationID = "01KOP2"
	second.Question.Name = "www.example.com"
	request.Operations = append(request.Operations, second)
	return request
}

func observationForOperation(roundID string, operation Operation) Observation {
	observation := validObservation()
	observation.RoundID = roundID
	observation.OperationID = operation.OperationID
	observation.Question = operation.Question
	observation.Endpoint = operation.Endpoint
	observation.Protocol = operation.Endpoint.Protocol
	observation.Attempts[0].Protocol = operation.Endpoint.Protocol
	if operation.Endpoint.ConnectIP != "" {
		observation.PeerIP = operation.Endpoint.ConnectIP
		observation.Attempts[0].PeerIP = operation.Endpoint.ConnectIP
	}
	observation.Sections.Answer[0].Owner = operation.Question.Name
	return observation
}

func validObservation() Observation {
	startedAt := time.Date(2026, time.July, 19, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(12 * time.Millisecond)
	return Observation{
		Schema:          SchemaV1,
		RoundID:         "01KROUND",
		OperationID:     "01KOP",
		Question:        Question{Name: "example.com.", Type: RRTypeA, Class: DNSClassIN},
		Endpoint:        Endpoint{Kind: EndpointSystem, Protocol: ProtocolUDP, Port: 53},
		TransportStatus: TransportSuccess,
		AttemptCount:    1,
		Attempts: []WireAttempt{{
			Protocol: ProtocolUDP, TransportStatus: TransportSuccess,
			StartedAt: startedAt, FinishedAt: finishedAt, DurationMS: 12,
			PeerIP: "192.168.1.1", ResponseSizeBytes: 45,
		}},
		ResponseAttempt:   1,
		PeerIP:            "192.168.1.1",
		Protocol:          ProtocolUDP,
		StartedAt:         startedAt,
		ObservedAt:        finishedAt,
		FinishedAt:        finishedAt,
		DurationMS:        12,
		ResponseSizeBytes: 45,
		RCode:             bytePointer(0),
		Flags:             DNSFlags{Response: true, RecursionDesired: true, RecursionAvailable: true},
		Outcome:           DNSOutcomeAnswer,
		Sections: Sections{Answer: []ResourceRecord{{
			Owner:            "example.com.",
			Type:             RRTypeA,
			Class:            DNSClassIN,
			TTL:              300,
			DisplayRData:     "93.184.216.34",
			CanonicalRData:   `\# 4 5DB8D822`,
			RRSetRecordCount: 1,
		}}},
	}
}

func setSameProtocolRetrySuccess(observation *Observation) {
	firstFinished := observation.StartedAt.Add(4 * time.Millisecond)
	secondStarted := firstFinished.Add(time.Millisecond)
	observation.AttemptCount = 2
	observation.Attempts = []WireAttempt{
		{Protocol: observation.Endpoint.Protocol, TransportStatus: TransportTimeout, StartedAt: observation.StartedAt, FinishedAt: firstFinished, DurationMS: 4, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: observation.Endpoint.Protocol, TransportStatus: TransportSuccess, StartedAt: secondStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(secondStarted).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes, ResponseTruncated: observation.ResponseTruncated},
	}
	observation.ResponseAttempt = 2
	observation.ObservedAt = observation.FinishedAt
}

func setSuccessfulFallback(observation *Observation) {
	udpFinished := observation.StartedAt.Add(4 * time.Millisecond)
	tcpStarted := udpFinished.Add(time.Millisecond)
	observation.Protocol = ProtocolTCP
	observation.UDPToTCPFallback = true
	observation.AttemptCount = 2
	observation.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: observation.StartedAt, FinishedAt: udpFinished, DurationMS: 4, PeerIP: observation.PeerIP, ResponseSizeBytes: 28, ResponseTruncated: true},
		{Protocol: ProtocolTCP, TransportStatus: TransportSuccess, StartedAt: tcpStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(tcpStarted).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes, ResponseTruncated: observation.ResponseTruncated},
	}
	observation.ResponseAttempt = 2
	observation.ObservedAt = observation.FinishedAt
}

func setFailedFallback(observation *Observation, status TransportStatus, attemptError AttemptError) {
	udpFinished := observation.StartedAt.Add(4 * time.Millisecond)
	tcpStarted := udpFinished.Add(time.Millisecond)
	observation.TransportStatus = status
	observation.Protocol = ProtocolTCP
	observation.UDPToTCPFallback = true
	observation.AttemptCount = 2
	observation.Flags.Truncated = true
	observation.ResponseTruncated = true
	observation.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: observation.StartedAt, FinishedAt: udpFinished, DurationMS: 4, PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes, ResponseTruncated: true},
		{Protocol: ProtocolTCP, TransportStatus: status, StartedAt: tcpStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(tcpStarted).Milliseconds(), Error: &attemptError},
	}
	observation.ResponseAttempt = 1
	observation.ObservedAt = udpFinished
}

func unstartedCancellationObservation() Observation {
	observation := observationWithOutcome(DNSOutcomeNotObserved)
	observation.TransportStatus = TransportCancelled
	observation.AttemptCount = 0
	observation.Attempts = []WireAttempt{}
	observation.ResponseAttempt = 0
	observation.PeerIP = ""
	observation.ResponseSizeBytes = 0
	observation.DurationMS = 0
	observation.StartedAt = observation.ObservedAt
	observation.FinishedAt = observation.ObservedAt
	observation.Error = &ObservationError{Code: "CANCELLED", Message: "operation cancelled before execution"}
	return observation
}

func observationWithCNAMEChain(hopCount int) Observation {
	observation := validObservation()
	names := make([]string, hopCount+1)
	names[0] = observation.Question.Name
	for i := 1; i < len(names); i++ {
		names[i] = fmt.Sprintf("alias-%d.example.com.", i)
	}
	observation.Sections.Answer = make([]ResourceRecord, 0, hopCount)
	for i := 0; i < hopCount; i++ {
		observation.Sections.Answer = append(observation.Sections.Answer, aliasRecordForTest(names[i], RRTypeCNAME, names[i+1]))
	}
	chainLength := min(hopCount, MaxAliasChainDepth)
	observation.AliasChain.Hops = make([]AliasHop, 0, chainLength)
	for i := 0; i < chainLength; i++ {
		observation.AliasChain.Hops = append(observation.AliasChain.Hops, AliasHop{Type: RRTypeCNAME, From: names[i], To: names[i+1]})
	}
	if chainLength != 0 {
		observation.AliasChain.TerminalName = names[chainLength]
	}
	observation.AliasChain.Truncated = hopCount > chainLength
	return observation
}

func aliasRecordForTest(owner string, rrType RRType, target string) ResourceRecord {
	wire := make([]byte, 255)
	offset, err := dns.PackDomainName(target, wire, 0, nil, false)
	if err != nil {
		panic(err)
	}
	return ResourceRecord{
		Owner: owner, Type: rrType, Class: DNSClassIN, TTL: 60,
		DisplayRData: target, CanonicalRData: fmt.Sprintf(`\# %d %X`, offset, wire[:offset]), RRSetRecordCount: 1,
	}
}

func rrsigRecordForTest() ResourceRecord {
	record := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeA,
		Algorithm:   13,
		Labels:      2,
		OrigTtl:     60,
		Expiration:  2_000_000_000,
		Inception:   1_900_000_000,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "AQID",
	}
	canonical, comparable, err := CanonicalRDataForRR(record)
	if err != nil || !comparable {
		panic(fmt.Sprintf("canonicalize RRSIG test record: comparable=%t err=%v", comparable, err))
	}
	return ResourceRecord{
		Owner: record.Hdr.Name, Type: RRTypeRRSIG, Class: DNSClassIN, TTL: record.Hdr.Ttl,
		DisplayRData:   "A 13 2 60 20330518033320 20300317174640 12345 example.com. AQID",
		CanonicalRData: canonical, RRSetRecordCount: 1,
	}
}

func observationWithOutcome(outcome DNSOutcome) Observation {
	observation := validObservation()
	observation.Outcome = outcome
	observation.Comparison = ComparisonUnknown
	observation.DNSSEC = DNSSECResult{Status: DNSSECIndeterminate}
	observation.Sections = Sections{}
	switch outcome {
	case DNSOutcomeAnswer:
		observation.Sections = validObservation().Sections
	case DNSOutcomeNoData, DNSOutcomeReferral:
		observation.RCode = bytePointer(0)
	case DNSOutcomeNXDomain:
		observation.RCode = bytePointer(3)
	case DNSOutcomeServFail:
		observation.RCode = bytePointer(2)
	case DNSOutcomeRefused:
		observation.RCode = bytePointer(5)
	case DNSOutcomeRCodeError:
		observation.RCode = bytePointer(4)
	case DNSOutcomeMalformed:
		observation.RCode = nil
		observation.Flags = DNSFlags{}
		observation.Error = &ObservationError{Code: "MALFORMED_DNS", Message: "response could not be parsed"}
	case DNSOutcomeNotObserved:
		observation.TransportStatus = TransportTimeout
		observation.PeerIP = ""
		observation.ResponseSizeBytes = 0
		observation.ResponseAttempt = 0
		observation.Attempts = []WireAttempt{{
			Protocol: ProtocolUDP, TransportStatus: TransportTimeout,
			StartedAt: observation.StartedAt, FinishedAt: observation.FinishedAt, DurationMS: observation.DurationMS,
			Error: &AttemptError{Code: "TIMEOUT", Retryable: true},
		}}
		observation.RCode = nil
		observation.Flags = DNSFlags{}
		observation.Error = &ObservationError{Code: "TIMEOUT", Message: "attempt timed out", Retryable: true}
	case DNSOutcomeTruncatedResponse:
		observation.Endpoint.Protocol = ProtocolUDP
		observation.Protocol = ProtocolTCP
		observation.AttemptCount = 2
		middle := observation.StartedAt.Add(5 * time.Millisecond)
		observation.Attempts = []WireAttempt{
			{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: observation.StartedAt, FinishedAt: middle, DurationMS: 5, PeerIP: observation.PeerIP, ResponseSizeBytes: 28, ResponseTruncated: true},
			{Protocol: ProtocolTCP, TransportStatus: TransportSuccess, StartedAt: middle, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(middle).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: 40, ResponseTruncated: true},
		}
		observation.ResponseAttempt = 2
		observation.UDPToTCPFallback = true
		observation.RCode = bytePointer(0)
		observation.Flags.Truncated = true
		observation.ResponseTruncated = true
		observation.ResponseSizeBytes = 40
		observation.Error = &ObservationError{Code: "MALFORMED_DNS", Message: "TCP fallback response was malformed"}
	}
	return observation
}

func bytePointer(value uint8) *uint8 {
	return &value
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}
