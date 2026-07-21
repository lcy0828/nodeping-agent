package dnsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

type authoritativeFixtureKey struct {
	owner  string
	rrType uint16
	class  uint16
}

type authoritativeFixtureZone struct {
	records map[authoritativeFixtureKey][]dns.RR
	ordered []dns.RR
}

func TestAuthoritativeFixtureCoversEverySupportedQueryType(t *testing.T) {
	zone := loadAuthoritativeFixtureZone(t)
	queryNames := map[dnsobs.RRType]string{
		dnsobs.RRTypeA:      "a.types.test.",
		dnsobs.RRTypeAAAA:   "aaaa.types.test.",
		dnsobs.RRTypeCNAME:  "alias.types.test.",
		dnsobs.RRTypeMX:     "types.test.",
		dnsobs.RRTypeTXT:    "text.types.test.",
		dnsobs.RRTypeNS:     "types.test.",
		dnsobs.RRTypeSOA:    "types.test.",
		dnsobs.RRTypeCAA:    "types.test.",
		dnsobs.RRTypeSRV:    "_sip._tcp.types.test.",
		dnsobs.RRTypePTR:    "10.2.0.192.in-addr.arpa.",
		dnsobs.RRTypeDS:     "child.types.test.",
		dnsobs.RRTypeDNSKEY: "types.test.",
		dnsobs.RRTypeTLSA:   "_443._tcp.tlsa.types.test.",
		dnsobs.RRTypeSVCB:   "service.types.test.",
		dnsobs.RRTypeHTTPS:  "service.types.test.",
	}
	supported := dnsobs.SupportedQueryTypes()
	if len(queryNames) != len(supported) {
		t.Fatalf("authoritative fixture has %d query mappings, contract has %d supported query types", len(queryNames), len(supported))
	}

	for _, rrType := range supported {
		rrType := rrType
		name, ok := queryNames[rrType]
		if !ok {
			t.Fatalf("authoritative fixture has no query name for supported type %s", rrType)
		}
		wireType, ok := dns.StringToType[string(rrType)]
		if !ok {
			t.Fatalf("miekg/dns has no wire type for supported type %s", rrType)
		}
		t.Run(string(rrType), func(t *testing.T) {
			answer := zone.mustRecords(t, name, wireType, dns.ClassINET)
			observation := observeAuthoritativeFixture(t, name, wireType, dns.RcodeSuccess, answer, nil, nil)
			if observation.Outcome != dnsobs.DNSOutcomeAnswer || observation.ResponseTruncated || observation.ResultTruncated {
				t.Fatalf("%s authoritative outcome = %+v", rrType, observation)
			}
			if len(observation.Sections.Answer) != len(answer) || len(observation.Sections.Authority) != 0 || len(observation.Sections.Additional) != 0 {
				t.Fatalf("%s sections = %+v", rrType, observation.Sections)
			}
			wantOwner, err := dnsobs.NormalizeOwnerName(name)
			if err != nil {
				t.Fatalf("normalize fixture owner %q: %v", name, err)
			}
			fingerprint := ""
			for index, record := range observation.Sections.Answer {
				if record.Owner != wantOwner || record.Type != rrType || record.Class != dnsobs.DNSClassIN || record.RRSetFingerprint == "" {
					t.Fatalf("%s answer[%d] = %+v", rrType, index, record)
				}
				if fingerprint == "" {
					fingerprint = record.RRSetFingerprint
				} else if record.RRSetFingerprint != fingerprint {
					t.Fatalf("%s RRset has inconsistent fingerprints %q and %q", rrType, fingerprint, record.RRSetFingerprint)
				}
			}
			assertObservationSemanticBounds(t, observation)
		})
	}
}

func TestAuthoritativeFixtureCoversResponseOnlyTypes(t *testing.T) {
	zone := loadAuthoritativeFixtureZone(t)
	soa := zone.mustRecords(t, "types.test.", dns.TypeSOA, dns.ClassINET)
	tests := []struct {
		name        string
		queryName   string
		queryType   uint16
		rcode       int
		answer      []dns.RR
		authority   []dns.RR
		wantType    dnsobs.RRType
		wantOwner   string
		wantOutcome dnsobs.DNSOutcome
		section     string
	}{
		{
			name: "DNAME", queryName: "host.branch.types.test.", queryType: dns.TypeA,
			answer:   zone.mustRecords(t, "branch.types.test.", dns.TypeDNAME, dns.ClassINET),
			wantType: dnsobs.RRTypeDNAME, wantOwner: "branch.types.test.", wantOutcome: dnsobs.DNSOutcomeAnswer, section: "answer",
		},
		{
			name: "RRSIG", queryName: "signed.types.test.", queryType: dns.TypeA,
			answer:   append(zone.mustRecords(t, "signed.types.test.", dns.TypeA, dns.ClassINET), zone.mustRecords(t, "signed.types.test.", dns.TypeRRSIG, dns.ClassINET)...),
			wantType: dnsobs.RRTypeRRSIG, wantOwner: "signed.types.test.", wantOutcome: dnsobs.DNSOutcomeAnswer, section: "answer",
		},
		{
			name: "NSEC", queryName: "nodata.types.test.", queryType: dns.TypeAAAA,
			authority: append(append([]dns.RR(nil), soa...), zone.mustRecords(t, "nodata.types.test.", dns.TypeNSEC, dns.ClassINET)...),
			wantType:  dnsobs.RRTypeNSEC, wantOwner: "nodata.types.test.", wantOutcome: dnsobs.DNSOutcomeNoData, section: "authority",
		},
		{
			name: "NSEC3", queryName: "missing.types.test.", queryType: dns.TypeA, rcode: dns.RcodeNameError,
			authority: append(append([]dns.RR(nil), soa...), zone.mustRecords(t, "hash.types.test.", dns.TypeNSEC3, dns.ClassINET)...),
			wantType:  dnsobs.RRTypeNSEC3, wantOwner: "hash.types.test.", wantOutcome: dnsobs.DNSOutcomeNXDomain, section: "authority",
		},
		{
			name: "NSEC3PARAM", queryName: "types.test.", queryType: dns.TypeDNSKEY,
			answer:   append(zone.mustRecords(t, "types.test.", dns.TypeDNSKEY, dns.ClassINET), zone.mustRecords(t, "types.test.", dns.TypeNSEC3PARAM, dns.ClassINET)...),
			wantType: dnsobs.RRTypeNSEC3PARAM, wantOwner: "types.test.", wantOutcome: dnsobs.DNSOutcomeAnswer, section: "answer",
		},
	}
	if len(tests) != 5 {
		t.Fatalf("response-only fixture count = %d, want 5", len(tests))
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			observation := observeAuthoritativeFixture(t, test.queryName, test.queryType, test.rcode, test.answer, test.authority, nil)
			if observation.Outcome != test.wantOutcome || observation.ResponseTruncated || observation.ResultTruncated {
				t.Fatalf("%s authoritative outcome = %+v", test.name, observation)
			}
			records := observation.Sections.Answer
			if test.section == "authority" {
				records = observation.Sections.Authority
			}
			found := false
			for _, record := range records {
				if record.Type != test.wantType {
					continue
				}
				found = true
				if record.Owner != test.wantOwner || record.Class != dnsobs.DNSClassIN {
					t.Fatalf("%s normalized record = %+v", test.name, record)
				}
				if test.wantType == dnsobs.RRTypeRRSIG {
					if record.RRSetFingerprint != "" {
						t.Fatalf("RRSIG unexpectedly has fingerprint %q", record.RRSetFingerprint)
					}
				} else if record.RRSetFingerprint == "" {
					t.Fatalf("%s response-only record has no fingerprint: %+v", test.name, record)
				}
			}
			if !found {
				t.Fatalf("%s response-only type not found in %s: %+v", test.name, test.section, records)
			}
			assertObservationSemanticBounds(t, observation)
		})
	}
}

func observeAuthoritativeFixture(t *testing.T, name string, qtype uint16, rcode int, answer, authority, additional []dns.RR) dnsobs.Observation {
	t.Helper()
	endpoint, serverErr := startUDPResolver(t, func(query *dns.Msg) (*dns.Msg, error) {
		if len(query.Question) != 1 || !strings.EqualFold(dns.Fqdn(query.Question[0].Name), dns.Fqdn(name)) || query.Question[0].Qtype != qtype {
			return nil, fmt.Errorf("fixture query = %+v, want %s/%s", query.Question, name, dns.TypeToString[qtype])
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Authoritative = true
		response.Rcode = rcode
		response.Answer = copyFixtureRecords(answer)
		response.Ns = copyFixtureRecords(authority)
		response.Extra = copyFixtureRecords(additional)
		return response, nil
	})
	result, err := newTestEngine(t, nil).Observe(context.Background(), endpoint, Query{
		Name: name, Type: qtype, Class: dns.ClassINET, Mode: QueryModeAuthoritative,
	})
	if err != nil {
		t.Fatalf("observe authoritative fixture %s/%s: %v", name, dns.TypeToString[qtype], err)
	}
	if err := receiveServerError(serverErr); err != nil {
		t.Fatalf("authoritative fixture resolver %s/%s: %v", name, dns.TypeToString[qtype], err)
	}
	rrType, err := dnsobs.ParseRRType(typeName(qtype))
	if err != nil {
		t.Fatalf("normalize fixture query type %d: %v", qtype, err)
	}
	observation, err := ToObservation(result, nil, ObservationEnvelope{
		RoundID: "round-authoritative-fixture", OperationID: "operation-" + strings.ToLower(string(rrType)),
		Question:   dnsobs.Question{Name: name, Type: rrType, Class: dnsobs.DNSClassIN},
		Endpoint:   dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
		Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
	})
	if err != nil {
		t.Fatalf("convert authoritative fixture %s/%s: %v", name, rrType, err)
	}
	return observation
}

func loadAuthoritativeFixtureZone(t testing.TB) authoritativeFixtureZone {
	t.Helper()
	path := filepath.Join("testdata", "authoritative-types.zone")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open authoritative fixture zone: %v", err)
	}
	defer file.Close()

	zone := authoritativeFixtureZone{records: make(map[authoritativeFixtureKey][]dns.RR)}
	parser := dns.NewZoneParser(file, ".", path)
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		header := record.Header()
		key := authoritativeFixtureKey{owner: strings.ToLower(dns.Fqdn(header.Name)), rrType: header.Rrtype, class: header.Class}
		zone.records[key] = append(zone.records[key], record)
		zone.ordered = append(zone.ordered, record)
	}
	if err := parser.Err(); err != nil {
		t.Fatalf("parse authoritative fixture zone: %v", err)
	}
	return zone
}

func (z authoritativeFixtureZone) mustRecords(t testing.TB, owner string, rrType uint16, class uint16) []dns.RR {
	t.Helper()
	key := authoritativeFixtureKey{owner: strings.ToLower(dns.Fqdn(owner)), rrType: rrType, class: class}
	records := z.records[key]
	if len(records) == 0 {
		t.Fatalf("authoritative fixture has no %s/%s/%s records", key.owner, dns.TypeToString[rrType], dns.ClassToString[class])
	}
	return copyFixtureRecords(records)
}

func copyFixtureRecords(records []dns.RR) []dns.RR {
	result := make([]dns.RR, len(records))
	for index, record := range records {
		result[index] = dns.Copy(record)
	}
	return result
}

func assertObservationSemanticBounds(t testing.TB, observation dnsobs.Observation) {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	if len(raw) > dnsobs.MaxObservationBytes {
		t.Fatalf("observation is %d bytes, limit %d", len(raw), dnsobs.MaxObservationBytes)
	}
	normalized, err := dnsobs.NormalizeObservation(observation)
	if err != nil {
		t.Fatalf("renormalize observation: %v", err)
	}
	if !reflect.DeepEqual(observation, normalized) {
		t.Fatal("normalized observation is not idempotent")
	}
}
