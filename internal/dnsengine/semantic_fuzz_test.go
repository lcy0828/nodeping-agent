package dnsengine

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

func TestSemanticFingerprintStableAcrossOrderTTLAndOwnerVariants(t *testing.T) {
	first := semanticRRSetRecords([]ResourceRecord{
		semanticTXTRecord(t, "SET.Types.Test", 30, "alpha"),
		semanticTXTRecord(t, "set.types.test.", 60, "beta"),
		semanticTXTRecord(t, "sEt.TyPeS.tEsT.", 90, "alpha"),
	})
	second := semanticRRSetRecords([]ResourceRecord{
		semanticTXTRecord(t, "set.types.test", 900, "beta"),
		semanticTXTRecord(t, "SET.TYPES.TEST.", 1, "alpha"),
	})

	firstObservation := semanticObservationForRecords(t, "operation-fingerprint-first", first)
	secondObservation := semanticObservationForRecords(t, "operation-fingerprint-second", second)
	firstFingerprint := semanticRRSetFingerprint(t, firstObservation.Sections.Additional, dnsobs.RRTypeTXT)
	secondFingerprint := semanticRRSetFingerprint(t, secondObservation.Sections.Additional, dnsobs.RRTypeTXT)
	if firstFingerprint != secondFingerprint {
		t.Fatalf("order, TTL, duplicate, or owner variant changed fingerprint: %q != %q", firstFingerprint, secondFingerprint)
	}
	want, err := dnsobs.FingerprintRRSet("set.types.test.", dnsobs.RRTypeTXT, dnsobs.DNSClassIN, []string{
		semanticCanonicalRData(t, dnsobs.RRTypeTXT, "alpha"),
		semanticCanonicalRData(t, dnsobs.RRTypeTXT, "beta"),
	})
	if err != nil {
		t.Fatalf("compute expected semantic fingerprint: %v", err)
	}
	if firstFingerprint != want {
		t.Fatalf("semantic fingerprint = %q, want %q", firstFingerprint, want)
	}
}

func FuzzSemanticObservationRRSetInvariants(f *testing.F) {
	formalTypes := semanticFormalResponseTypes()
	for index, rrType := range formalTypes {
		f.Add(2, 2048, uint8(index), string(rrType))
	}
	for _, seed := range []struct {
		records int
		bytes   int
	}{
		{records: 127, bytes: 65535},
		{records: 128, bytes: 65536},
		{records: 129, bytes: 65537},
	} {
		f.Add(seed.records, seed.bytes, uint8(seed.records), string(dnsobs.RRTypeTXT))
	}

	f.Fuzz(func(t *testing.T, rawCount int, rawBytes int, variant uint8, rrTypeText string) {
		if len(rrTypeText) > 32 {
			return
		}
		rrType, err := dnsobs.ParseResponseRRType(rrTypeText)
		if err != nil || !semanticFormalResponseType(rrType) {
			return
		}
		count := 1 + int(uint(rawCount)%uint(dnsobs.MaxSectionRecordLimit+2))
		targetBytes := 1 + int(uint(rawBytes)%uint(dnsobs.MaxObservationBytes*2))
		perValue := max(1, targetBytes/(count*2))
		perValue = min(perValue, dnsobs.MaxRDataBytes)
		if rrType == dnsobs.RRTypeTXT {
			perValue = min(perValue, semanticComparableTXTValueLimit)
		}

		records := make([]ResourceRecord, 0, count)
		canonicalValues := make([]string, 0, count)
		for index := 0; index < count; index++ {
			value := semanticFuzzRData(index, perValue)
			display, canonical := semanticRecordData(t, rrType, value)
			canonicalValues = append(canonicalValues, canonical)
			records = append(records, ResourceRecord{
				Owner:            semanticOwnerVariant(index, variant),
				Type:             semanticTypeVariant(rrType, index),
				Class:            semanticClassVariant(index),
				TTL:              uint32(index*17 + int(variant)),
				DisplayRData:     display,
				CanonicalRData:   canonical,
				RRSetRecordCount: count,
			})
		}

		observation := semanticObservationForRecords(t, "operation-rrset-fuzz", records)
		assertObservationSemanticBounds(t, observation)
		retained := make([]dnsobs.ResourceRecord, 0, count)
		for _, record := range observation.Sections.Additional {
			if record.Owner == "set.types.test." && record.Type == rrType && record.Class == dnsobs.DNSClassIN {
				retained = append(retained, record)
			}
		}
		if len(retained) != 0 && len(retained) != count {
			t.Fatalf("normalized RRset %s retained %d of %d records", rrType, len(retained), count)
		}
		if len(retained) == 0 {
			if !observation.ResultTruncated {
				t.Fatalf("dropped RRset %s did not set result_truncated", rrType)
			}
			return
		}
		if observation.ResponseTruncated || observation.ResultTruncated {
			t.Fatalf("complete RRset %s has truncation markers: %+v", rrType, observation)
		}
		if rrType == dnsobs.RRTypeRRSIG {
			for _, record := range retained {
				if record.RRSetFingerprint != "" {
					t.Fatalf("RRSIG retained fingerprint %q", record.RRSetFingerprint)
				}
			}
			return
		}
		wantFingerprint, err := dnsobs.FingerprintRRSet("set.types.test.", rrType, dnsobs.DNSClassIN, canonicalValues)
		if err != nil {
			t.Fatalf("fingerprint source RRset %s: %v", rrType, err)
		}
		for _, record := range retained {
			if record.RRSetFingerprint != wantFingerprint {
				t.Fatalf("RRset %s fingerprint = %q, want %q", rrType, record.RRSetFingerprint, wantFingerprint)
			}
		}
	})
}

var semanticComparableTXTValueLimit = func() int {
	for valueBytes := dnsobs.MaxRDataBytes; valueBytes > 0; valueBytes-- {
		chunkCount := (valueBytes + 254) / 255
		wireBytes := valueBytes + chunkCount
		canonicalBytes := len(`\# `) + len(strconv.Itoa(wireBytes)) + 1 + 2*wireBytes
		displayBytes := valueBytes + 2*chunkCount + (chunkCount - 1)
		if canonicalBytes <= dnsobs.MaxRDataBytes && displayBytes <= dnsobs.MaxRDataBytes {
			return valueBytes
		}
	}
	return 1
}()

func FuzzSuccessfulFallbackRequiresFinalTCPProvenance(f *testing.F) {
	f.Add(uint8(0), false, true, true, true, true)
	f.Add(uint8(1), false, true, true, true, true)
	f.Add(uint8(2), false, true, true, true, true)
	f.Add(uint8(0), true, true, true, true, true)
	f.Add(uint8(1), false, false, true, true, true)
	f.Add(uint8(2), false, true, false, true, true)
	f.Add(uint8(0), false, true, true, false, true)
	f.Add(uint8(0), false, true, true, true, false)
	f.Add(uint8(1), false, true, true, true, false)

	f.Fuzz(func(t *testing.T, rawMode uint8, finalError bool, peerMatches bool, sizeMatches bool, tcMatches bool, timingMatches bool) {
		started := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
		final := Attempt{
			Protocol: ProtocolTCP, StartedAt: started.Add(6 * time.Millisecond), Duration: 2 * time.Millisecond,
			PeerIP: "8.8.8.8", ResponseSize: 100,
		}
		if finalError {
			final.Error = "context deadline exceeded"
		}
		if !peerMatches {
			final.PeerIP = "1.1.1.1"
		}
		if !sizeMatches {
			final.ResponseSize = 99
		}
		if !tcMatches {
			final.Truncated = true
		}
		if !timingMatches {
			if rawMode%2 == 0 {
				final.StartedAt = started.Add(-time.Millisecond)
			} else {
				final.StartedAt = started.Add(9 * time.Millisecond)
			}
		}

		var attempts []Attempt
		switch rawMode % 3 {
		case 0:
			attempts = []Attempt{{Protocol: ProtocolUDP, StartedAt: started, Duration: time.Millisecond, PeerIP: "8.8.8.8", ResponseSize: 60, Truncated: true}, final}
		case 1:
			attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started, Duration: time.Millisecond, PeerIP: "8.8.8.8", Error: "context deadline exceeded"},
				{Protocol: ProtocolUDP, StartedAt: started.Add(3 * time.Millisecond), Duration: time.Millisecond, PeerIP: "8.8.8.8", ResponseSize: 60, Truncated: true},
				final,
			}
		case 2:
			attempts = []Attempt{
				{Protocol: ProtocolUDP, StartedAt: started, Duration: time.Millisecond, PeerIP: "8.8.8.8", ResponseSize: 60, Truncated: true},
				{Protocol: ProtocolTCP, StartedAt: started.Add(3 * time.Millisecond), Duration: time.Millisecond, PeerIP: "8.8.8.8", Error: "context deadline exceeded"},
				final,
			}
		}
		result := &Result{
			Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			Protocol: ProtocolUDP, PeerIP: "8.8.8.8", StartedAt: started, Duration: 10 * time.Millisecond,
			Attempts: attempts, UDPToTCPFallback: true,
			RCode: 0, Flags: Flags{Response: true}, Outcome: OutcomeAnswer,
			Sections: Sections{Answer: []ResourceRecord{{
				Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
				DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
			}}},
			ResponseSize: 100, ResponseParsed: true,
		}
		observation, err := ToObservation(result, nil, ObservationEnvelope{
			RoundID: "round-fallback-fuzz", OperationID: "operation-fallback-fuzz",
			Question:   dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
			Endpoint:   dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
			Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		})
		valid := !finalError && peerMatches && sizeMatches && tcMatches && timingMatches
		if !valid {
			if err == nil {
				t.Fatalf("successful fallback accepted invalid final TCP provenance: %+v", observation)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid successful fallback rejected: %v", err)
		}
		if observation.Protocol != dnsobs.ProtocolTCP || !observation.UDPToTCPFallback || observation.ResponseSizeBytes != 100 || !observation.ObservedAt.Equal(final.StartedAt.Add(final.Duration)) {
			t.Fatalf("successful fallback did not use final TCP evidence: %+v", observation)
		}
		assertObservationSemanticBounds(t, observation)
	})
}

func FuzzAuthoritativeWireSemanticInvariants(f *testing.F) {
	zone := loadAuthoritativeFixtureZone(f)
	baseQuestion := dns.Question{Name: "wire-seed.types.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for _, rrType := range semanticFormalResponseTypes() {
		wireType := dns.StringToType[string(rrType)]
		record := zone.firstRecordOfType(f, wireType)
		response := semanticWireSeedResponse(baseQuestion, false)
		response.Extra = []dns.RR{record}
		wire, err := response.Pack()
		if err != nil {
			f.Fatalf("pack %s wire fuzz seed: %v", rrType, err)
		}
		f.Add(wire)
	}
	tc := semanticWireSeedResponse(baseQuestion, true)
	tcWire, err := tc.Pack()
	if err != nil {
		f.Fatalf("pack TC wire fuzz seed: %v", err)
	}
	f.Add(tcWire)
	f.Add([]byte{0, 1, 2, 3})
	f.Add(append(append([]byte(nil), tcWire...), 0xa5))

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65535 {
			return
		}
		message, err := unpackResponse(wire)
		if err != nil || len(message.Question) != 1 {
			return
		}
		question := message.Question[0]
		if question.Qclass != dns.ClassINET {
			return
		}
		rrType, err := dnsobs.ParseRRType(typeName(question.Qtype))
		if err != nil {
			return
		}
		query := new(dns.Msg)
		query.Id = message.Id
		query.Opcode = message.Opcode
		query.Question = []dns.Question{question}
		if err := validateResponse(query, message); err != nil {
			return
		}

		started := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
		result := &Result{
			Question: question, Protocol: ProtocolTCP, PeerIP: "192.0.2.53", StartedAt: started, Duration: time.Millisecond,
			Attempts:     []Attempt{{Protocol: ProtocolTCP, PeerIP: "192.0.2.53", StartedAt: started, Duration: time.Millisecond, ResponseSize: len(wire), Truncated: message.Truncated}},
			ResponseSize: len(wire),
		}
		engine := &Engine{maxRecordsPerSection: dnsobs.MaxSectionRecordLimit}
		if err := engine.populateResult(result, message); err != nil {
			return
		}
		observation, err := ToObservation(result, nil, ObservationEnvelope{
			RoundID: "round-wire-fuzz", OperationID: "operation-wire-fuzz",
			Question:   dnsobs.Question{Name: question.Name, Type: rrType, Class: dnsobs.DNSClassIN},
			Endpoint:   dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolTCP, Port: 53},
			Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		})
		if err != nil {
			return
		}
		assertObservationSemanticBounds(t, observation)
		assertWireRRSetAtomicity(t, message, observation)
	})
}

func semanticObservationForRecords(t testing.TB, operationID string, records []ResourceRecord) dnsobs.Observation {
	t.Helper()
	started := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	result := &Result{
		Question: dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Protocol: ProtocolTCP, PeerIP: "192.0.2.53", StartedAt: started, Duration: time.Millisecond,
		Attempts: []Attempt{{Protocol: ProtocolTCP, PeerIP: "192.0.2.53", StartedAt: started, Duration: time.Millisecond, ResponseSize: 512}},
		RCode:    0, Flags: Flags{Response: true}, Outcome: OutcomeAnswer,
		Sections: Sections{
			Answer: []ResourceRecord{{
				Owner: "example.com.", Type: "A", Class: "IN", TTL: 60,
				DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1,
			}},
			Additional: append([]ResourceRecord(nil), records...),
		},
		ResponseSize: 512, ResponseParsed: true,
	}
	observation, err := ToObservation(result, nil, ObservationEnvelope{
		RoundID: "round-semantic-fixture", OperationID: operationID,
		Question:   dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:   dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolTCP, Port: 53},
		Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
	})
	if err != nil {
		t.Fatalf("convert semantic observation: %v", err)
	}
	return observation
}

func semanticTXTRecord(t testing.TB, owner string, ttl uint32, value string) ResourceRecord {
	t.Helper()
	display, canonical := semanticRecordData(t, dnsobs.RRTypeTXT, value)
	return ResourceRecord{
		Owner: owner, Type: "TXT", Class: "IN", TTL: ttl,
		DisplayRData: display, CanonicalRData: canonical,
	}
}

func semanticRRSetRecords(records []ResourceRecord) []ResourceRecord {
	for index := range records {
		records[index].RRSetRecordCount = len(records)
	}
	return records
}

func semanticRRSetFingerprint(t testing.TB, records []dnsobs.ResourceRecord, rrType dnsobs.RRType) string {
	t.Helper()
	fingerprint := ""
	for _, record := range records {
		if record.Type != rrType {
			continue
		}
		if fingerprint == "" {
			fingerprint = record.RRSetFingerprint
		} else if fingerprint != record.RRSetFingerprint {
			t.Fatalf("RRset %s has inconsistent fingerprints %q and %q", rrType, fingerprint, record.RRSetFingerprint)
		}
	}
	if fingerprint == "" {
		t.Fatalf("RRset %s has no fingerprint", rrType)
	}
	return fingerprint
}

func semanticFormalResponseTypes() []dnsobs.RRType {
	result := dnsobs.SupportedQueryTypes()
	return append(result,
		dnsobs.RRTypeDNAME,
		dnsobs.RRTypeRRSIG,
		dnsobs.RRTypeNSEC,
		dnsobs.RRTypeNSEC3,
		dnsobs.RRTypeNSEC3PARAM,
	)
}

func semanticFormalResponseType(rrType dnsobs.RRType) bool {
	for _, formal := range semanticFormalResponseTypes() {
		if rrType == formal {
			return true
		}
	}
	return false
}

func semanticCanonicalRData(t testing.TB, rrType dnsobs.RRType, txtValue string) string {
	t.Helper()
	_, canonical := semanticRecordData(t, rrType, txtValue)
	return canonical
}

func semanticRecordData(t testing.TB, rrType dnsobs.RRType, txtValue string) (string, string) {
	t.Helper()
	var record dns.RR
	if rrType == dnsobs.RRTypeTXT {
		chunks := make([]string, 0, len(txtValue)/255+1)
		for len(txtValue) > 255 {
			chunks = append(chunks, txtValue[:255])
			txtValue = txtValue[255:]
		}
		chunks = append(chunks, txtValue)
		record = &dns.TXT{
			Hdr: dns.RR_Header{Name: "set.types.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: chunks,
		}
	} else {
		fixtures := map[dnsobs.RRType]string{
			dnsobs.RRTypeA:          "set.types.test. 60 IN A 192.0.2.1",
			dnsobs.RRTypeAAAA:       "set.types.test. 60 IN AAAA 2001:db8::1",
			dnsobs.RRTypeCNAME:      "set.types.test. 60 IN CNAME target.types.test.",
			dnsobs.RRTypeMX:         "set.types.test. 60 IN MX 10 mail.types.test.",
			dnsobs.RRTypeNS:         "set.types.test. 60 IN NS ns.types.test.",
			dnsobs.RRTypeSOA:        "set.types.test. 60 IN SOA ns.types.test. hostmaster.types.test. 1 3600 600 86400 300",
			dnsobs.RRTypeCAA:        `set.types.test. 60 IN CAA 0 issue "ca.example"`,
			dnsobs.RRTypeSRV:        "set.types.test. 60 IN SRV 10 20 5060 sip.types.test.",
			dnsobs.RRTypePTR:        "set.types.test. 60 IN PTR ptr.types.test.",
			dnsobs.RRTypeDS:         "set.types.test. 60 IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			dnsobs.RRTypeDNSKEY:     "set.types.test. 60 IN DNSKEY 257 3 13 AQID",
			dnsobs.RRTypeTLSA:       "set.types.test. 60 IN TLSA 3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			dnsobs.RRTypeSVCB:       `set.types.test. 60 IN SVCB 1 target.types.test. alpn="h2,h3" port=8443 ipv4hint=192.0.2.80`,
			dnsobs.RRTypeHTTPS:      `set.types.test. 60 IN HTTPS 1 target.types.test. alpn="h2,h3" port=8443 ipv4hint=192.0.2.80`,
			dnsobs.RRTypeDNAME:      "set.types.test. 60 IN DNAME destination.test.",
			dnsobs.RRTypeRRSIG:      "set.types.test. 60 IN RRSIG A 13 3 300 20300101000000 20250101000000 12345 types.test. AQID",
			dnsobs.RRTypeNSEC:       "set.types.test. 60 IN NSEC next.types.test. A RRSIG NSEC",
			dnsobs.RRTypeNSEC3:      "set.types.test. 60 IN NSEC3 1 0 5 A1B2 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A AAAA RRSIG",
			dnsobs.RRTypeNSEC3PARAM: "set.types.test. 60 IN NSEC3PARAM 1 0 5 A1B2",
		}
		text, ok := fixtures[rrType]
		if !ok {
			t.Fatalf("no semantic RDATA fixture for %s", rrType)
		}
		var err error
		record, err = dns.NewRR(text)
		if err != nil {
			t.Fatalf("parse semantic %s fixture: %v", rrType, err)
		}
	}
	display, canonical, comparable, err := dnsobs.CanonicalRecordDataForRR(record)
	if err != nil || !comparable {
		t.Fatalf("canonicalize semantic %s fixture: comparable=%t err=%v", rrType, comparable, err)
	}
	return display, canonical
}

func semanticFuzzRData(index, size int) string {
	prefix := fmt.Sprintf("%03d:", index)
	if size <= len(prefix) {
		return prefix
	}
	return prefix + strings.Repeat(string(rune('a'+index%26)), size-len(prefix))
}

func semanticOwnerVariant(index int, variant uint8) string {
	owners := [...]string{"SET.Types.Test", "set.types.test.", "sEt.TyPeS.tEsT.", "Set.Types.Test."}
	return owners[(index+int(variant))%len(owners)]
}

func semanticTypeVariant(rrType dnsobs.RRType, index int) string {
	if index%2 == 0 {
		return strings.ToLower(string(rrType))
	}
	return string(rrType)
}

func semanticClassVariant(index int) string {
	if index%2 == 0 {
		return "in"
	}
	return "IN"
}

func semanticWireSeedResponse(question dns.Question, truncated bool) *dns.Msg {
	query := new(dns.Msg)
	query.Id = 0x4545
	query.Question = []dns.Question{question}
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.Truncated = truncated
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 90},
	}}
	return response
}

func (z authoritativeFixtureZone) firstRecordOfType(t testing.TB, rrType uint16) dns.RR {
	t.Helper()
	for _, record := range z.ordered {
		if record.Header().Rrtype == rrType {
			return dns.Copy(record)
		}
	}
	t.Fatalf("authoritative fixture has no record of type %s", dns.TypeToString[rrType])
	return nil
}

type semanticWireRRSetKey struct {
	section int
	owner   string
	rrType  dnsobs.RRType
	class   dnsobs.DNSClass
}

type semanticWireRRSet struct {
	count         int
	representable bool
}

func assertWireRRSetAtomicity(t testing.TB, message *dns.Msg, observation dnsobs.Observation) {
	t.Helper()
	source := make(map[semanticWireRRSetKey]semanticWireRRSet)
	sections := [][]dns.RR{message.Answer, message.Ns, message.Extra}
	for sectionIndex, records := range sections {
		for _, record := range records {
			if nilInterface(record) || record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			header := record.Header()
			owner, ownerErr := dnsobs.NormalizeWireName(header.Name)
			rrType, typeErr := dnsobs.ParseResponseRRType(typeName(header.Rrtype))
			class := dnsobs.DNSClass(dns.ClassToString[header.Class])
			if ownerErr != nil || typeErr != nil || class != dnsobs.DNSClassIN {
				continue
			}
			key := semanticWireRRSetKey{section: sectionIndex, owner: owner, rrType: rrType, class: class}
			current, exists := source[key]
			if !exists {
				current.representable = true
			}
			current.count++
			_, comparable, err := canonicalRDataForFingerprint(record)
			if err != nil || !comparable {
				current.representable = false
			}
			source[key] = current
		}
	}

	output := make(map[semanticWireRRSetKey][]dnsobs.ResourceRecord)
	observationSections := [][]dnsobs.ResourceRecord{observation.Sections.Answer, observation.Sections.Authority, observation.Sections.Additional}
	for sectionIndex, records := range observationSections {
		for _, record := range records {
			key := semanticWireRRSetKey{section: sectionIndex, owner: record.Owner, rrType: record.Type, class: record.Class}
			output[key] = append(output[key], record)
		}
	}
	for key, sourceSet := range source {
		retained := output[key]
		if !sourceSet.representable {
			if len(retained) != 0 {
				t.Fatalf("unrepresentable RRset %+v retained %d records", key, len(retained))
			}
			continue
		}
		if len(retained) != 0 && len(retained) != sourceSet.count {
			t.Fatalf("wire RRset %+v retained %d of %d records", key, len(retained), sourceSet.count)
		}
		for _, record := range retained {
			if key.rrType == dnsobs.RRTypeRRSIG {
				if record.RRSetFingerprint != "" {
					t.Fatalf("RRSIG wire RRset retained fingerprint %q", record.RRSetFingerprint)
				}
			} else if record.RRSetFingerprint == "" {
				t.Fatalf("wire RRset %+v retained a record without fingerprint", key)
			}
		}
	}
}
