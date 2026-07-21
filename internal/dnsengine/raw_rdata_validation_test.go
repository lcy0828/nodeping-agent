package dnsengine

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAuditedRawRDataRejectsTruncatedTailForEveryType(t *testing.T) {
	for _, record := range auditedRawRDataFixtures(t) {
		rrType := record.Header().Rrtype
		t.Run(dns.TypeToString[rrType], func(t *testing.T) {
			rdataHex := rawRDataHex(t, record)
			rdata, err := hex.DecodeString(rdataHex)
			if err != nil || len(rdata) < 2 {
				t.Fatalf("decode valid TYPE%d fixture %q: %v", rrType, rdataHex, err)
			}
			assertRawAdditionalRRAccepted(t, rrType, rdataHex)
			truncated := rdata[:len(rdata)-1]
			switch rrType {
			case dns.TypeCAA:
				truncated = rdata[:1+int(rdata[1])]
			case dns.TypeDS, dns.TypeDNSKEY:
				truncated = rdata[:3]
			case dns.TypeTLSA:
				truncated = rdata[:2]
			case dns.TypeRRSIG:
				truncated = rdata[:18]
			}
			truncatedHex := strings.ToUpper(hex.EncodeToString(truncated))
			assertRawWireValidationRejected(t, rrType, truncatedHex)
			assertRawAdditionalRRRejected(t, rrType, truncatedHex)
		})
	}
}

func TestRawRDataRejectsPreferenceOnlyMXAndPriorityOnlySVCB(t *testing.T) {
	for _, test := range []struct {
		rrType   uint16
		rdataHex string
	}{
		{rrType: dns.TypeMX, rdataHex: "000A"},
		{rrType: dns.TypeSVCB, rdataHex: "0001"},
		{rrType: dns.TypeHTTPS, rdataHex: "0001"},
	} {
		assertRawWireValidationRejected(t, test.rrType, test.rdataHex)
		assertRawAdditionalRRRejected(t, test.rrType, test.rdataHex)
	}
}

func TestRawReceiverPreservesParseableEmptyOpaquePayloads(t *testing.T) {
	for _, test := range []struct {
		rrType   uint16
		rdataHex string
	}{
		{rrType: dns.TypeDS, rdataHex: "00010802"},
		{rrType: dns.TypeDNSKEY, rdataHex: "0101030D"},
		{rrType: dns.TypeTLSA, rdataHex: "030101"},
		{rrType: dns.TypeRRSIG, rdataHex: strings.Repeat("00", 18) + "00"},
		{rrType: dns.TypeNSEC, rdataHex: "00"},
		{rrType: dns.TypeNSEC3, rdataHex: "010000000000"},
	} {
		t.Run(dns.TypeToString[test.rrType], func(t *testing.T) {
			assertRawAdditionalRRAccepted(t, test.rrType, test.rdataHex)
		})
	}
}

func TestRawReceiverPreservesCAAAndDNSKEYReservedFlags(t *testing.T) {
	assertRawAdditionalRRAccepted(t, dns.TypeCAA, "01056973737565")
	assertRawAdditionalRRAccepted(t, dns.TypeDNSKEY, "0002030D01")
}

func TestRawSVCBKnownKeyValueShapesAreValidated(t *testing.T) {
	for _, test := range []struct {
		name      string
		key       uint16
		valueHex  string
		valueSize int
	}{
		{name: "mandatory empty", key: 0},
		{name: "mandatory odd", key: 0, valueHex: "00", valueSize: 1},
		{name: "mandatory duplicate", key: 0, valueHex: "00010001", valueSize: 4},
		{name: "mandatory key zero", key: 0, valueHex: "0000", valueSize: 2},
		{name: "mandatory key reserved", key: 0, valueHex: "FFFF", valueSize: 2},
		{name: "mandatory not increasing", key: 0, valueHex: "00030001", valueSize: 4},
		{name: "alpn empty", key: 1},
		{name: "alpn empty id", key: 1, valueHex: "00", valueSize: 1},
		{name: "no-default-alpn nonempty", key: 2, valueHex: "00", valueSize: 1},
		{name: "port short", key: 3, valueHex: "00", valueSize: 1},
		{name: "ipv4hint empty", key: 4},
		{name: "ipv4hint partial", key: 4, valueHex: "000000", valueSize: 3},
		{name: "ech empty", key: 5},
		{name: "ech vector mismatch", key: 5, valueHex: "0001", valueSize: 2},
		{name: "ech truncated config header", key: 5, valueHex: "0001FF", valueSize: 3},
		{name: "ech truncated config contents", key: 5, valueHex: "0004FE0D0001", valueSize: 6},
		{name: "ech trailing partial config", key: 5, valueHex: "0005FE0D0000FF", valueSize: 7},
		{name: "ipv6hint empty", key: 6},
		{name: "ipv6hint partial", key: 6, valueHex: strings.Repeat("00", 15), valueSize: 15},
		{name: "dohpath empty", key: 7},
		{name: "dohpath invalid UTF-8", key: 7, valueHex: "FF", valueSize: 1},
		{name: "dohpath invalid template", key: 7, valueHex: strings.ToUpper(hex.EncodeToString([]byte("/dns-query{?dns"))), valueSize: len("/dns-query{?dns")},
		{name: "dohpath missing dns variable", key: 7, valueHex: strings.ToUpper(hex.EncodeToString([]byte("/dns-query"))), valueSize: len("/dns-query")},
		{name: "dohpath absolute", key: 7, valueHex: strings.ToUpper(hex.EncodeToString([]byte("https://example/dns-query{?dns}"))), valueSize: len("https://example/dns-query{?dns}")},
		{name: "dohpath truncates dns variable", key: 7, valueHex: strings.ToUpper(hex.EncodeToString([]byte("/dns-query{?dns:8}"))), valueSize: len("/dns-query{?dns:8}")},
		{name: "ohttp nonempty", key: 8, valueHex: "00", valueSize: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			rdataHex := fmt.Sprintf("000100%04X%04X%s", test.key, test.valueSize, test.valueHex)
			assertRawWireValidationRejected(t, dns.TypeSVCB, rdataHex)
			assertRawWireValidationRejected(t, dns.TypeHTTPS, rdataHex)
			assertRawAdditionalRRRejected(t, dns.TypeSVCB, rdataHex)
			assertRawAdditionalRRRejected(t, dns.TypeHTTPS, rdataHex)
		})
	}
}

func TestRawSVCBRejectsFixedSuffixDoHPathPrefixBypass(t *testing.T) {
	const rdataHex = "0001000007003C2F7B646E733A393939397D505152535455565758595A6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435363738392D5F"
	for _, rrType := range []uint16{dns.TypeSVCB, dns.TypeHTTPS} {
		assertRawWireValidationRejected(t, rrType, rdataHex)
		assertRawAdditionalRRRejected(t, rrType, rdataHex)
	}
}

func TestRawSVCBStructuredKnownValuesAreAccepted(t *testing.T) {
	for _, test := range []struct {
		name     string
		key      uint16
		valueHex string
	}{
		{name: "minimal framed ECHConfigList", key: uint16(dns.SVCB_ECHCONFIG), valueHex: "0004FE0D0000"},
		{name: "RFC9461 dohpath", key: uint16(dns.SVCB_DOHPATH), valueHex: strings.ToUpper(hex.EncodeToString([]byte("/dns-query{?dns}")))},
	} {
		t.Run(test.name, func(t *testing.T) {
			rdataHex := fmt.Sprintf("000100%04X%04X%s", test.key, len(test.valueHex)/2, test.valueHex)
			assertRawAdditionalRRAccepted(t, dns.TypeSVCB, rdataHex)
			assertRawAdditionalRRAccepted(t, dns.TypeHTTPS, rdataHex)
		})
	}
}

func TestRawAliasModeStillRejectsMalformedMandatoryValue(t *testing.T) {
	for _, valueHex := range []string{
		"",
		"00010001",
		"0000",
		"FFFF",
		"00030001",
	} {
		rdataHex := fmt.Sprintf("0000000000%04X%s", len(valueHex)/2, valueHex)
		assertRawWireValidationRejected(t, dns.TypeSVCB, rdataHex)
		assertRawWireValidationRejected(t, dns.TypeHTTPS, rdataHex)
		assertRawAdditionalRRRejected(t, dns.TypeSVCB, rdataHex)
		assertRawAdditionalRRRejected(t, dns.TypeHTTPS, rdataHex)
	}
}

func TestRawNSECBitmapsPreserveMetaAndQueryOnlyBits(t *testing.T) {
	bitmap := make([]byte, 32)
	bitmap[31] = 0x40 // TYPE249 (TKEY)
	nsecHex := "000020" + strings.ToUpper(hex.EncodeToString(bitmap))
	assertRawAdditionalRRAccepted(t, dns.TypeNSEC, nsecHex)

	nsec3Prefix := "010000000014" + strings.Repeat("00", 20)
	assertRawAdditionalRRAccepted(t, dns.TypeNSEC3, nsec3Prefix+"0020"+strings.ToUpper(hex.EncodeToString(bitmap)))
}

func TestRawRDataNameCompressionPolicy(t *testing.T) {
	allowed := []struct {
		name     string
		rrType   uint16
		rdataHex string
	}{
		{name: "CNAME", rrType: dns.TypeCNAME, rdataHex: "C00C"},
		{name: "NS", rrType: dns.TypeNS, rdataHex: "C00C"},
		{name: "PTR", rrType: dns.TypePTR, rdataHex: "C00C"},
		{name: "MX", rrType: dns.TypeMX, rdataHex: "000AC00C"},
		{name: "SOA", rrType: dns.TypeSOA, rdataHex: "C00CC00C" + strings.Repeat("00", 20)},
	}
	for _, test := range allowed {
		t.Run("allowed/"+test.name, func(t *testing.T) {
			assertRawAdditionalRRAccepted(t, test.rrType, test.rdataHex)
		})
	}

	forbidden := []struct {
		name     string
		rrType   uint16
		rdataHex string
	}{
		{name: "SRV", rrType: dns.TypeSRV, rdataHex: strings.Repeat("00", 6) + "C00C"},
		{name: "DNAME", rrType: dns.TypeDNAME, rdataHex: "C00C"},
		{name: "RRSIG", rrType: dns.TypeRRSIG, rdataHex: strings.Repeat("00", 18) + "C00C01"},
		{name: "NSEC", rrType: dns.TypeNSEC, rdataHex: "C00C000140"},
		{name: "SVCB", rrType: dns.TypeSVCB, rdataHex: "0001C00C"},
		{name: "HTTPS", rrType: dns.TypeHTTPS, rdataHex: "0001C00C"},
	}
	for _, test := range forbidden {
		t.Run("forbidden/"+test.name, func(t *testing.T) {
			assertRawAdditionalRRRejected(t, test.rrType, test.rdataHex)
		})
	}
}

func FuzzValidateAuditedRawRDataBoundaries(f *testing.F) {
	fixtures := auditedRawRDataFixtures(f)
	for index, record := range fixtures {
		rdata, err := hex.DecodeString(rawRDataHex(f, record))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(index), rdata)
		if len(rdata) > 0 {
			f.Add(uint8(index), rdata[:len(rdata)-1])
		}
	}
	f.Fuzz(func(t *testing.T, rawIndex uint8, rdata []byte) {
		if len(rdata) > 4096 {
			return
		}
		rrType := fixtures[int(rawIndex)%len(fixtures)].Header().Rrtype
		wire := make([]byte, 12+len(rdata))
		copy(wire[12:], rdata)
		_ = validateAuditedRawRData(wire, rrType, 12, len(wire))
	})
}

func auditedRawRDataFixtures(t testing.TB) []dns.RR {
	t.Helper()
	mustRR := func(text string) dns.RR {
		t.Helper()
		record, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("parse raw RDATA fixture %q: %v", text, err)
		}
		return record
	}
	return []dns.RR{
		mustRR("example.com. 60 IN A 192.0.2.1"),
		mustRR("example.com. 60 IN AAAA 2001:db8::1"),
		mustRR("example.com. 60 IN CNAME a."),
		mustRR("example.com. 60 IN MX 10 a."),
		mustRR(`example.com. 60 IN TXT "x"`),
		mustRR("example.com. 60 IN NS a."),
		mustRR("example.com. 60 IN SOA a. b. 1 2 3 4 5"),
		mustRR(`example.com. 60 IN CAA 0 issue "x"`),
		mustRR("example.com. 60 IN SRV 1 2 80 a."),
		mustRR("example.com. 60 IN PTR a."),
		mustRR("example.com. 60 IN DS 1 13 2 " + strings.Repeat("00", 32)),
		mustRR("example.com. 60 IN DNSKEY 257 3 13 AQ=="),
		mustRR("example.com. 60 IN TLSA 3 1 1 " + strings.Repeat("00", 32)),
		mustRR("example.com. 60 IN SVCB 1 a."),
		mustRR("example.com. 60 IN HTTPS 1 a."),
		mustRR("example.com. 60 IN DNAME a."),
		mustRR("example.com. 60 IN RRSIG A 13 2 300 20300101000000 20250101000000 12345 example.com. AQ=="),
		mustRR("example.com. 60 IN NSEC a. A"),
		mustRR("example.com. 60 IN NSEC3 1 0 5 A1B2 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A"),
		mustRR("example.com. 60 IN NSEC3PARAM 1 0 5 A1B2"),
	}
}

func rawRDataHex(t testing.TB, record dns.RR) string {
	t.Helper()
	raw := new(dns.RFC3597)
	if err := raw.ToRFC3597(record); err != nil {
		t.Fatalf("convert TYPE%d fixture to RFC3597: %v", record.Header().Rrtype, err)
	}
	return strings.ToUpper(raw.Rdata)
}

func assertRawAdditionalRRAccepted(t *testing.T, rrType uint16, rdataHex string) {
	t.Helper()
	wire := rawAdditionalResponseWire(t, rrType, rdataHex)
	message, err := unpackResponse(wire)
	if err != nil {
		t.Fatalf("unpack valid raw TYPE%d response: %v", rrType, err)
	}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	result := &Result{Question: query.Question[0]}
	if err := newTestEngine(t, nil).populateResult(result, message); err != nil {
		t.Fatalf("populate valid raw TYPE%d response: %v", rrType, err)
	}
	if result.ResultTruncated || len(result.Sections.Additional) != 1 || result.Sections.Additional[0].Type != typeName(rrType) {
		t.Fatalf("valid raw TYPE%d was not retained: %s", rrType, fmt.Sprintf("%+v", result))
	}
}

func assertRawWireValidationRejected(t *testing.T, rrType uint16, rdataHex string) {
	t.Helper()
	wire := rawAdditionalResponseWire(t, rrType, rdataHex)
	if err := validateDNSWireConsumption(wire); err == nil {
		t.Fatalf("raw TYPE%d RDATA passed the pre-unpack wire validator: %s", rrType, rdataHex)
	}
	if _, err := unpackResponse(wire); err == nil {
		t.Fatalf("raw TYPE%d RDATA passed unpackResponse: %s", rrType, rdataHex)
	}
}

func rawAdditionalResponseWire(t testing.TB, rrType uint16, rdataHex string) []byte {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Extra = []dns.RR{&dns.RFC3597{
		Hdr:   dns.RR_Header{Name: "invalid.example.com.", Rrtype: rrType, Class: dns.ClassINET, Ttl: 60},
		Rdata: rdataHex,
	}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatalf("pack raw TYPE%d response: %v", rrType, err)
	}
	return wire
}
