package dnsobs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCanonicalRDataForRRUsesStableWireForm(t *testing.T) {
	a, err := dns.NewRR("EXAMPLE.COM. 60 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	display, canonical, comparable, err := CanonicalRecordDataForRR(a)
	if err != nil || !comparable || display != "192.0.2.1" || canonical != `\# 4 C0000201` {
		t.Fatalf("A record data = %q, %q, %t, %v", display, canonical, comparable, err)
	}

	cname, err := dns.NewRR("EXAMPLE.COM. 60 IN CNAME TARGET.EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	wantTarget := cname.(*dns.CNAME).Target
	first, comparable, err := CanonicalRDataForRR(cname)
	if err != nil || !comparable {
		t.Fatalf("CNAME canonical RDATA = %q, %t, %v", first, comparable, err)
	}
	lower, err := dns.NewRR("example.com. 60 IN CNAME target.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	second, comparable, err := CanonicalRDataForRR(lower)
	if err != nil || !comparable || first != second {
		t.Fatalf("embedded name case changed canonical RDATA: %q != %q (%t, %v)", first, second, comparable, err)
	}
	if cname.(*dns.CNAME).Target != wantTarget {
		t.Fatal("CanonicalRDataForRR mutated its input")
	}

	unknown := &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: 65400, Class: dns.ClassINET, Ttl: 60},
		Rdata: "00",
	}
	if value, comparable, err := CanonicalRDataForRR(unknown); err != nil || comparable || value != "" {
		t.Fatalf("unknown RFC3597 canonical RDATA = %q, %t, %v", value, comparable, err)
	}
}

func TestValidateCanonicalRDataRoundTripsKnownTypedRecords(t *testing.T) {
	svcb, err := dns.NewRR(`example.com. 60 IN SVCB 1 target.example.com. alpn="h2"`)
	if err != nil {
		t.Fatal(err)
	}
	svcbDisplay, svcbCanonical, comparable, err := CanonicalRecordDataForRR(svcb)
	if err != nil || !comparable {
		t.Fatalf("SVCB canonical RDATA = %q, %t, %v", svcbCanonical, comparable, err)
	}

	for _, test := range []struct {
		name      string
		owner     string
		rrType    RRType
		class     DNSClass
		canonical string
		display   string
	}{
		{name: "A", owner: "EXAMPLE.COM", rrType: "type1", class: " in ", canonical: `\# 4 C0000201`, display: "192.0.2.1"},
		{name: "audited numeric response type", owner: "example.com.", rrType: "TYPE64", class: DNSClassIN, canonical: svcbCanonical, display: svcbDisplay},
	} {
		t.Run(test.name, func(t *testing.T) {
			display, err := DisplayRDataForCanonicalRData(test.owner, test.rrType, test.class, test.canonical)
			if err != nil {
				t.Fatalf("ValidateCanonicalRData: %v", err)
			}
			if display != test.display {
				t.Fatalf("display RDATA = %q, want %q", display, test.display)
			}
		})
	}
}

func TestCanonicalRDataRejectsTypesOutsideAuditedResponseContract(t *testing.T) {
	for _, text := range []string{
		"example.com. 60 IN SSHFP 1 1 1234567890abcdef",
		`example.com. 60 IN NAPTR 10 20 "S" "SIP+D2U" "" target.example.com.`,
		"example.com. 60 IN NULL \\# 1 00",
	} {
		record, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("parse outside-contract RR %q: %v", text, err)
		}
		if display, canonical, comparable, err := CanonicalRecordDataForRR(record); err != nil || comparable || display != "" || canonical != "" {
			t.Fatalf("outside-contract RR %q = display %q canonical %q comparable=%t err=%v", text, display, canonical, comparable, err)
		}
	}
	for _, rrType := range []RRType{"TYPE44", "TYPE35", "TYPE10"} {
		if err := ValidateCanonicalRData("example.com.", rrType, DNSClassIN, `\# 1 00`); err == nil {
			t.Fatalf("typed ingress accepted outside-contract type %s", rrType)
		}
	}
}

func TestAuditedResponseTypesRejectZeroLengthRDATA(t *testing.T) {
	for _, rrType := range []RRType{
		RRTypeA, RRTypeAAAA, RRTypeCNAME, RRTypeMX, RRTypeTXT, RRTypeNS, RRTypeSOA, RRTypeCAA,
		RRTypeSRV, RRTypePTR, RRTypeDS, RRTypeDNSKEY, RRTypeTLSA, RRTypeSVCB, RRTypeHTTPS,
		RRTypeDNAME, RRTypeRRSIG, RRTypeNSEC, RRTypeNSEC3, RRTypeNSEC3PARAM,
	} {
		t.Run(string(rrType), func(t *testing.T) {
			if err := ValidateCanonicalRData("example.com.", rrType, DNSClassIN, `\# 0 `); err == nil {
				t.Fatalf("zero-length %s RDATA was accepted", rrType)
			}
		})
	}
	zeroTXT := &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}}
	if display, canonical, comparable, err := CanonicalRecordDataForRR(zeroTXT); err != nil || comparable || display != "" || canonical != "" {
		t.Fatalf("zero-length typed TXT = %q, %q, %t, %v", display, canonical, comparable, err)
	}
}

func TestCanonicalNameFoldingIsASCIIOnly(t *testing.T) {
	upper := &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "\u00c4.example."}
	lower := &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "\u00e4.example."}
	upperCanonical, upperComparable, upperErr := CanonicalRDataForRR(upper)
	lowerCanonical, lowerComparable, lowerErr := CanonicalRDataForRR(lower)
	if upperErr != nil || lowerErr != nil || !upperComparable || !lowerComparable {
		t.Fatalf("Unicode name fixtures were not comparable: upper=%t/%v lower=%t/%v", upperComparable, upperErr, lowerComparable, lowerErr)
	}
	if upperCanonical == lowerCanonical {
		t.Fatal("non-ASCII DNS label bytes were case folded")
	}
}

func TestNormalizeWireNamePreservesEscapedOctetsWithoutIDNA(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: `\255.EXAMPLE`, want: `\255.example.`},
		{input: "B\u00fcCHER.EXAMPLE.", want: `b\195\188cher.example.`},
	} {
		got, err := NormalizeWireName(test.input)
		if err != nil || got != test.want {
			t.Fatalf("NormalizeWireName(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
		if strings.Contains(got, "xn--") {
			t.Fatalf("wire-derived name was IDNA-mapped: %q", got)
		}
	}
}

func TestCAALegalPropertyTagIsCanonicalizedWhileInvalidTagEvidenceIsPreserved(t *testing.T) {
	upper := &dns.CAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Flag: 0, Tag: "ISSUE", Value: "ca.example"}
	lower := dns.Copy(upper).(*dns.CAA)
	lower.Tag = "issue"
	upperDisplay, upperCanonical, upperComparable, upperErr := CanonicalRecordDataForRR(upper)
	lowerDisplay, lowerCanonical, lowerComparable, lowerErr := CanonicalRecordDataForRR(lower)
	if upperErr != nil || lowerErr != nil || !upperComparable || !lowerComparable || upperCanonical != lowerCanonical || upperDisplay != lowerDisplay {
		t.Fatalf("CAA tag case did not canonicalize: upper=%q/%q/%t/%v lower=%q/%q/%t/%v", upperDisplay, upperCanonical, upperComparable, upperErr, lowerDisplay, lowerCanonical, lowerComparable, lowerErr)
	}
	if !strings.Contains(upperDisplay, " issue ") {
		t.Fatalf("canonical CAA display = %q", upperDisplay)
	}
	for _, canonical := range []string{`\# 2 0000`, `\# 3 000121`} {
		if _, err := DisplayRDataForCanonicalRData("example.com.", RRTypeCAA, DNSClassIN, canonical); err != nil {
			t.Fatalf("parseable CAA publisher violation %s was dropped: %v", canonical, err)
		}
	}
	if err := ValidateCanonicalRData("example.com.", RRTypeCAA, DNSClassIN, `\# 1 00`); err == nil {
		t.Fatal("truncated CAA without a tag-length field was accepted")
	}
}

func TestCanonicalRecordDataRejectsExpandedDisplayAboveContractLimit(t *testing.T) {
	chunks := make([]string, 20)
	for index := range chunks {
		chunks[index] = strings.Repeat("\x00", 255)
	}
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: chunks,
	}
	if display, canonical, comparable, err := CanonicalRecordDataForRR(record); err != nil || comparable || display != "" || canonical != "" {
		t.Fatalf("expanded TXT display = %d/%d bytes comparable=%t err=%v", len(display), len(canonical), comparable, err)
	}
	raw := new(dns.RFC3597)
	if err := raw.ToRFC3597(record); err != nil {
		t.Fatalf("encode expanded TXT fixture: %v", err)
	}
	canonical := fmt.Sprintf(`\# %d %s`, len(raw.Rdata)/2, strings.ToUpper(raw.Rdata))
	if len(canonical) >= MaxRDataBytes {
		t.Fatalf("canonical fixture is not below the contract limit: %d", len(canonical))
	}
	if _, err := FingerprintRRSet("example.com.", RRTypeTXT, DNSClassIN, []string{canonical}); err == nil {
		t.Fatal("fingerprint accepted canonical RDATA whose derived display exceeds the contract limit")
	}
}

func TestAuditedTypedSemanticsPreserveParseableEmptyOpaquePayloads(t *testing.T) {
	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: "example.com.", Rrtype: rrType, Class: dns.ClassINET}
	}
	records := []dns.RR{
		&dns.DS{Hdr: header(dns.TypeDS), KeyTag: 1, Algorithm: 13, DigestType: dns.SHA256},
		&dns.DNSKEY{Hdr: header(dns.TypeDNSKEY), Flags: 257, Protocol: 3, Algorithm: 13},
		&dns.TLSA{Hdr: header(dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1},
		&dns.RRSIG{Hdr: header(dns.TypeRRSIG), TypeCovered: dns.TypeA, Algorithm: 13, Labels: 2, SignerName: "example.com."},
		&dns.NSEC{Hdr: header(dns.TypeNSEC), NextDomain: "next.example.com."},
		&dns.NSEC3{Hdr: header(dns.TypeNSEC3), Hash: 1},
	}
	for _, record := range records {
		t.Run(dns.TypeToString[record.Header().Rrtype], func(t *testing.T) {
			if display, canonical, comparable, err := CanonicalRecordDataForRR(record); err != nil || !comparable || display == "" || canonical == "" {
				t.Fatalf("parseable typed RR = display %q canonical %q comparable=%t err=%v", display, canonical, comparable, err)
			}
		})
	}
}

func TestReceiverPreservesPublisherReservedBits(t *testing.T) {
	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: "example.com.", Rrtype: rrType, Class: dns.ClassINET}
	}
	records := []dns.RR{
		&dns.CAA{Hdr: header(dns.TypeCAA), Flag: 1, Tag: "issue", Value: "ca.example"},
		&dns.DNSKEY{Hdr: header(dns.TypeDNSKEY), Flags: 2, Protocol: 3, Algorithm: 13, PublicKey: "AQ=="},
		&dns.NSEC{Hdr: header(dns.TypeNSEC), NextDomain: "next.example.com.", TypeBitMap: []uint16{dns.TypeOPT, dns.TypeTKEY}},
	}
	for _, record := range records {
		display, canonical, comparable, err := CanonicalRecordDataForRR(record)
		if err != nil || !comparable || display == "" || canonical == "" {
			t.Fatalf("receiver-side TYPE%d evidence = display %q canonical %q comparable=%t err=%v", record.Header().Rrtype, display, canonical, comparable, err)
		}
	}
}

func TestPropagationEvidencePreservesParseableDNSSECAndTLSAValues(t *testing.T) {
	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: "*.example.com.", Rrtype: rrType, Class: dns.ClassINET}
	}
	records := []dns.RR{
		&dns.DNSKEY{Hdr: header(dns.TypeDNSKEY), Flags: 2, Protocol: 2, Algorithm: 13, PublicKey: "AQ=="},
		&dns.DS{Hdr: header(dns.TypeDS), KeyTag: 1, Algorithm: 13, DigestType: dns.SHA256, Digest: "00"},
		&dns.TLSA{Hdr: header(dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1, Certificate: "00"},
		&dns.RRSIG{Hdr: header(dns.TypeRRSIG), TypeCovered: dns.TypeA, Algorithm: 13, Labels: 3, SignerName: "example.com.", Signature: "AQ=="},
		&dns.NSEC3{Hdr: header(dns.TypeNSEC3), Hash: 1, Flags: 2, HashLength: 1, NextDomain: "00"},
		&dns.NSEC3PARAM{Hdr: header(dns.TypeNSEC3PARAM), Hash: 1, Flags: 1},
	}
	for _, record := range records {
		display, canonical, comparable, err := CanonicalRecordDataForRR(record)
		if err != nil || !comparable || display == "" || canonical == "" {
			t.Fatalf("parseable TYPE%d evidence = display %q canonical %q comparable=%t err=%v", record.Header().Rrtype, display, canonical, comparable, err)
		}
	}
}

func TestUnknownAlgorithmValuesRemainComparableWhenStructurallyValid(t *testing.T) {
	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: "example.com.", Rrtype: rrType, Class: dns.ClassINET}
	}
	records := []dns.RR{
		&dns.DS{Hdr: header(dns.TypeDS), KeyTag: 1, Algorithm: 250, DigestType: 250, Digest: "00"},
		&dns.DNSKEY{Hdr: header(dns.TypeDNSKEY), Flags: 257, Protocol: 3, Algorithm: 250, PublicKey: "AQ=="},
		&dns.TLSA{Hdr: header(dns.TypeTLSA), Usage: 250, Selector: 250, MatchingType: 250, Certificate: "00"},
		&dns.NSEC3{Hdr: header(dns.TypeNSEC3), Hash: 250, HashLength: 1, NextDomain: "00"},
	}
	for _, record := range records {
		t.Run(dns.TypeToString[record.Header().Rrtype], func(t *testing.T) {
			display, canonical, comparable, err := CanonicalRecordDataForRR(record)
			if err != nil || !comparable || display == "" || canonical == "" {
				t.Fatalf("unknown algorithm RR = display %q canonical %q comparable=%t err=%v", display, canonical, comparable, err)
			}
		})
	}
}

func TestSVCBParametersRequireAuditedRFC9460Semantics(t *testing.T) {
	header := dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60}
	alpn := func(values ...string) *dns.SVCBAlpn { return &dns.SVCBAlpn{Alpn: values} }
	for _, test := range []struct {
		name   string
		record *dns.SVCB
	}{
		{name: "empty mandatory", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBMandatory{}}}},
		{name: "mandatory duplicate", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ALPN}}, alpn("h2")}}},
		{name: "mandatory key zero", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_MANDATORY}}}}},
		{name: "mandatory key absent", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_PORT}}}}},
		{name: "top keys unsorted", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{alpn("h2"), &dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN}}}}},
		{name: "no default without alpn", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBNoDefaultAlpn{}}}},
		{name: "empty alpn", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{alpn()}}},
		{name: "empty alpn id", record: &dns.SVCB{Hdr: header, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{alpn("")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if display, canonical, comparable, err := CanonicalRecordDataForRR(test.record); err != nil || comparable || display != "" || canonical != "" {
				t.Fatalf("invalid SVCB = display %q canonical %q comparable=%t err=%v", display, canonical, comparable, err)
			}
		})
	}

	valid := &dns.SVCB{
		Hdr: header, Priority: 1, Target: "TARGET.EXAMPLE.",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN}},
			alpn("h2"),
			&dns.SVCBNoDefaultAlpn{},
		},
	}
	display, canonical, comparable, err := CanonicalRecordDataForRR(valid)
	if err != nil || !comparable || display == "" || canonical == "" {
		t.Fatalf("valid SVCB = display %q canonical %q comparable=%t err=%v", display, canonical, comparable, err)
	}
	if !strings.Contains(display, "target.example.") || !strings.Contains(display, "mandatory=") || !strings.Contains(display, "no-default-alpn") {
		t.Fatalf("valid SVCB display = %q", display)
	}

	alias := &dns.SVCB{Hdr: header, Priority: 0, Target: "alias.example.", Value: []dns.SVCBKeyValue{alpn("h2")}}
	aliasDisplay, aliasCanonical, aliasComparable, aliasErr := CanonicalRecordDataForRR(alias)
	if aliasErr != nil || !aliasComparable || aliasDisplay == "" || aliasCanonical == "" {
		t.Fatalf("AliasMode SvcParams were rejected: display=%q canonical=%q comparable=%t err=%v", aliasDisplay, aliasCanonical, aliasComparable, aliasErr)
	}
	for _, ignored := range []*dns.SVCB{
		{Hdr: header, Priority: 0, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBNoDefaultAlpn{}}},
		{Hdr: header, Priority: 0, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_PORT}}}},
	} {
		if display, canonical, comparable, err := CanonicalRecordDataForRR(ignored); err != nil || !comparable || display == "" || canonical == "" {
			t.Fatalf("ignored AliasMode ServiceMode semantics = display %q canonical %q comparable=%t err=%v", display, canonical, comparable, err)
		}
	}
}

func TestTypedIngressRejectsInvalidSVCBWireSemantics(t *testing.T) {
	for _, test := range []struct {
		name     string
		rrType   RRType
		rdataHex string
	}{
		{name: "empty mandatory", rrType: RRTypeSVCB, rdataHex: "00010000000000"},
		{name: "mandatory duplicate", rrType: RRTypeSVCB, rdataHex: "000100000000040001000100010003026832"},
		{name: "mandatory key zero", rrType: RRTypeSVCB, rdataHex: "000100000000020000"},
		{name: "mandatory key absent", rrType: RRTypeSVCB, rdataHex: "000100000000020003"},
		{name: "mandatory not increasing", rrType: RRTypeSVCB, rdataHex: "000100000000040003000100010003026832000300020050"},
		{name: "top keys unsorted", rrType: RRTypeSVCB, rdataHex: "0001000002000000010003026832"},
		{name: "top keys duplicate", rrType: RRTypeSVCB, rdataHex: "0001000001000302683200010003026833"},
		{name: "no default without alpn", rrType: RRTypeSVCB, rdataHex: "00010000020000"},
		{name: "empty alpn", rrType: RRTypeSVCB, rdataHex: "00010000010000"},
		{name: "empty alpn id", rrType: RRTypeSVCB, rdataHex: "0001000001000100"},
	} {
		t.Run(test.name, func(t *testing.T) {
			canonical := fmt.Sprintf(`\# %d %s`, len(test.rdataHex)/2, strings.ToUpper(test.rdataHex))
			if err := ValidateCanonicalRData("example.com.", test.rrType, DNSClassIN, canonical); err == nil {
				t.Fatalf("invalid %s RDATA was accepted: %s", test.rrType, canonical)
			}
		})
	}
}

func TestTypedIngressAcceptsAliasModeSvcParams(t *testing.T) {
	for _, rrType := range []RRType{RRTypeSVCB, RRTypeHTTPS} {
		for _, canonical := range []string{
			`\# 24 000005616C696173076578616D706C650000010003026832`,
			`\# 7 00000000020000`,
			`\# 9 000000000000020003`,
		} {
			display, err := DisplayRDataForCanonicalRData("example.com.", rrType, DNSClassIN, canonical)
			if err != nil || display == "" {
				t.Fatalf("AliasMode %s canonical=%s display=%q err=%v", rrType, canonical, display, err)
			}
		}
	}
}

func TestAliasModeStillRejectsMalformedMandatoryValue(t *testing.T) {
	for _, rrType := range []RRType{RRTypeSVCB, RRTypeHTTPS} {
		for _, canonical := range []string{
			`\# 7 00000000000000`,
			`\# 11 0000000000000400010001`,
			`\# 9 000000000000020000`,
			`\# 9 00000000000002FFFF`,
			`\# 11 0000000000000400030001`,
		} {
			if err := ValidateCanonicalRData("example.com.", rrType, DNSClassIN, canonical); err == nil {
				t.Fatalf("AliasMode %s accepted malformed mandatory value %s", rrType, canonical)
			}
		}
	}
}

func TestSVCBECHConfigListFraming(t *testing.T) {
	for _, valueHex := range []string{
		"0004FE0D0000",
		"000AFE0D0001AA12340001BB",
	} {
		value := mustDecodeHex(t, valueHex)
		if err := ValidateSVCBECHConfigList(value); err != nil {
			t.Fatalf("valid ECHConfigList %s: %v", valueHex, err)
		}
		record := &dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET},
			Priority: 1, Target: ".",
			Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: value}},
		}
		if _, _, comparable, err := CanonicalRecordDataForRR(record); err != nil || !comparable {
			t.Fatalf("typed ECHConfigList %s comparable=%t err=%v", valueHex, comparable, err)
		}
	}
	for _, valueHex := range []string{
		"",
		"0000",
		"0001FF",
		"0004FE0D0001",
		"0005FE0D0000FF",
	} {
		if err := ValidateSVCBECHConfigList(mustDecodeHex(t, valueHex)); err == nil {
			t.Fatalf("malformed ECHConfigList was accepted: %s", valueHex)
		}
	}
}

func TestSVCBDoHPathRequiresRFC9461Template(t *testing.T) {
	for _, value := range []string{
		"/dns-query{?dns}",
		"/resolve/{dns}",
	} {
		if err := ValidateSVCBDoHPathTemplate(value); err != nil {
			t.Fatalf("valid dohpath %q: %v", value, err)
		}
		record := &dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET},
			Priority: 1, Target: ".",
			Value: []dns.SVCBKeyValue{&dns.SVCBDoHPath{Template: value}},
		}
		if _, _, comparable, err := CanonicalRecordDataForRR(record); err != nil || !comparable {
			t.Fatalf("typed dohpath %q comparable=%t err=%v", value, comparable, err)
		}
	}
	for _, value := range []string{
		"x",
		"/dns-query",
		"dns-query{?dns}",
		"https://example/dns-query{?dns}",
		"//example/dns-query{?dns}",
		"/dns-query{#dns}",
		"/dns-query{?dns",
		"/{dns:1}",
		"/dns-query{?dns:9999}",
		"/{dns:9999}PQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
	} {
		if err := ValidateSVCBDoHPathTemplate(value); err == nil {
			t.Fatalf("invalid dohpath was accepted: %q", value)
		}
	}
}

func mustDecodeHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func TestSVCBCompatibleRecordsAcceptRootTarget(t *testing.T) {
	for _, rrType := range []RRType{RRTypeSVCB, RRTypeHTTPS} {
		for _, canonical := range []string{`\# 3 000000`, `\# 3 000100`} {
			if err := ValidateCanonicalRData("example.com.", rrType, DNSClassIN, canonical); err != nil {
				t.Fatalf("%s rejected root target %s: %v", rrType, canonical, err)
			}
		}
	}
}

func TestFingerprintRRSetRejectsUnverifiedCanonicalRData(t *testing.T) {
	for _, test := range []struct {
		name      string
		rrType    RRType
		canonical string
	}{
		{name: "presentation text", rrType: RRTypeA, canonical: "192.0.2.1"},
		{name: "lowercase wire hex", rrType: RRTypeA, canonical: `\# 4 c0000201`},
		{name: "unknown wire semantics", rrType: "TYPE65400", canonical: `\# 1 00`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if fingerprint, err := FingerprintRRSet("example.com.", test.rrType, DNSClassIN, []string{test.canonical}); err == nil {
				t.Fatalf("FingerprintRRSet accepted %q as %q", test.canonical, fingerprint)
			}
		})
	}
}

func TestValidateCanonicalRDataRejectsNonCanonicalOrOpaqueInput(t *testing.T) {
	upperNS := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
		Ns:  "NS.EXAMPLE.COM.",
	}
	rawNS := new(dns.RFC3597)
	if err := rawNS.ToRFC3597(upperNS); err != nil {
		t.Fatalf("encode uppercase NS RDATA: %v", err)
	}
	uppercaseNameWire := fmt.Sprintf(`\# %d %s`, len(rawNS.Rdata)/2, strings.ToUpper(rawNS.Rdata))
	canonicalNS, comparable, err := CanonicalRDataForRR(upperNS)
	if err != nil || !comparable || uppercaseNameWire == canonicalNS {
		t.Fatalf("NS test setup = raw %q canonical %q comparable=%t err=%v", uppercaseNameWire, canonicalNS, comparable, err)
	}

	for _, test := range []struct {
		name      string
		rrType    RRType
		canonical string
	}{
		{name: "ordinary presentation text", rrType: RRTypeA, canonical: "192.0.2.1"},
		{name: "lowercase hex", rrType: RRTypeA, canonical: `\# 4 c0000201`},
		{name: "leading zero length", rrType: RRTypeA, canonical: `\# 04 C0000201`},
		{name: "extra whitespace", rrType: RRTypeA, canonical: `\# 4  C0000201`},
		{name: "deceptive length", rrType: RRTypeA, canonical: `\# 3 C0000201`},
		{name: "malformed typed wire", rrType: RRTypeA, canonical: `\# 3 C00002`},
		{name: "noncanonical embedded name case", rrType: RRTypeNS, canonical: uppercaseNameWire},
		{name: "compressed embedded name", rrType: RRTypeNS, canonical: `\# 2 C000`},
		{name: "unknown RFC3597 type", rrType: "TYPE65400", canonical: `\# 1 00`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCanonicalRData("example.com.", test.rrType, DNSClassIN, test.canonical); err == nil {
				t.Fatalf("ValidateCanonicalRData accepted %q", test.canonical)
			}
		})
	}
}

func TestNormalizeObservationRejectsNonCanonicalRDataBeforeFingerprinting(t *testing.T) {
	for _, canonical := range []string{
		"93.184.216.34",
		`\# 4 5db8d822`,
		`\# 3 5DB8D822`,
	} {
		observation := validObservation()
		observation.Sections.Answer[0].CanonicalRData = canonical
		_, err := NormalizeObservation(observation)
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) || validationErr.Code != "INVALID_CANONICAL_RDATA" {
			t.Fatalf("canonical RDATA %q error = %#v", canonical, err)
		}
		if observation.Sections.Answer[0].RRSetFingerprint != "" {
			t.Fatal("NormalizeObservation mutated rejected input with a fingerprint")
		}
	}
}

func TestNormalizeObservationBindsDisplayToCanonicalTypedRData(t *testing.T) {
	observation := validObservation()
	observation.Sections.Answer[0].DisplayRData = "203.0.113.9"
	_, err := NormalizeObservation(observation)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "DISPLAY_RDATA_MISMATCH" || validationErr.Field != "sections.answer[0].display_rdata" {
		t.Fatalf("display mismatch error = %#v", err)
	}
}

func canonicalTXTForDNSObsTest(t testing.TB, value string) string {
	t.Helper()
	chunks := make([]string, 0, len(value)/255+1)
	for len(value) > 255 {
		chunks = append(chunks, value[:255])
		value = value[255:]
	}
	chunks = append(chunks, value)
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: chunks,
	}
	canonical, comparable, err := CanonicalRDataForRR(record)
	if err != nil || !comparable {
		t.Fatalf("canonicalize TXT test RDATA: comparable=%t err=%v", comparable, err)
	}
	return canonical
}
