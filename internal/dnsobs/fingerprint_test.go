package dnsobs

import "testing"

func TestFingerprintRRSetIgnoresOrderTTLAndDuplicates(t *testing.T) {
	first := []ResourceRecord{
		{Owner: "Example.COM", Type: "a", Class: "in", TTL: 60, CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 2},
		{Owner: "example.com.", Type: RRTypeA, Class: DNSClassIN, TTL: 120, CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 2},
	}
	second := []ResourceRecord{
		{Owner: "example.com", Type: RRTypeA, Class: DNSClassIN, TTL: 1, CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 3},
		{Owner: "EXAMPLE.COM", Type: RRTypeA, Class: DNSClassIN, TTL: 999, CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 3},
		{Owner: "example.com", Type: RRTypeA, Class: DNSClassIN, TTL: 999, CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 3},
	}
	left, err := FingerprintRecords(first)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	right, err := FingerprintRecords(second)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if left != right {
		t.Fatalf("fingerprints differ:\n%s\n%s", left, right)
	}
	if !ValidRRSetFingerprint(left) {
		t.Fatalf("invalid generated fingerprint %q", left)
	}
}

func TestFingerprintRRSetPreservesCanonicalRDataBytes(t *testing.T) {
	lower, err := FingerprintRRSet("example.com", RRTypeTXT, DNSClassIN, []string{`\# 6 0576616C7565`})
	if err != nil {
		t.Fatal(err)
	}
	upper, err := FingerprintRRSet("example.com", RRTypeTXT, DNSClassIN, []string{`\# 6 0556616C7565`})
	if err != nil {
		t.Fatal(err)
	}
	if lower == upper {
		t.Fatal("TXT case was incorrectly ignored")
	}
	one, _ := FingerprintRRSet("example.com", RRTypeTXT, DNSClassIN, []string{`\# 2 0161`, `\# 3 026263`})
	two, _ := FingerprintRRSet("example.com", RRTypeTXT, DNSClassIN, []string{`\# 3 026162`, `\# 2 0163`})
	if one == two {
		t.Fatal("length framing did not distinguish ambiguous concatenations")
	}
}

func TestApplyRRSetFingerprintsSeparatesSections(t *testing.T) {
	sections := Sections{
		Answer:     []ResourceRecord{{Owner: "EXAMPLE.COM", Type: "a", Class: "in", TTL: 10, DisplayRData: "192.0.2.1", CanonicalRData: `\# 4 C0000201`, RRSetRecordCount: 1}},
		Additional: []ResourceRecord{{Owner: "example.com.", Type: RRTypeA, Class: DNSClassIN, TTL: 20, DisplayRData: "192.0.2.2", CanonicalRData: `\# 4 C0000202`, RRSetRecordCount: 1}},
		Authority:  []ResourceRecord{{Owner: "example.com.", Type: RRTypeRRSIG, Class: DNSClassIN, TTL: 20, DisplayRData: "A 13 2 ...", CanonicalRData: "A 13 2 ...", RRSetRecordCount: 1}},
	}
	if err := ApplyRRSetFingerprints(&sections); err != nil {
		t.Fatalf("ApplyRRSetFingerprints: %v", err)
	}
	if sections.Answer[0].RRSetFingerprint == "" || sections.Additional[0].RRSetFingerprint == "" || sections.Answer[0].RRSetFingerprint == sections.Additional[0].RRSetFingerprint {
		t.Fatalf("RRset fingerprints = %q and %q", sections.Answer[0].RRSetFingerprint, sections.Additional[0].RRSetFingerprint)
	}
	if sections.Authority[0].RRSetFingerprint != "" {
		t.Fatal("RRSIG was included in RRset fingerprinting")
	}
	sections.Answer[0].RRSetFingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := ApplyRRSetFingerprints(&sections); err == nil {
		t.Fatal("mismatched supplied fingerprint was accepted")
	}
}

func TestSectionSwapCannotProduceTheSameAnswerFingerprint(t *testing.T) {
	makeSections := func(answer, additional string) Sections {
		return Sections{
			Answer:     []ResourceRecord{{Owner: "example.com.", Type: RRTypeA, Class: DNSClassIN, DisplayRData: answer, CanonicalRData: `\# 4 ` + answer, RRSetRecordCount: 1}},
			Additional: []ResourceRecord{{Owner: "example.com.", Type: RRTypeA, Class: DNSClassIN, DisplayRData: additional, CanonicalRData: `\# 4 ` + additional, RRSetRecordCount: 1}},
		}
	}
	left := makeSections("C0000201", "C0000202")
	right := makeSections("C0000202", "C0000201")
	if err := ApplyRRSetFingerprints(&left); err != nil {
		t.Fatalf("fingerprint left sections: %v", err)
	}
	if err := ApplyRRSetFingerprints(&right); err != nil {
		t.Fatalf("fingerprint right sections: %v", err)
	}
	if left.Answer[0].RRSetFingerprint == right.Answer[0].RRSetFingerprint {
		t.Fatal("swapping answer and additional RDATA preserved the answer fingerprint")
	}
}

func TestParseResponseRRTypeSupportsRFC3597ButRejectsMetaTypes(t *testing.T) {
	got, err := ParseResponseRRType("type065400")
	if err != nil || got != "TYPE65400" {
		t.Fatalf("ParseResponseRRType = %q, %v", got, err)
	}
	for _, value := range []string{
		"TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY",
		"TYPE249", "TYPE250", "TYPE251", "TYPE252", "TYPE253", "TYPE254", "TYPE255",
		"TYPE0", "TYPE65536", "OPT",
	} {
		if got, err := ParseResponseRRType(value); err == nil {
			t.Errorf("ParseResponseRRType(%q) = %q, want error", value, got)
		}
	}
	if _, err := FingerprintRRSet("example.com", RRTypeRRSIG, DNSClassIN, []string{"value"}); err == nil {
		t.Fatal("RRSIG fingerprint was accepted")
	}
	if got, err := ParseResponseRRType("TYPE1"); err != nil || got != RRTypeA {
		t.Fatalf("TYPE1 = %q, %v, want A", got, err)
	}
	if _, err := FingerprintRRSet("example.com", "TYPE46", DNSClassIN, []string{"value"}); err == nil {
		t.Fatal("numeric RRSIG fingerprint bypass was accepted")
	}
}
