package dnsobs

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeFQDN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "ascii", input: " ExAmPle.COM ", want: "example.com."},
		{name: "idna", input: "b\u00fccher.example", want: "xn--bcher-kva.example."},
		{name: "unicode dot", input: "www\u3002example\uff0ecom\uff61", want: "www.example.com."},
		{name: "root", input: ".", want: "."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeFQDN(test.input)
			if err != nil {
				t.Fatalf("NormalizeFQDN: %v", err)
			}
			if got != test.want {
				t.Fatalf("NormalizeFQDN(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeFQDNRejectsUnsafeNames(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	longName := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63),
		strings.Repeat("c", 63), strings.Repeat("d", 63),
	}, ".")
	for _, input := range []string{"", "example..com", "example.com..", "*.example.com", "_sip.example.com", "-bad.example", longLabel, longName} {
		if got, err := NormalizeFQDN(input); err == nil {
			t.Errorf("NormalizeFQDN(%q) = %q, want error", input, got)
		}
	}
}

func TestNormalizeQuestionNameAllowsUnderscoreLabels(t *testing.T) {
	srv, err := NormalizeQuestionName("_SIP._TCP.b\u00fccher.example", RRTypeSRV)
	if err != nil {
		t.Fatalf("normalize SRV: %v", err)
	}
	if srv != "_sip._tcp.xn--bcher-kva.example." {
		t.Fatalf("SRV name = %q", srv)
	}
	tlsa, err := NormalizeQuestionName("_443._TCP.Example.com", RRTypeTLSA)
	if err != nil {
		t.Fatalf("normalize TLSA: %v", err)
	}
	if tlsa != "_443._tcp.example.com." {
		t.Fatalf("TLSA name = %q", tlsa)
	}
	for _, test := range []struct {
		name   string
		rrType RRType
		want   string
	}{
		{name: "_DMARC.Example", rrType: RRTypeTXT, want: "_dmarc.example."},
		{name: "_acme-challenge.Example", rrType: RRTypeCNAME, want: "_acme-challenge.example."},
		{name: "Selector._DomainKey.Example", rrType: RRTypeTXT, want: "selector._domainkey.example."},
		{name: "_service.Example", rrType: RRTypeA, want: "_service.example."},
	} {
		got, err := NormalizeQuestionName(test.name, test.rrType)
		if err != nil {
			t.Errorf("NormalizeQuestionName(%q, %s): %v", test.name, test.rrType, err)
		} else if got != test.want {
			t.Errorf("NormalizeQuestionName(%q, %s) = %q, want %q", test.name, test.rrType, got, test.want)
		}
	}
	for _, test := range []struct {
		name   string
		rrType RRType
	}{
		{name: "sip.example.com", rrType: RRTypeSRV},
		{name: "_sip._tcp._bad.example", rrType: RRTypeSRV},
		{name: "_0._tcp.example", rrType: RRTypeTLSA},
		{name: "_443._quic.example", rrType: RRTypeTLSA},
		{name: "*.example", rrType: RRTypeTXT},
		{name: "_owner.example", rrType: RRTypePTR},
	} {
		if got, err := NormalizeQuestionName(test.name, test.rrType); err == nil {
			t.Errorf("NormalizeQuestionName(%q, %s) = %q, want error", test.name, test.rrType, got)
		}
	}
}

func TestNormalizePTRName(t *testing.T) {
	got, err := NormalizePTRName("192.0.2.1")
	if err != nil {
		t.Fatalf("NormalizePTRName IPv4: %v", err)
	}
	if got != "1.2.0.192.in-addr.arpa." {
		t.Fatalf("IPv4 reverse = %q", got)
	}
	ipv6, err := NormalizePTRName("2001:db8::1")
	if err != nil {
		t.Fatalf("NormalizePTRName IPv6: %v", err)
	}
	if !strings.HasSuffix(ipv6, ".8.b.d.0.1.0.0.2.ip6.arpa.") {
		t.Fatalf("IPv6 reverse = %q", ipv6)
	}
	if normalized, err := NormalizePTRName(strings.ToUpper(ipv6)); err != nil || normalized != ipv6 {
		t.Fatalf("canonical IPv6 reverse = %q, %v", normalized, err)
	}
	if got := ReverseName(netip.MustParseAddr("::ffff:192.0.2.1")); got != "1.2.0.192.in-addr.arpa." {
		t.Fatalf("mapped IPv4 reverse = %q", got)
	}
	if got := ReverseName(netip.Addr{}); got != "" {
		t.Fatalf("invalid reverse = %q, want empty", got)
	}
	for _, input := range []string{"example.com", "01.2.0.192.in-addr.arpa", "1.2.3.in-addr.arpa", "g.0.0.0.ip6.arpa", "fe80::1%eth0"} {
		if value, err := NormalizePTRName(input); err == nil {
			t.Errorf("NormalizePTRName(%q) = %q, want error", input, value)
		}
	}
}

func TestUnicodeFQDNPreservesDNSServiceLabels(t *testing.T) {
	got, err := UnicodeFQDN("_sip._tcp.xn--bcher-kva.example.")
	if err != nil {
		t.Fatalf("UnicodeFQDN: %v", err)
	}
	if got != "_sip._tcp.b\u00fccher.example." {
		t.Fatalf("UnicodeFQDN = %q", got)
	}
}
