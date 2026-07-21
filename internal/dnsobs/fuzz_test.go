package dnsobs

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzNormalizeFQDNIdempotent(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"b\u00fccher.example",
		"www\u3002example.com.",
		".",
		"_sip._tcp.example.com",
		"example..com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		normalized, err := NormalizeFQDN(input)
		if err != nil {
			return
		}
		if !utf8.ValidString(normalized) || len(normalized) > 255 || !strings.HasSuffix(normalized, ".") {
			t.Fatalf("invalid normalized FQDN %q", normalized)
		}
		again, err := NormalizeFQDN(normalized)
		if err != nil || again != normalized {
			t.Fatalf("normalization is not idempotent: %q -> %q, %v", normalized, again, err)
		}
	})
}

func FuzzFingerprintRRSetPermutationInvariant(f *testing.F) {
	f.Add("first", "second")
	f.Add("192.0.2.1", "192.0.2.2")
	f.Add("\"MiXeD Case\"", "\"value\"")
	f.Fuzz(func(t *testing.T, left, right string) {
		if left == "" || right == "" || !utf8.ValidString(left) || !utf8.ValidString(right) || len(left) > MaxRDataBytes || len(right) > MaxRDataBytes {
			return
		}
		leftCanonical := canonicalTXTForDNSObsTest(t, left)
		rightCanonical := canonicalTXTForDNSObsTest(t, right)
		if len(leftCanonical) > MaxRDataBytes || len(rightCanonical) > MaxRDataBytes {
			return
		}
		first, err := FingerprintRRSet("example.com.", RRTypeTXT, DNSClassIN, []string{leftCanonical, rightCanonical, leftCanonical})
		if err != nil {
			t.Fatalf("fingerprint first ordering: %v", err)
		}
		second, err := FingerprintRRSet("EXAMPLE.COM", RRTypeTXT, DNSClassIN, []string{rightCanonical, leftCanonical})
		if err != nil {
			t.Fatalf("fingerprint second ordering: %v", err)
		}
		if first != second {
			t.Fatalf("order or duplicate changed fingerprint: %q != %q", first, second)
		}
	})
}

func FuzzNormalizeObservationJSON(f *testing.F) {
	seed, err := json.Marshal(validObservation())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema":"dns-observation/v1"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxObservationBytes*2 {
			return
		}
		var observation Observation
		if err := json.Unmarshal(raw, &observation); err != nil {
			return
		}
		normalized, err := NormalizeObservation(observation)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(normalized)
		if err != nil {
			t.Fatalf("marshal normalized observation: %v", err)
		}
		if len(encoded) > MaxObservationBytes {
			t.Fatalf("normalized observation is %d bytes, limit %d", len(encoded), MaxObservationBytes)
		}
		again, err := NormalizeObservation(normalized)
		if err != nil {
			t.Fatalf("renormalize accepted observation: %v", err)
		}
		if !reflect.DeepEqual(normalized, again) {
			t.Fatal("observation normalization is not idempotent")
		}
	})
}
