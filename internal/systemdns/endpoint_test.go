package systemdns

import (
	"net/netip"
	"testing"
)

func TestParseSystemEndpointAllowsSystemRangesWithoutGrantingTrust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		zone string
	}{
		{name: "private", raw: "10.0.0.53"},
		{name: "loopback", raw: "127.0.0.53"},
		{name: "ipv4 link local", raw: "169.254.1.53"},
		{name: "ipv6 private", raw: "fd00::53"},
		{name: "ipv6 loopback", raw: "::1"},
		{name: "ipv6 link local", raw: "fe80::53%en0", zone: "en0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint, err := parseSystemEndpoint(test.raw, "")
			if err != nil {
				t.Fatalf("parseSystemEndpoint() error = %v", err)
			}
			if endpoint.Port() != 53 || endpoint.Zone() != test.zone {
				t.Fatalf("endpoint = %#v", endpoint)
			}
			if endpoint.Address().Zone() != "" {
				t.Fatalf("unscoped address leaked zone: %v", endpoint.Address())
			}
			if endpoint.IsTrustedSystem() {
				t.Fatal("text parsing unexpectedly granted native system trust")
			}
		})
	}
}

func TestParseSystemEndpointRejectsInvalidAddressOrZone(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"1.1.1.1:53",
		"0.0.0.0",
		"::",
		"224.0.0.53",
		"255.255.255.255",
		"fe80::53",
		"fe80::53%bad/zone",
		"2001:db8::53%en0",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if endpoint, err := parseSystemEndpoint(raw, ""); err == nil {
				t.Fatalf("parseSystemEndpoint(%q) = %#v, want error", raw, endpoint)
			}
		})
	}
}

func TestEndpointSeparatesDialZoneFromPublicAddress(t *testing.T) {
	t.Parallel()

	endpoint, err := sealEndpoint(Endpoint{
		address: netip.MustParseAddr("fe80::53"),
		zone:    "en0",
		port:    53,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := endpoint.DialAddress(); got != "[fe80::53%en0]:53" {
		t.Fatalf("DialAddress() = %q", got)
	}
	if got := endpoint.Address().String(); got != "fe80::53" {
		t.Fatalf("public address = %q", got)
	}
}

func TestEndpointProvenanceBindsAllDialFields(t *testing.T) {
	t.Parallel()

	endpoint, err := sealEndpoint(Endpoint{
		address: netip.MustParseAddr("fe80::53"),
		zone:    "en0",
		port:    5353,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !endpoint.IsTrustedSystem() {
		t.Fatal("sealed endpoint is not trusted")
	}
	copyOfEndpoint := endpoint
	if !copyOfEndpoint.IsTrustedSystem() {
		t.Fatal("ordinary value copy lost provenance")
	}

	tests := []struct {
		name   string
		tamper func(*Endpoint)
	}{
		{name: "address", tamper: func(value *Endpoint) { value.address = netip.MustParseAddr("fe80::54") }},
		{name: "zone", tamper: func(value *Endpoint) { value.zone = "en1" }},
		{name: "port", tamper: func(value *Endpoint) { value.port = 53 }},
		{name: "provenance", tamper: func(value *Endpoint) { value.provenance[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := endpoint
			test.tamper(&tampered)
			if tampered.IsTrustedSystem() {
				t.Fatalf("tampered endpoint retained trust: %#v", tampered)
			}
		})
	}
	if (Endpoint{}).IsTrustedSystem() {
		t.Fatal("zero endpoint is trusted")
	}
}

func TestNormalizeNameAllowsServiceLabelsAndIDNA(t *testing.T) {
	t.Parallel()

	name, err := normalizeName("_443._TCP.Bucher.example.", false)
	if err != nil {
		t.Fatalf("normalizeName() error = %v", err)
	}
	if name != "_443._tcp.bucher.example" {
		t.Fatalf("normalizeName() = %q", name)
	}
	idn, err := normalizeName("b\u00fccher.example", false)
	if err != nil || idn != "xn--bcher-kva.example" {
		t.Fatalf("normalizeName() = %q, %v", idn, err)
	}
}
