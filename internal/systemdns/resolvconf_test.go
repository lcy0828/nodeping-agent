package systemdns

import (
	"strings"
	"testing"
)

func TestParseResolvConfPreservesOrderOptionsAndZones(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte(`
# managed by the operating system
nameserver 127.0.0.53
nameserver fe80::53%eth0
nameserver 127.0.0.53 ; duplicate
domain ignored.example
search Example.COM buecher.example example.com.
options rotate timeout:7 attempts:4 unknown-option
`))
	if err != nil {
		t.Fatalf("ParseResolvConf() error = %v", err)
	}
	if len(result.Resolvers) != 3 {
		t.Fatalf("resolver count = %d", len(result.Resolvers))
	}
	if got := result.Resolvers[0].Endpoint.Address().String(); got != "127.0.0.53" {
		t.Fatalf("first resolver = %q", got)
	}
	if got := result.Resolvers[1].Endpoint.Zone(); got != "eth0" {
		t.Fatalf("IPv6 zone = %q", got)
	}
	if got := result.Resolvers[2].Endpoint.Address().String(); got != "127.0.0.53" {
		t.Fatalf("duplicate slot = %q", got)
	}
	if result.Domain != "" {
		t.Fatalf("domain = %q, want cleared by search", result.Domain)
	}
	wantSearch := []string{"example.com", "buecher.example"}
	assertStrings(t, result.SearchDomains, wantSearch)
	assertStrings(t, result.Resolvers[0].SearchDomains, wantSearch)
	if !result.Options.Rotate || result.Options.TimeoutSeconds != 7 || result.Options.ConfiguredTimeoutSeconds != 7 || !result.Options.TimeoutConfigured || result.Options.Attempts != 4 || result.Options.ConfiguredAttempts != 4 || !result.Options.AttemptsConfigured {
		t.Fatalf("options = %#v", result.Options)
	}
	rotated, err := result.Select(Selection{Name: "www.example.com", Rotation: 1})
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if len(rotated) != 3 || rotated[0].Endpoint.Address().String() != "fe80::53" {
		got := rotated[0].Endpoint.Address().String()
		t.Fatalf("rotated first resolver = %q", got)
	}
	if got := result.Resolvers[0].Endpoint.Address().String(); got != "127.0.0.53" {
		t.Fatalf("Select mutated discovery order: %q", got)
	}
	trusted := result
	if err := sealDiscoveryResult(&trusted); err != nil {
		t.Fatal(err)
	}
	trustedRotated, err := trusted.SelectTrusted(Selection{Name: "www.example.com", Rotation: 1})
	if err != nil {
		t.Fatalf("SelectTrusted() error = %v", err)
	}
	if trustedRotated[0].Endpoint.Address().String() != "fe80::53" || trustedRotated[0].Endpoint.Zone() != "eth0" || !trustedRotated[0].Endpoint.IsTrustedSystem() {
		t.Fatalf("trusted Linux rotation/zone = %#v", trustedRotated[0])
	}
}

func TestParseResolvConfLastDomainDirectiveWins(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("nameserver 10.0.0.53\nsearch one.example two.example\ndomain final.example\n"))
	if err != nil {
		t.Fatalf("ParseResolvConf() error = %v", err)
	}
	if result.Domain != "final.example" || len(result.SearchDomains) != 0 {
		t.Fatalf("domain/search = %q/%v", result.Domain, result.SearchDomains)
	}
	assertStrings(t, result.Resolvers[0].SearchDomains, []string{"final.example"})
}

func TestParseResolvConfAcceptsRootSearchDomain(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("nameserver 127.0.0.53\nsearch .\n"))
	if err != nil {
		t.Fatalf("ParseResolvConf() error = %v", err)
	}
	assertStrings(t, result.SearchDomains, []string{"."})
}

func TestParseResolvConfRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []string{
		"nameserver\n",
		"nameserver dns.example\n",
		"nameserver 1.1.1.1:53\n",
		"nameserver fe80::53\n",
		"nameserver 1.1.1.1 extra\n",
		"nameserver 1.1.1.1\nsearch\n",
		"nameserver 1.1.1.1\ndomain bad..example\n",
		"nameserver 1.1.1.1\noptions timeout:nope\n",
		"nameserver 1.1.1.1\noptions attempts:4294967296\n",
		"nameserver 1.1.1.1\x00\n",
		"nameserver 1.1.1.1\n\xff\n",
	}
	for _, input := range tests {
		input := input
		t.Run(strings.ReplaceAll(input, "\n", "_"), func(t *testing.T) {
			t.Parallel()
			_, err := ParseResolvConf([]byte(input))
			if !IsErrorCode(err, ErrorMalformed) {
				t.Fatalf("error = %v, want malformed", err)
			}
		})
	}
}

func TestParseResolvConfPreservesRawClampedOptions(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("nameserver 1.1.1.1\noptions timeout:60 attempts:0\n"))
	if err != nil {
		t.Fatal(err)
	}
	options := result.Options
	if options.ConfiguredTimeoutSeconds != 60 || options.TimeoutSeconds != 30 || options.ConfiguredAttempts != 0 || options.Attempts != 1 {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseResolvConfRejectsOversizeAndTooMany(t *testing.T) {
	t.Parallel()

	limits, err := normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	limits.MaxInputBytes = 32
	limits.MaxLineBytes = 32
	if _, err := parseResolvConf([]byte(strings.Repeat("#", 33)), limits); !IsErrorCode(err, ErrorTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}

	limits, err = normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	limits.MaxResolvers = 1
	_, err = parseResolvConf([]byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), limits)
	if !IsErrorCode(err, ErrorTooMany) {
		t.Fatalf("too-many error = %v", err)
	}

	limits, err = normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	limits.MaxLines = 1
	_, err = parseResolvConf([]byte("nameserver 1.1.1.1\n\n"), limits)
	if !IsErrorCode(err, ErrorTooMany) {
		t.Fatalf("line-count error = %v", err)
	}
}

func TestParseResolvConfDefaultsToLocalResolver(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("search example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolvers) != 1 || result.Resolvers[0].Endpoint.DialAddress() != "127.0.0.1:53" {
		t.Fatalf("default resolvers = %v", resolverAddresses(result.Resolvers))
	}
	if result.Resolvers[0].Endpoint.IsTrustedSystem() {
		t.Fatal("public parser granted native trust")
	}
}

func TestParseResolvConfUsesExactlyThreeEffectiveSlots(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("nameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver invalid extra fields\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolvers) != 3 {
		t.Fatalf("resolver slots = %d", len(result.Resolvers))
	}
	assertStrings(t, resolverAddresses(result.Resolvers), []string{"1.1.1.1:53", "1.1.1.1:53", "8.8.8.8:53"})
	selected, err := result.ResolversForName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertStrings(t, resolverAddresses(selected), []string{"1.1.1.1:53", "1.1.1.1:53", "8.8.8.8:53"})
}

func assertStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("values = %v, want %v", got, want)
		}
	}
}
