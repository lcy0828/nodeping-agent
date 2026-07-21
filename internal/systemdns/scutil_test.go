package systemdns

import (
	"strings"
	"testing"
)

const scutilFixture = `DNS configuration

resolver #1
  search domain[1] : second.example
  search domain[0] : first.example
  nameserver[1] : 9.9.9.9
  nameserver[0] : 1.1.1.1
  nameserver[2] : 1.1.1.1
  flags    : Request A records, Request AAAA records
  order    : 200000

resolver #2
  domain   : corp.example
  nameserver[0] : 10.0.0.1
  if_index : 4 (en4)
  flags    : Scoped, Request A records
  order    : 300000

resolver #3
  domain   : corp.example
  nameserver[0] : 10.0.0.2
  if_index : 5 (en5)
  flags    : Scoped
  order    : 100000

DNS configuration (for scoped queries)

resolver #1
  domain   : dev.corp.example
  nameserver[0] : fe80::53
  if_index : 7 (en7)
  flags    : Scoped, Request A records, Request AAAA records
  order    : 400000
`

func TestParseSCUtilDNSPreservesBlocksAndSelectsLongestSuffix(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(scutilFixture))
	if err != nil {
		t.Fatalf("ParseSCUtilDNS() error = %v", err)
	}
	if len(result.Resolvers) != 5 {
		t.Fatalf("resolver count = %d", len(result.Resolvers))
	}
	if got := result.Resolvers[0].Endpoint.Address().String(); got != "1.1.1.1" {
		t.Fatalf("first indexed nameserver = %q", got)
	}
	if got := result.Resolvers[1].Endpoint.Address().String(); got != "9.9.9.9" {
		t.Fatalf("second indexed nameserver = %q", got)
	}
	assertStrings(t, result.SearchDomains, []string{"first.example", "second.example"})
	assertStrings(t, result.Resolvers[0].Flags, []string{"Request A records", "Request AAAA records"})

	corp, err := result.ResolversForName("host.corp.example")
	if err != nil {
		t.Fatalf("ResolversForName(corp) error = %v", err)
	}
	if len(corp) != 2 || corp[0].Endpoint.Address().String() != "10.0.0.2" || corp[1].Endpoint.Address().String() != "10.0.0.1" {
		t.Fatalf("corp resolver order = %v", resolverAddresses(corp))
	}

	deep, err := result.ResolversForName("host.dev.corp.example")
	if err != nil {
		t.Fatalf("ResolversForName(deep) error = %v", err)
	}
	if len(deep) != 1 || deep[0].Endpoint.Zone() != "en7" || deep[0].InterfaceIndex != 7 {
		t.Fatalf("deep resolver = %#v", deep)
	}
	if got := deep[0].Endpoint.DialAddress(); got != "[fe80::53%en7]:53" {
		t.Fatalf("deep dial address = %q", got)
	}
	trusted := result
	if err := sealDiscoveryResult(&trusted); err != nil {
		t.Fatal(err)
	}
	trustedDeep, err := trusted.SelectTrusted(Selection{Name: "host.dev.corp.example"})
	if err != nil {
		t.Fatalf("SelectTrusted(deep) error = %v", err)
	}
	if len(trustedDeep) != 1 || trustedDeep[0].Endpoint.Zone() != "en7" || !trustedDeep[0].Endpoint.IsTrustedSystem() {
		t.Fatalf("trusted macOS suffix/zone = %#v", trustedDeep)
	}

	public, err := result.ResolversForName("example.net")
	if err != nil {
		t.Fatalf("ResolversForName(default) error = %v", err)
	}
	if len(public) != 2 || public[0].Endpoint.Address().String() != "1.1.1.1" || public[1].Endpoint.Address().String() != "9.9.9.9" {
		t.Fatalf("default resolver order = %v", resolverAddresses(public))
	}
}

func TestParseSCUtilDNSPreservesResolverPortAndTimeout(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 10.0.0.17
  port : 5354
  timeout : 60

resolver #2
  nameserver[0] : 10.0.0.18.5300
  port : 5354
  timeout : 0

resolver #3
  nameserver[0] : 2001:db8::53.5301
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Resolvers[0].Endpoint.DialAddress(); got != "10.0.0.17:5354" {
		t.Fatalf("resolver-level port = %q", got)
	}
	first := result.Resolvers[0]
	if first.ConfiguredTimeoutSeconds != 60 || first.TimeoutSeconds != 30 || !first.TimeoutConfigured {
		t.Fatalf("first timeout = %#v", first)
	}
	if got := result.Resolvers[1].Endpoint.DialAddress(); got != "10.0.0.18:5300" {
		t.Fatalf("nameserver-level port override = %q", got)
	}
	second := result.Resolvers[1]
	if second.ConfiguredTimeoutSeconds != 0 || second.TimeoutSeconds != 1 || !second.TimeoutConfigured {
		t.Fatalf("second timeout = %#v", second)
	}
	if got := result.Resolvers[2].Endpoint.DialAddress(); got != "[2001:db8::53]:5301" {
		t.Fatalf("IPv6 dotted port = %q", got)
	}
	for _, resolver := range result.Resolvers {
		if resolver.Endpoint.IsTrustedSystem() {
			t.Fatal("public scutil parser granted native trust")
		}
	}
}

func TestSCUtilUnsupportedRouteNeverFallsBackToDefault(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 192.0.2.53

resolver #2
  domain : local
  options : mdns
  timeout : 5
  order : 300000
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.UnsupportedRoutes) != 1 || result.UnsupportedRoutes[0].ScopeDomain != "local" {
		t.Fatalf("unsupported routes = %#v", result.UnsupportedRoutes)
	}
	if _, err := result.ResolversForName("printer.local"); !IsErrorCode(err, ErrorUnsupported) {
		t.Fatalf("local selection error = %v", err)
	}
	selected, err := result.ResolversForName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Endpoint.DialAddress() != "192.0.2.53:53" {
		t.Fatalf("default selection = %v", resolverAddresses(selected))
	}
}

func TestSCUtilUnsupportedScopedRouteHonorsInterface(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 192.0.2.53

resolver #2
  domain : corp.example
  if_index : 4 (en4)
  flags : Scoped
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Select(Selection{Name: "host.corp.example", InterfaceIndex: 4}); !IsErrorCode(err, ErrorUnsupported) {
		t.Fatalf("matching interface error = %v", err)
	}
	selected, err := result.Select(Selection{Name: "host.corp.example", InterfaceIndex: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Endpoint.DialAddress() != "192.0.2.53:53" {
		t.Fatalf("other interface selection = %v", resolverAddresses(selected))
	}
}

func TestSCUtilSuffixMatchingUsesLabelBoundary(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(scutilFixture))
	if err != nil {
		t.Fatal(err)
	}
	resolvers, err := result.ResolversForName("host.notcorp.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvers) != 2 || resolvers[0].ScopeDomain != "" {
		t.Fatalf("boundary match selected scoped resolver: %#v", resolvers)
	}
}

func TestSCUtilSelectionHonorsRequestedInterface(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(scutilFixture))
	if err != nil {
		t.Fatal(err)
	}
	resolvers, err := result.Select(Selection{Name: "host.corp.example", InterfaceIndex: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvers) != 1 || resolvers[0].InterfaceIndex != 4 {
		t.Fatalf("interface-scoped resolvers = %#v", resolvers)
	}
}

func TestSCUtilSelectionPrefersInterfaceOnlyScopedResolver(t *testing.T) {
	t.Parallel()

	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 192.168.1.53
  if_index : 14 (en0)
  flags : Request A records

resolver #2
  nameserver[0] : 192.168.1.53
  if_index : 14 (en0)
  flags : Scoped, Request A records
`))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := result.Select(Selection{Name: "public.example", InterfaceIndex: 14})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || !selected[0].Scoped {
		t.Fatalf("selected resolvers = %#v", selected)
	}
}

func TestParseSCUtilDNSRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []string{
		"resolver #1\n nameserver[0] : nope\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n nameserver[0] : 8.8.8.8\n",
		"resolver #1\n nameserver[x] : 1.1.1.1\n",
		"resolver #1\n nameserver[0] 1.1.1.1\n",
		"resolver #1\n nameserver[0] : fe80::53\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n order : no\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n if_index : 0 (en0)\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n flags : Scoped, Scoped\n",
		"resolver #x\n nameserver[0] : 1.1.1.1\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\x00\n",
		"resolver #1\n nameserver[0] : fe80::53%en1\n if_index : 1 (en0)\n",
		"resolver #1\n nameserver[0] : fe80::53%en0.5353\n if_index : 1 (en0)\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n port : 0\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n port : 65536\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n timeout : nope\n",
		"resolver #1\n nameserver[0] : 1.1.1.1\n flags : Scoped\n",
		"nameserver[0] : 1.1.1.1\nresolver #1\nnameserver[0] : 8.8.8.8\n",
	}
	for _, input := range tests {
		input := input
		t.Run(strings.ReplaceAll(input, "\n", "_"), func(t *testing.T) {
			t.Parallel()
			_, err := ParseSCUtilDNS([]byte(input))
			if !IsErrorCode(err, ErrorMalformed) {
				t.Fatalf("error = %v, want malformed", err)
			}
		})
	}
}

func TestParseSCUtilDNSRejectsOversizeAndTooManyBlocks(t *testing.T) {
	t.Parallel()

	limits, err := normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	limits.MaxInputBytes = 32
	limits.MaxLineBytes = 32
	if _, err := parseSCUtilDNS([]byte(strings.Repeat("x", 33)), limits); !IsErrorCode(err, ErrorTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}

	limits, err = normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	limits.MaxResolverBlocks = 1
	_, err = parseSCUtilDNS([]byte("resolver #1\nnameserver[0] : 1.1.1.1\nresolver #2\nnameserver[0] : 8.8.8.8\n"), limits)
	if !IsErrorCode(err, ErrorTooMany) {
		t.Fatalf("too-many error = %v", err)
	}
}

func resolverAddresses(resolvers []Resolver) []string {
	addresses := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		addresses = append(addresses, resolver.Endpoint.DialAddress())
	}
	return addresses
}
