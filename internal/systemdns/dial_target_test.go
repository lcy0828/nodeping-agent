package systemdns

import (
	"net/netip"
	"testing"
)

func TestTrustedDialTargetsSealPlatformEndpointAndRouteInterface(t *testing.T) {
	tests := []struct {
		name              string
		result            func(*testing.T) DiscoveryResult
		selection         Selection
		wantPlatform      Platform
		wantAddress       netip.Addr
		wantZone          string
		wantBindInterface uint32
	}{
		{
			name: "Linux zone without route metadata", result: trustedLinuxSnapshotFixture,
			selection: Selection{Name: "example.com", Rotation: 1}, wantPlatform: PlatformLinux,
			wantAddress: netip.MustParseAddr("fe80::53"), wantZone: "eth0",
		},
		{
			name: "macOS scoped interface", result: trustedDarwinSnapshotFixture,
			selection: Selection{Name: "host.corp.example", InterfaceIndex: 4}, wantPlatform: PlatformDarwin,
			wantAddress: netip.MustParseAddr("fe80::53"), wantZone: "en4", wantBindInterface: 4,
		},
		{
			name: "Windows selected route interface", result: trustedWindowsSnapshotFixture,
			selection: Selection{Name: "example.com"}, wantPlatform: PlatformWindows,
			wantAddress: netip.MustParseAddr("fe80::53"), wantZone: "11", wantBindInterface: 11,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.result(t)
			targets, err := result.SelectTrustedDialTargets(test.selection)
			if err != nil || len(targets) == 0 {
				t.Fatalf("SelectTrustedDialTargets() = %#v, %v", targets, err)
			}
			target := targets[0]
			if !target.IsTrustedSystem() || target.Platform() != test.wantPlatform || target.Address() != test.wantAddress || target.Zone() != test.wantZone || target.Port() != 53 || target.BindInterfaceIndex() != test.wantBindInterface {
				t.Fatalf("selected target = %#v", target)
			}
		})
	}
}

func TestDialTargetProvenanceRejectsEveryDialFieldTamper(t *testing.T) {
	result := trustedDarwinSnapshotFixture(t)
	targets, err := result.SelectTrustedDialTargets(Selection{Name: "host.corp.example", InterfaceIndex: 4})
	if err != nil || len(targets) != 1 {
		t.Fatalf("SelectTrustedDialTargets() = %#v, %v", targets, err)
	}
	target := targets[0]
	tests := []struct {
		name   string
		mutate func(*DialTarget)
	}{
		{name: "endpoint address", mutate: func(value *DialTarget) { value.endpoint.address = netip.MustParseAddr("fe80::54") }},
		{name: "endpoint zone", mutate: func(value *DialTarget) { value.endpoint.zone = "en5" }},
		{name: "endpoint port", mutate: func(value *DialTarget) { value.endpoint.port = 5353 }},
		{name: "endpoint provenance", mutate: func(value *DialTarget) { value.endpoint.provenance[0] ^= 0xff }},
		{name: "platform", mutate: func(value *DialTarget) { value.platform = PlatformWindows }},
		{name: "bind interface", mutate: func(value *DialTarget) { value.bindInterfaceIndex++ }},
		{name: "target provenance", mutate: func(value *DialTarget) { value.provenance[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := target
			test.mutate(&tampered)
			if tampered.IsTrustedSystem() {
				t.Fatalf("tampered target retained trust: %#v", tampered)
			}
		})
	}
}

func TestTrustedDialTargetSelectionRejectsSnapshotTamper(t *testing.T) {
	result := trustedWindowsSnapshotFixture(t)
	result.Resolvers[0].RouteInterfaceIndex++
	if targets, err := result.SelectTrustedDialTargets(Selection{Name: "example.com"}); !IsErrorCode(err, ErrorMalformed) || targets != nil {
		t.Fatalf("tampered snapshot targets = %#v, %v", targets, err)
	}
}

func TestTrustedDialTargetUsesNativePortInsteadOfRequestMarker(t *testing.T) {
	result, err := ParseSCUtilDNS([]byte(`
resolver #1
  nameserver[0] : 10.0.0.53
  port : 5353
  order : 100000
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := sealDiscoveryResult(&result); err != nil {
		t.Fatal(err)
	}
	targets, err := result.SelectTrustedDialTargets(Selection{Name: "example.com"})
	if err != nil || len(targets) != 1 {
		t.Fatalf("SelectTrustedDialTargets() = %#v, %v", targets, err)
	}
	if targets[0].Port() != 5353 || targets[0].DialAddress() != "10.0.0.53:5353" {
		t.Fatalf("native target port was not retained: port=%d address=%q", targets[0].Port(), targets[0].DialAddress())
	}
}

func TestDialTargetRejectsMissingRequiredRouteInterface(t *testing.T) {
	result := trustedWindowsSnapshotFixture(t)
	resolver := result.Resolvers[0]
	resolver.RouteInterfaceIndex = 0
	if target, err := newDialTarget(PlatformWindows, resolver); err == nil || target.IsTrustedSystem() {
		t.Fatalf("Windows target without route interface = %#v, %v", target, err)
	}

	darwin := trustedDarwinSnapshotFixture(t).Resolvers[1]
	darwin.InterfaceIndex = 0
	if target, err := newDialTarget(PlatformDarwin, darwin); err == nil || target.IsTrustedSystem() {
		t.Fatalf("scoped macOS target without interface = %#v, %v", target, err)
	}
}
