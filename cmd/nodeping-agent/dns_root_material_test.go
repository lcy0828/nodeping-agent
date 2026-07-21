package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodeping/internal/dnsroots"
)

func TestNextDNSRootMaterialRefreshUsesBeijingTenWithStableJitter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	first := nextDNSRootMaterialRefresh(now, "agent-a")
	second := nextDNSRootMaterialRefresh(now, "agent-a")
	if !first.Equal(second) {
		t.Fatalf("jitter changed: %s != %s", first, second)
	}
	windowStart := time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC)
	if first.Before(windowStart) || !first.Before(windowStart.Add(dnsRootRefreshJitterWindow)) {
		t.Fatalf("refresh %s is outside Beijing 10:00 jitter window", first)
	}
	nextDay := nextDNSRootMaterialRefresh(first, "agent-a")
	if !nextDay.Equal(first.Add(24 * time.Hour)) {
		t.Fatalf("next day refresh = %s, want %s", nextDay, first.Add(24*time.Hour))
	}
}

func TestDNSRootMaterialConfigurationFailsClosedWhenPartial(t *testing.T) {
	t.Parallel()
	if dnsRootMaterialHasAnyConfig(config{}) || dnsRootMaterialConfigComplete(config{}) {
		t.Fatal("empty configuration was treated as configured")
	}
	partial := config{DNSRootStateDir: t.TempDir(), DNSRootHintsFile: "named.root"}
	if !dnsRootMaterialHasAnyConfig(partial) || dnsRootMaterialConfigComplete(partial) {
		t.Fatal("partial configuration did not fail closed")
	}
	hints, anchor := collectDNSRootMaterialReadiness(context.Background(), partial)
	if hints.Ready || anchor.Ready || hints.ReasonCode != dnsroots.ReasonMaterialInvalid || anchor.ReasonCode != dnsroots.ReasonMaterialInvalid {
		t.Fatalf("partial readiness = hints=%+v anchor=%+v", hints, anchor)
	}
}

func TestDNSRootMaterialReadinessReportsOnlyVersionAndHash(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("a", 64)
	hints := rootHintsReadiness(dnsroots.HintsSnapshot{
		Version: "2026052101", SHA256: hash, Path: "/private/named.root", Recovered: true,
	})
	anchor := trustAnchorReadiness(dnsroots.AnchorSnapshot{
		Version: "rfc5011-a", SHA256: hash, Path: "/private/root.key",
	})
	if !hints.Ready || hints.ReasonCode != dnsroots.ReasonUsingLKG || hints.Version != "2026052101" || hints.SHA256 != hash {
		t.Fatalf("hints readiness = %+v", hints)
	}
	if !anchor.Ready || anchor.ReasonCode != dnsroots.ReasonReady || anchor.Version != "rfc5011-a" || anchor.SHA256 != hash {
		t.Fatalf("anchor readiness = %+v", anchor)
	}
	if strings.Contains(hints.Version+hints.SHA256+anchor.Version+anchor.SHA256, "/private") {
		t.Fatal("readiness leaked a local path")
	}
}

func TestDNSRootMaterialErrorsMapToAllowlistedReasons(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want string
	}{
		{dnsroots.ErrNotConfigured, doctorDNSReasonNotConfigured},
		{dnsroots.ErrInvalidSignature, dnsroots.ReasonSignatureInvalid},
		{context.DeadlineExceeded, dnsroots.ReasonLockUnavailable},
		{errors.New("private /var/lib/path"), dnsroots.ReasonMaterialInvalid},
	}
	for _, test := range tests {
		got := dnsRootMaterialErrorReadiness(test.err)
		if got.Ready || got.ReasonCode != test.want {
			t.Fatalf("error %v mapped to %+v, want %s", test.err, got, test.want)
		}
	}
}

func TestConfiguredRootHintsKeepsNewerLKGAcrossCandidateDowngrade(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	stateDir := t.TempDir()
	manager, err := dnsroots.NewManager(stateDir, dnsroots.Keyring{dnsroots.PublicKeyID(publicKey): publicKey})
	if err != nil {
		t.Fatal(err)
	}
	newerHints := agentRootHintsFixture(3600001)
	newerManifest, err := dnsroots.NewHintsManifest("newer", now.Add(-time.Hour), newerHints, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := manager.ActivateHints(context.Background(), newerManifest, newerHints)
	if err != nil {
		t.Fatal(err)
	}
	olderHints := agentRootHintsFixture(3600000)
	olderManifest, err := dnsroots.NewHintsManifest("older", now.Add(-2*time.Hour), olderHints, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	hintsPath := filepath.Join(directory, "named.root")
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(hintsPath, olderHints, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(olderManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		DNSRootHintsFile:  hintsPath,
		DNSRootManifest:   manifestPath,
		DNSRootPublicKeys: base64.StdEncoding.EncodeToString(publicKey),
	}
	got, warning, err := activateConfiguredRootHints(context.Background(), manager, cfg)
	if err != nil || !errors.Is(warning, dnsroots.ErrStaleHints) {
		t.Fatalf("fallback result = %+v, warning=%v err=%v", got, warning, err)
	}
	if !got.Recovered || got.SHA256 != newer.SHA256 {
		t.Fatalf("fallback snapshot = %+v, want newer %s", got, newer.SHA256)
	}
}

func agentRootHintsFixture(ttl uint32) []byte {
	ipv4 := []string{
		"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
		"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
		"193.0.14.129", "199.7.83.42", "202.12.27.33",
	}
	ipv6 := []string{
		"2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d",
		"2001:500:a8::e", "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53",
		"2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1", "2001:500:9f::42", "2001:dc3::35",
	}
	var builder strings.Builder
	for index := 0; index < dnsroots.RootServerCount; index++ {
		name := fmt.Sprintf("%c.root-servers.net.", byte('a'+index))
		fmt.Fprintf(&builder, ". %d IN NS %s\n", ttl, name)
		fmt.Fprintf(&builder, "%s %d IN A %s\n", name, ttl, ipv4[index])
		fmt.Fprintf(&builder, "%s %d IN AAAA %s\n", name, ttl, ipv6[index])
	}
	return []byte(builder.String())
}
