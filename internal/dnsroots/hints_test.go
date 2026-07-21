package dnsroots

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var rootIPv4 = []string{
	"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
	"193.0.14.129", "199.7.83.42", "202.12.27.33",
}

var rootIPv6 = []string{
	"2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d",
	"2001:500:a8::e", "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53",
	"2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1", "2001:500:9f::42", "2001:dc3::35",
}

func TestParseRootHintsAcceptsCanonicalMaterialIndependentOfRecordOrder(t *testing.T) {
	t.Parallel()
	for _, glueFirst := range []bool{false, true} {
		summary, err := ParseRootHints(rootHintsFixture(3600000, glueFirst))
		if err != nil {
			t.Fatalf("ParseRootHints(glueFirst=%v): %v", glueFirst, err)
		}
		if summary != (HintsSummary{RootServerCount: 13, IPv4Count: 13, IPv6Count: 13}) {
			t.Fatalf("summary = %+v", summary)
		}
	}
}

func TestParseRootHintsRejectsIncompleteOrUnrelatedRecords(t *testing.T) {
	t.Parallel()
	valid := string(rootHintsFixture(3600000, false))
	tests := map[string]string{
		"missing IPv6": strings.Replace(valid, "m.root-servers.net. 3600000 IN AAAA 2001:dc3::35\n", "", 1),
		"unrelated":    valid + "example. 3600000 IN A 1.1.1.1\n",
		"duplicate NS": valid + ". 3600000 IN NS a.root-servers.net.\n",
		"private glue": strings.Replace(valid, "198.41.0.4", "10.0.0.1", 1),
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseRootHints([]byte(value)); !errors.Is(err, ErrInvalidHints) {
				t.Fatalf("error = %v, want ErrInvalidHints", err)
			}
		})
	}
}

func TestHintsManifestRejectsTamperingAndUnknownKey(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	hints := rootHintsFixture(3600000, false)
	manifest, err := NewHintsManifest("2026052101", now, hints, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := Keyring{PublicKeyID(publicKey): publicKey}
	if _, _, err := VerifyHintsManifest(manifest, hints, keys, now); err != nil {
		t.Fatalf("verify valid manifest: %v", err)
	}
	tampered := append([]byte(nil), hints...)
	tampered[len(tampered)-2] ^= 1
	if _, _, err := VerifyHintsManifest(manifest, tampered, keys, now); !errors.Is(err, ErrInvalidHints) {
		t.Fatalf("tampered hints error = %v", err)
	}
	if _, _, err := VerifyHintsManifest(manifest, hints, Keyring{}, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unknown key error = %v", err)
	}
	manifest.Signature = strings.Repeat("A", 88)
	if _, _, err := VerifyHintsManifest(manifest, hints, keys, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestParseKeyringDerivesIDsAndRejectsDuplicates(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(publicKey)
	keyring, err := ParseKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyring) != 1 || keyring[PublicKeyID(publicKey)] == nil {
		t.Fatalf("keyring = %+v", keyring)
	}
	if _, err := ParseKeyring(encoded + "," + encoded); err == nil {
		t.Fatal("duplicate key was accepted")
	}
}

func TestHintsStoreRotationRollbackReplayAndCorruptionRecovery(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Keyring{PublicKeyID(publicKey): publicKey}, now)
	hints1 := rootHintsFixture(3600000, false)
	hints2 := rootHintsFixture(3600001, true)
	manifest1 := mustHintsManifest(t, "2026052101", now.Add(-2*time.Hour), hints1, privateKey)
	manifest2 := mustHintsManifest(t, "2026072001", now.Add(-time.Hour), hints2, privateKey)

	first, err := manager.ActivateHints(context.Background(), manifest1, hints1)
	if err != nil {
		t.Fatalf("activate first: %v", err)
	}
	second, err := manager.ActivateHints(context.Background(), manifest2, hints2)
	if err != nil {
		t.Fatalf("activate second: %v", err)
	}
	if first.SHA256 == second.SHA256 || second.Version != "2026072001" {
		t.Fatalf("rotation did not change snapshot: first=%+v second=%+v", first, second)
	}
	if _, err := manager.ActivateHints(context.Background(), manifest1, hints1); !errors.Is(err, ErrStaleHints) {
		t.Fatalf("replay error = %v", err)
	}

	rolledBack, err := manager.RollbackHints(context.Background())
	if err != nil || rolledBack.SHA256 != first.SHA256 {
		t.Fatalf("rollback = %+v, %v", rolledBack, err)
	}
	rolledForward, err := manager.RollbackHints(context.Background())
	if err != nil || rolledForward.SHA256 != second.SHA256 {
		t.Fatalf("second rollback = %+v, %v", rolledForward, err)
	}
	if err := os.WriteFile(second.Path, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.CurrentHints(context.Background())
	if err != nil {
		t.Fatalf("recover previous: %v", err)
	}
	if !recovered.Recovered || recovered.SHA256 != first.SHA256 {
		t.Fatalf("recovered snapshot = %+v", recovered)
	}
	encoded, err := json.Marshal(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), manager.root) || strings.Contains(string(encoded), "named.root") {
		t.Fatalf("public snapshot leaked local path: %s", encoded)
	}
}

func TestHintsStoreRebuildsCorruptStateFromSignedImmutableMaterial(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Keyring{PublicKeyID(publicKey): publicKey}, now)
	hints := rootHintsFixture(3600000, false)
	manifest := mustHintsManifest(t, "2026052101", now.Add(-time.Hour), hints, privateKey)
	want, err := manager.ActivateHints(context.Background(), manifest, hints)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.root+"/hints/state.json", []byte(`{"schema":"broken","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := manager.CurrentHints(context.Background())
	if err != nil {
		t.Fatalf("recover corrupt state: %v", err)
	}
	if !got.Recovered || got.SHA256 != want.SHA256 {
		t.Fatalf("recovered snapshot = %+v, want hash %s", got, want.SHA256)
	}
}

func newTestManager(t *testing.T, keys Keyring, now time.Time) *Manager {
	t.Helper()
	manager, err := NewManager(t.TempDir(), keys)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	return manager
}

func mustHintsManifest(t *testing.T, version string, publishedAt time.Time, hints []byte, key ed25519.PrivateKey) HintsManifest {
	t.Helper()
	manifest, err := NewHintsManifest(version, publishedAt, hints, key)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func rootHintsFixture(ttl uint32, glueFirst bool) []byte {
	var names strings.Builder
	var glue strings.Builder
	for index := 0; index < RootServerCount; index++ {
		letter := byte('a' + index)
		name := fmt.Sprintf("%c.root-servers.net.", letter)
		fmt.Fprintf(&names, ". %d IN NS %s\n", ttl, name)
		fmt.Fprintf(&glue, "%s %d IN A %s\n", name, ttl, rootIPv4[index])
		fmt.Fprintf(&glue, "%s %d IN AAAA %s\n", name, ttl, rootIPv6[index])
	}
	if glueFirst {
		return []byte(glue.String() + names.String())
	}
	return []byte(names.String() + glue.String())
}
