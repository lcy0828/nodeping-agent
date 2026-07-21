package dnsroots

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCurrentMaterialReturnsAtomicPathFreeEvidence(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Keyring{PublicKeyID(publicKey): publicKey}, now)
	hints := rootHintsFixture(3600000, false)
	manifest := mustHintsManifest(t, "2026072001", now.Add(-time.Hour), hints, privateKey)
	wantHints, err := manager.ActivateHints(context.Background(), manifest, hints)
	if err != nil {
		t.Fatal(err)
	}
	wantAnchor, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326,38696\n"), testAnchorValidator)
	if err != nil {
		t.Fatal(err)
	}

	validatedHintsPath := ""
	snapshot, err := manager.CurrentMaterial(context.Background(), func(rootHintsPath string) (AnchorValidator, error) {
		validatedHintsPath = rootHintsPath
		return testAnchorValidator, nil
	})
	if err != nil {
		t.Fatalf("CurrentMaterial: %v", err)
	}
	if validatedHintsPath != wantHints.Path || snapshot.RootHints.SHA256 != wantHints.SHA256 ||
		snapshot.TrustAnchor.SHA256 != wantAnchor.Snapshot.SHA256 {
		t.Fatalf("material snapshot = %+v, validated hints path = %q", snapshot, validatedHintsPath)
	}

	evidence := snapshot.Evidence()
	if evidence.Schema != MaterialEvidenceSchema || evidence.RootHints.Health != ReasonReady ||
		evidence.TrustAnchor.Health != ReasonReady || evidence.RootHints.Version != wantHints.Version ||
		evidence.TrustAnchor.Version != wantAnchor.Snapshot.Version {
		t.Fatalf("material evidence = %+v", evidence)
	}
	for _, value := range []any{snapshot, evidence} {
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if strings.Contains(string(raw), manager.root) || strings.Contains(string(raw), "named.root") || strings.Contains(string(raw), "root.key") {
			t.Fatalf("serialized material leaked a local path: %s", raw)
		}
	}
}

func TestCurrentMaterialHoldsOneLockAcrossThePair(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Keyring{PublicKeyID(publicKey): publicKey}, now)
	firstHints := rootHintsFixture(3600000, false)
	firstManifest := mustHintsManifest(t, "2026072001", now.Add(-2*time.Hour), firstHints, privateKey)
	if _, err := manager.ActivateHints(context.Background(), firstManifest, firstHints); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326\n"), testAnchorValidator); err != nil {
		t.Fatal(err)
	}

	factoryEntered := make(chan struct{})
	releaseFactory := make(chan struct{})
	materialDone := make(chan error, 1)
	go func() {
		_, currentErr := manager.CurrentMaterial(context.Background(), func(string) (AnchorValidator, error) {
			close(factoryEntered)
			<-releaseFactory
			return testAnchorValidator, nil
		})
		materialDone <- currentErr
	}()
	<-factoryEntered

	secondHints := rootHintsFixture(3600001, true)
	secondManifest := mustHintsManifest(t, "2026072002", now.Add(-time.Hour), secondHints, privateKey)
	blockedCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, activationErr := manager.ActivateHints(blockedCtx, secondManifest, secondHints)
	if !errors.Is(activationErr, context.DeadlineExceeded) {
		close(releaseFactory)
		t.Fatalf("concurrent activation error = %v, want context deadline", activationErr)
	}
	close(releaseFactory)
	if err := <-materialDone; err != nil {
		t.Fatalf("CurrentMaterial: %v", err)
	}
}

func TestCurrentMaterialFailsClosedWithoutCompletePair(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Keyring{PublicKeyID(publicKey): publicKey}, now)
	hints := rootHintsFixture(3600000, false)
	manifest := mustHintsManifest(t, "2026072001", now.Add(-time.Hour), hints, privateKey)
	if _, err := manager.ActivateHints(context.Background(), manifest, hints); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CurrentMaterial(context.Background(), func(string) (AnchorValidator, error) {
		return testAnchorValidator, nil
	}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
	if _, err := manager.CurrentMaterial(context.Background(), nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil factory error = %v, want ErrNotConfigured", err)
	}
}
