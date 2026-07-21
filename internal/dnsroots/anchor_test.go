package dnsroots

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAnchorRefreshPreservesStateAcrossManagerUpgradeAndRollsBack(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	stateDir := t.TempDir()
	manager, err := NewManager(stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	validator := testAnchorValidator
	firstResult, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326\n"), validator)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if !firstResult.Updated || firstResult.WarningCode != "" {
		t.Fatalf("first result = %+v", firstResult)
	}

	upgradedManager, err := NewManager(stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	upgradedManager.now = func() time.Time { return now.Add(time.Hour) }
	preserved, err := upgradedManager.CurrentAnchor(context.Background(), validator)
	if err != nil || preserved.SHA256 != firstResult.Snapshot.SHA256 {
		t.Fatalf("upgrade preservation = %+v, %v", preserved, err)
	}
	secondResult, err := upgradedManager.RefreshAnchor(context.Background(), writeAnchor("valid:20326,38696\n"), validator)
	if err != nil || !secondResult.Updated {
		t.Fatalf("second refresh = %+v, %v", secondResult, err)
	}
	rolledBack, err := upgradedManager.RollbackAnchor(context.Background(), validator)
	if err != nil || rolledBack.SHA256 != firstResult.Snapshot.SHA256 {
		t.Fatalf("rollback = %+v, %v", rolledBack, err)
	}
}

func TestAnchorRefreshUsesLKGWhenUpdateFailsOrCandidateIsInvalid(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, nil, now)
	initial, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326\n"), testAnchorValidator)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := manager.RefreshAnchor(context.Background(), func(context.Context, string) error {
		return errors.New("network unavailable")
	}, testAnchorValidator)
	if err != nil {
		t.Fatalf("existing LKG should survive update failure: %v", err)
	}
	if failed.WarningCode != ReasonUsingLKG || failed.Warning == nil || failed.Snapshot.SHA256 != initial.Snapshot.SHA256 {
		t.Fatalf("failed update result = %+v", failed)
	}
	invalid, err := manager.RefreshAnchor(context.Background(), writeAnchor("invalid\n"), testAnchorValidator)
	if err != nil || invalid.WarningCode != ReasonUsingLKG || invalid.Snapshot.SHA256 != initial.Snapshot.SHA256 {
		t.Fatalf("invalid candidate result = %+v, %v", invalid, err)
	}
}

func TestAnchorCorruptionRecoversImmutablePreviousSnapshot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	manager := newTestManager(t, nil, now)
	first, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326\n"), testAnchorValidator)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now.Add(time.Hour) }
	second, err := manager.RefreshAnchor(context.Background(), writeAnchor("valid:20326,38696\n"), testAnchorValidator)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second.Snapshot.Path, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.anchorLivePath(), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.anchorStatePath(), []byte(`{"schema":"broken","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.CurrentAnchor(context.Background(), testAnchorValidator)
	if err != nil {
		t.Fatalf("recover previous: %v", err)
	}
	if !recovered.Recovered || recovered.SHA256 != first.Snapshot.SHA256 {
		t.Fatalf("recovered snapshot = %+v", recovered)
	}
	live, err := os.ReadFile(manager.anchorLivePath())
	if err != nil || string(live) != "valid:20326\n" {
		t.Fatalf("recovered live state = %q, %v", live, err)
	}
}

func TestAnchorRefreshFailsClosedWithoutUsableState(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, nil, time.Now().UTC())
	_, err := manager.RefreshAnchor(context.Background(), func(context.Context, string) error {
		return errors.New("initialization failed")
	}, testAnchorValidator)
	if !errors.Is(err, ErrNoUsableTrustAnchor) {
		t.Fatalf("error = %v", err)
	}
}

func writeAnchor(value string) AnchorUpdater {
	return func(_ context.Context, path string) error {
		return os.WriteFile(path, []byte(value), 0o600)
	}
}

func testAnchorValidator(_ context.Context, path string) error {
	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(value), "valid:") {
		return errors.New("invalid anchor state")
	}
	return nil
}
