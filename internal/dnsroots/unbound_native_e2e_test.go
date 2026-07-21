//go:build dnsroots_native_e2e

package dnsroots

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnboundAnchorNativeLifecycle(t *testing.T) {
	anchorBinary := requireNativePath(t, "NODEPING_UNBOUND_ANCHOR_BINARY")
	checkconfBinary := requireNativePath(t, "NODEPING_UNBOUND_CHECKCONF_BINARY")
	rootHintsPath := requireNativePath(t, "NODEPING_ROOT_HINTS_FILE")
	adapter, err := NewUnboundAdapter(UnboundConfig{
		AnchorBinary: anchorBinary, CheckconfBinary: checkconfBinary, RootHintsPath: rootHintsPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := manager.RefreshAnchor(ctx, adapter.Update, adapter.Validate)
	if err != nil {
		t.Fatalf("refresh real RFC 5011 state: %v", err)
	}
	if result.Snapshot.SHA256 == "" || result.Snapshot.Size == 0 || result.Snapshot.Path == "" {
		t.Fatalf("incomplete real anchor snapshot: %+v", result)
	}
	value, err := os.ReadFile(result.Snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(value)
	if !strings.Contains(text, "20326") || !strings.Contains(text, "38696") {
		t.Fatalf("real anchor state is missing current KSK tags: %s", text)
	}
	preserved, err := manager.CurrentAnchor(ctx, adapter.Validate)
	if err != nil || preserved.SHA256 != result.Snapshot.SHA256 {
		t.Fatalf("reload real anchor state = %+v, %v", preserved, err)
	}
}

func requireNativePath(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}
