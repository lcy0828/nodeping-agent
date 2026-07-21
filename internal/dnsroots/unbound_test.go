package dnsroots

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUnboundAdapterUsesFixedRootHintsAndAcceptsDocumentedExitOne(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	anchorBinary := testExecutable(t, directory, "unbound-anchor")
	checkconfBinary := testExecutable(t, directory, "unbound-checkconf")
	hintsPath := filepath.Join(directory, "named.root")
	if err := os.WriteFile(hintsPath, rootHintsFixture(3600000, false), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewUnboundAdapter(UnboundConfig{
		AnchorBinary: anchorBinary, CheckconfBinary: checkconfBinary, RootHintsPath: hintsPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(directory, "root key with spaces")
	if err := os.WriteFile(candidatePath, []byte("valid:20326\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	adapter.run = func(_ context.Context, path string, args ...string) (int, string, error) {
		calls = append(calls, append([]string{path}, args...))
		if path == anchorBinary {
			return 1, "anchor initialized", errors.New("exit status 1")
		}
		configBytes, readErr := os.ReadFile(args[len(args)-1])
		if readErr != nil {
			return -1, "", readErr
		}
		if !strings.Contains(string(configBytes), `auto-trust-anchor-file: "`+candidatePath+`"`) {
			t.Fatalf("validator config = %q", configBytes)
		}
		return 0, "", nil
	}
	if err := adapter.Update(context.Background(), candidatePath); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := adapter.Validate(context.Background(), candidatePath); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wantUpdate := []string{anchorBinary, "-a", candidatePath, "-r", hintsPath, "-v"}
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], wantUpdate) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestUnboundAdapterRejectsRelativeSymlinkAndInvalidCandidate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	executable := testExecutable(t, directory, "helper")
	hintsPath := filepath.Join(directory, "named.root")
	if err := os.WriteFile(hintsPath, rootHintsFixture(3600000, false), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewUnboundAdapter(UnboundConfig{AnchorBinary: "relative", CheckconfBinary: executable, RootHintsPath: hintsPath}); err == nil {
		t.Fatal("relative executable was accepted")
	}
	symlink := filepath.Join(directory, "helper-link")
	if err := os.Symlink(executable, symlink); err == nil {
		if _, err := NewUnboundAdapter(UnboundConfig{AnchorBinary: symlink, CheckconfBinary: executable, RootHintsPath: hintsPath}); err == nil {
			t.Fatal("symlink executable was accepted")
		}
	}
	adapter, err := NewUnboundAdapter(UnboundConfig{AnchorBinary: executable, CheckconfBinary: executable, RootHintsPath: hintsPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Validate(context.Background(), filepath.Join(directory, "missing.key")); err == nil {
		t.Fatal("missing candidate was accepted")
	}
}

func testExecutable(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
