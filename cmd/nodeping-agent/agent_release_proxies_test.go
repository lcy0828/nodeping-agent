package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPersistAgentReleaseProxiesOrdersAndNormalizesCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-proxies.tsv")
	err := persistAgentReleaseProxies(path, []agentReleaseProxy{
		{ID: 2, Name: "LLKK", BaseURL: "HTTPS://gh.llkk.cc", Mode: "full_url", Priority: 100},
		{ID: 1, Name: "GHFast", BaseURL: "https://ghfast.top/", Mode: "query", QueryParam: "q", Priority: 200},
	})
	if err != nil {
		t.Fatalf("persistAgentReleaseProxies() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	want := "1\tquery\thttps://ghfast.top/\tq\n2\tfull_url\thttps://gh.llkk.cc/\t\n"
	if string(raw) != want {
		t.Fatalf("catalog = %q, want %q", string(raw), want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestPersistAgentReleaseProxiesRejectsInvalidCatalogWithoutReplacingLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-proxies.tsv")
	if err := os.WriteFile(path, []byte("last-good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := persistAgentReleaseProxies(path, []agentReleaseProxy{{
		ID: 1, Name: "Invalid", BaseURL: "http://proxy.example/", Mode: "full_url", Priority: 100,
	}})
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("error = %v, want HTTPS validation error", err)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != "last-good\n" {
		t.Fatalf("last-good catalog was replaced: %q", string(raw))
	}
}

func TestPersistAgentReleaseProxiesRejectsLoopbackHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-proxies.tsv")
	if err := os.WriteFile(path, []byte("last-good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := persistAgentReleaseProxies(path, []agentReleaseProxy{{
		ID: 1, Name: "Local", BaseURL: "http://127.0.0.1:8080/", Mode: "full_url", Priority: 100,
	}})
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("error = %v, want HTTPS validation error", err)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != "last-good\n" {
		t.Fatalf("last-good catalog was replaced: %q", string(raw))
	}
}

func TestPersistAgentReleaseProxiesAllowsEmptyCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-proxies.tsv")
	if err := persistAgentReleaseProxies(path, []agentReleaseProxy{}); err != nil {
		t.Fatalf("persistAgentReleaseProxies() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatalf("catalog = %q, want empty", string(raw))
	}
}

func TestPersistAgentReleaseProxiesKeepsTopPriorityEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release-proxies.tsv")
	proxies := make([]agentReleaseProxy, 0, maxAgentReleaseProxies+1)
	for id := int64(1); id <= maxAgentReleaseProxies+1; id++ {
		proxies = append(proxies, agentReleaseProxy{
			ID:       id,
			Name:     "Proxy",
			BaseURL:  "https://proxy.example/",
			Mode:     "full_url",
			Priority: int(id),
		})
	}
	if err := persistAgentReleaseProxies(path, proxies); err != nil {
		t.Fatalf("persistAgentReleaseProxies() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if got := len(lines); got != maxAgentReleaseProxies {
		t.Fatalf("catalog line count = %d, want %d", got, maxAgentReleaseProxies)
	}
	highestID := strconv.Itoa(maxAgentReleaseProxies + 1)
	if !strings.HasPrefix(lines[0], highestID+"\t") {
		t.Fatalf("first catalog entry = %q, want highest-priority id %s", lines[0], highestID)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "1\t") {
			t.Fatalf("lowest-priority entry was not truncated: %q", line)
		}
	}
}
