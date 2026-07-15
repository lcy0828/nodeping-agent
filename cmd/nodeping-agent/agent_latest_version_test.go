package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAgentLatestVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "0.0.25", want: "v0.0.25"},
		{input: "v1.2.3-rc.1+cn.5", want: "v1.2.3-rc.1+cn.5"},
		{input: " nodeping-agent/v10.20.30 ", want: "v10.20.30"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := normalizeAgentLatestVersion(test.input)
			if err != nil {
				t.Fatalf("normalizeAgentLatestVersion() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("normalizeAgentLatestVersion() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNormalizeAgentLatestVersionRejectsInvalidSemVer(t *testing.T) {
	for _, input := range []string{
		"",
		"latest",
		"1.2",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"1.2.3-01",
		"1.2.3-",
		"1.2.3+",
		"1.2.3\n2.0.0",
	} {
		t.Run(strings.ReplaceAll(input, "\n", "\\n"), func(t *testing.T) {
			if got, err := normalizeAgentLatestVersion(input); err == nil {
				t.Fatalf("normalizeAgentLatestVersion(%q) = %q, want error", input, got)
			}
		})
	}
}

func TestPersistAgentLatestVersionNormalizesAndPreservesLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "latest-version")
	if err := persistAgentLatestVersion(path, "1.2.3-rc.1"); err != nil {
		t.Fatalf("persistAgentLatestVersion() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), "v1.2.3-rc.1\n"; got != want {
		t.Fatalf("latest version file = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}

	if err := persistAgentLatestVersion(path, "not-semver"); err == nil {
		t.Fatal("persistAgentLatestVersion() error = nil, want validation error")
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), "v1.2.3-rc.1\n"; got != want {
		t.Fatalf("invalid update replaced last-good file: got %q, want %q", got, want)
	}
}

func TestHeartbeatPersistsReleaseMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/heartbeat" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"latest_version":"v2.3.4","release_proxies":[{"id":7,"name":"GHFast","base_url":"https://ghfast.top/","mode":"query","query_param":"q","priority":400}]}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	latestPath := filepath.Join(dir, "latest-version")
	proxyPath := filepath.Join(dir, "release-proxies.tsv")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		heartbeatLoop(ctx, config{
			ServerURL:         server.URL,
			AgentID:           "agent-test",
			AgentToken:        "agent-token",
			Version:           "nodeping-agent/test",
			HeartbeatInterval: time.Hour,
			LatestVersionFile: latestPath,
			ReleaseProxyFile:  proxyPath,
			HTTPClient:        server.Client(),
		})
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		latest, latestErr := os.ReadFile(latestPath)
		proxies, proxyErr := os.ReadFile(proxyPath)
		if latestErr == nil && proxyErr == nil {
			if got, want := string(latest), "v2.3.4\n"; got != want {
				t.Fatalf("latest version file = %q, want %q", got, want)
			}
			if got, want := string(proxies), "7\tquery\thttps://ghfast.top/\tq\n"; got != want {
				t.Fatalf("release proxy file = %q, want %q", got, want)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("heartbeat did not persist release metadata")
}
