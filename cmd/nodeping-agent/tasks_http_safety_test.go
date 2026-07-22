package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunHTTPPingFollowsHTTPSDowngrade(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer final.Close()

	secureRedirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", final.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer secureRedirect.Close()

	testTransport, ok := secureRedirect.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS test transport type = %T", secureRedirect.Client().Transport)
	}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = testTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	latency, responseIP, err := runHTTPPing(context.Background(), secureRedirect.URL, trustedPrivateTaskOptions(nil))
	if err != nil {
		t.Fatalf("runHTTPPing HTTPS downgrade: %v", err)
	}
	if latency <= 0 || responseIP == "" {
		t.Fatalf("runHTTPPing latency=%v responseIP=%q", latency, responseIP)
	}
}

func TestRunHTTPPingUsesRedirectHostForTLS(t *testing.T) {
	redirectedSNI := ""
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedSNI = r.TLS.ServerName
		w.WriteHeader(http.StatusNoContent)
	}))
	defer final.Close()

	initialSNI := ""
	secureRedirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		initialSNI = r.TLS.ServerName
		w.Header().Set("Location", final.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer secureRedirect.Close()

	testTransport, ok := secureRedirect.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS test transport type = %T", secureRedirect.Client().Transport)
	}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = testTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	_, _, err := runHTTPPing(context.Background(), secureRedirect.URL, trustedPrivateTaskOptions(map[string]any{
		"original_host": "origin.example.com",
	}))
	if err != nil {
		t.Fatalf("runHTTPPing redirected TLS request: %v", err)
	}
	if initialSNI != "origin.example.com" {
		t.Fatalf("initial TLS SNI = %q, want origin.example.com", initialSNI)
	}
	if redirectedSNI != "" {
		t.Fatalf("redirected TLS SNI = %q, want empty SNI for the redirected IP URL", redirectedSNI)
	}
}

func TestHTTPPingRedirectPolicyAllowsHTTPSDowngrade(t *testing.T) {
	source, err := http.NewRequest(http.MethodGet, "https://3.cn/", nil)
	if err != nil {
		t.Fatalf("new source request: %v", err)
	}
	redirect, err := http.NewRequest(http.MethodGet, "http://www.jd.com/", nil)
	if err != nil {
		t.Fatalf("new redirect request: %v", err)
	}
	redirect.Header.Set("Authorization", "Bearer secret")
	redirect.Header.Set("Cookie", "session=secret")
	redirect.Header.Set("Proxy-Authorization", "Basic secret")

	policy := httpRedirectPolicy{allowHTTPSDowngrade: true}
	if err := checkSafeHTTPRedirect(redirect, []*http.Request{source}, policy); err != nil {
		t.Fatalf("HTTP ping HTTPS downgrade: %v", err)
	}
	for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if value := redirect.Header.Get(header); value != "" {
			t.Fatalf("redirect retained %s header: %q", header, value)
		}
	}
}

func TestHTTPRequestRedirectPolicyBlocksHTTPSDowngrade(t *testing.T) {
	source, err := http.NewRequest(http.MethodGet, "https://3.cn/", nil)
	if err != nil {
		t.Fatalf("new source request: %v", err)
	}
	redirect, err := http.NewRequest(http.MethodGet, "http://www.jd.com/", nil)
	if err != nil {
		t.Fatalf("new redirect request: %v", err)
	}

	err = checkSafeHTTPRedirect(redirect, []*http.Request{source}, httpRedirectPolicy{})
	if err == nil || err.Error() != "HTTPS redirect downgrade is not allowed" {
		t.Fatalf("HTTP request downgrade error = %v", err)
	}
}

func TestHTTPPingRedirectPolicyStillBlocksPrivateTargets(t *testing.T) {
	source, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("new source request: %v", err)
	}
	redirect, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("new redirect request: %v", err)
	}

	err = checkSafeHTTPRedirect(redirect, []*http.Request{source}, httpRedirectPolicy{allowHTTPSDowngrade: true})
	if !errors.Is(err, errUnsafeHTTPDestination) {
		t.Fatalf("private redirect error = %v, want %v", err, errUnsafeHTTPDestination)
	}
}
