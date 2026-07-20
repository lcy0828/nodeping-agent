package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidateControlPlaneBaseURLRequiresExplicitHTTPOptIn(t *testing.T) {
	const privateURL = "http://192.168.2.28:8099"
	if _, err := validateControlPlaneBaseURL(privateURL, "NODEPING_SERVER_URL", false); err == nil || !strings.Contains(err.Error(), "NODEPING_AGENT_ALLOW_INSECURE_HTTP=true") {
		t.Fatalf("private HTTP without opt-in error = %v", err)
	}
	parsed, err := validateControlPlaneBaseURL(privateURL, "NODEPING_SERVER_URL", true)
	if err != nil {
		t.Fatalf("private HTTP with opt-in: %v", err)
	}
	if parsed.String() != privateURL {
		t.Fatalf("parsed URL = %q, want %q", parsed.String(), privateURL)
	}
	if _, err := validateControlPlaneBaseURL("ftp://192.168.2.28/resource", "NODEPING_SERVER_URL", true); err == nil {
		t.Fatal("insecure HTTP opt-in unexpectedly allowed a non-HTTP scheme")
	}
	if _, err := validateControlPlaneBaseURL("http://user:pass@192.168.2.28:8099", "NODEPING_SERVER_URL", true); err == nil {
		t.Fatal("insecure HTTP opt-in unexpectedly allowed URL credentials")
	}
}

func TestControlPlaneRedirectHTTPOptInStillBlocksHTTPSDowngrade(t *testing.T) {
	httpTarget := &http.Request{URL: mustControlPlaneURL(t, "http://192.168.2.29:8099/next"), Header: make(http.Header)}
	httpSource := &http.Request{URL: mustControlPlaneURL(t, "http://192.168.2.28:8099/start")}
	if err := controlPlaneRedirect(httpTarget, []*http.Request{httpSource}, true); err != nil {
		t.Fatalf("HTTP development redirect with opt-in: %v", err)
	}
	if err := controlPlaneRedirect(httpTarget, []*http.Request{httpSource}, false); err == nil {
		t.Fatal("HTTP development redirect without opt-in was accepted")
	}

	httpsSource := &http.Request{URL: mustControlPlaneURL(t, "https://agent.example/start")}
	if err := controlPlaneRedirect(httpTarget, []*http.Request{httpsSource}, true); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("HTTPS downgrade error = %v", err)
	}
}

func mustControlPlaneURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
