//go:build linux

package systemdns

import (
	"context"
	"io"
	"strings"
	"testing"
)

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (reader *trackedReadCloser) Close() error {
	reader.closed = true
	return nil
}

func TestLinuxDiscovererUsesBoundedReaderHook(t *testing.T) {
	t.Parallel()

	file := &trackedReadCloser{Reader: strings.NewReader("nameserver fe80::53%eth0\n")}
	discoverer := Discoverer{
		ResolvConfPath: "/test/resolv.conf",
		OpenFile: func(path string) (io.ReadCloser, error) {
			if path != "/test/resolv.conf" {
				t.Fatalf("path = %q", path)
			}
			return file, nil
		},
	}
	result, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !file.closed || len(result.Resolvers) != 1 {
		t.Fatalf("closed/result = %v/%#v", file.closed, result)
	}
	if result.Resolvers[0].Endpoint.IsTrustedSystem() {
		t.Fatal("injected resolv.conf source granted native trust")
	}
	if result.Resolvers[0].Endpoint.Zone() != "eth0" {
		t.Fatalf("link-local zone = %q", result.Resolvers[0].Endpoint.Zone())
	}
	if _, err := result.SelectTrusted(Selection{Name: "example.com"}); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("injected resolver entered trusted selection: %v", err)
	}
}

func TestLinuxDiscovererRejectsOversizeInjectedInput(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	limits.MaxInputBytes = 32
	limits.MaxLineBytes = 32
	discoverer := Discoverer{
		Limits: limits,
		OpenFile: func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", 33))), nil
		},
	}
	_, err := discoverer.Discover(context.Background())
	if !IsErrorCode(err, ErrorTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestLinuxNativeSourceClassification(t *testing.T) {
	t.Parallel()

	if !nativeDiscoverySource(Discoverer{}) {
		t.Fatal("zero-value Linux discoverer is not native")
	}
	if nativeDiscoverySource(Discoverer{ResolvConfPath: "/etc/resolv.conf"}) {
		t.Fatal("custom resolver path was classified as native")
	}
	if nativeDiscoverySource(Discoverer{OpenFile: func(string) (io.ReadCloser, error) { return nil, nil }}) {
		t.Fatal("injected reader was classified as native")
	}
}
