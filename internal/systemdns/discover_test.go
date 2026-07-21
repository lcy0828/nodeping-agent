package systemdns

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type testReadCloser struct {
	io.Reader
	closed bool
}

func (reader *testReadCloser) Close() error {
	reader.closed = true
	return nil
}

func TestDiscoverRejectsNilAndCancelledContext(t *testing.T) {
	t.Parallel()

	if _, err := (Discoverer{}).Discover(nil); !IsErrorCode(err, ErrorInvalidInput) {
		t.Fatalf("nil context error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Discoverer{}).Discover(ctx)
	if !IsErrorCode(err, ErrorCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}

func TestNormalizeLimitsRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	_, err := normalizeLimits(Limits{MaxResolvers: -1})
	if !IsErrorCode(err, ErrorInvalidInput) {
		t.Fatalf("error = %v", err)
	}
}

func TestDiscoverRejectsUnboundedCommandTimeout(t *testing.T) {
	t.Parallel()

	_, err := (Discoverer{CommandTimeout: maxCommandTimeout + 1}).Discover(context.Background())
	if !IsErrorCode(err, ErrorInvalidInput) {
		t.Fatalf("error = %v", err)
	}
}

func TestDiscoverResolvConfUsesInjectedBoundedReader(t *testing.T) {
	t.Parallel()

	file := &testReadCloser{Reader: strings.NewReader("nameserver 127.0.0.53\n")}
	limits, err := normalizeLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := discoverResolvConf(context.Background(), Discoverer{
		ResolvConfPath: "/test/resolv.conf",
		OpenFile: func(path string) (io.ReadCloser, error) {
			if path != "/test/resolv.conf" {
				t.Fatalf("path = %q", path)
			}
			return file, nil
		},
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !file.closed || len(result.Resolvers) != 1 {
		t.Fatalf("closed/result = %v/%#v", file.closed, result)
	}
}

func TestDiscoverResolvConfRejectsOversizeReader(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	limits.MaxInputBytes = 32
	limits.MaxLineBytes = 32
	_, err := discoverResolvConf(context.Background(), Discoverer{
		OpenFile: func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", 33))), nil
		},
	}, limits)
	if !IsErrorCode(err, ErrorTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestNativeSealIsRequiredByTrustedResultValidation(t *testing.T) {
	t.Parallel()

	result, err := ParseResolvConf([]byte("nameserver 127.0.0.53\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResult(result, true); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("unsealed validation error = %v", err)
	}
	if _, err := result.SelectTrusted(Selection{Name: "example.com"}); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("unsealed trusted selection error = %v", err)
	}
	if err := sealDiscoveryResult(&result); err != nil {
		t.Fatal(err)
	}
	if err := validateResult(result, true); err != nil {
		t.Fatalf("sealed validation error = %v", err)
	}
	if !result.Resolvers[0].Endpoint.IsTrustedSystem() {
		t.Fatal("native seal did not establish endpoint provenance")
	}
	selected, err := result.SelectTrusted(Selection{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || !selected[0].Endpoint.IsTrustedSystem() {
		t.Fatal("selection or value copying lost endpoint provenance")
	}
}
