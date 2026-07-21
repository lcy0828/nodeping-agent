//go:build darwin

package systemdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDarwinDiscovererUsesBoundedCommandHook(t *testing.T) {
	t.Parallel()

	called := false
	discoverer := Discoverer{
		SCUtilPath:     "/test/scutil",
		CommandTimeout: time.Second,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "/test/scutil" || len(args) != 1 || args[0] != "--dns" {
				t.Fatalf("command = %q %v", name, args)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("command context has no deadline")
			}
			return []byte("resolver #1\nnameserver[0] : fe80::53\nif_index : 7 (en7)\nflags : Scoped\n"), nil
		},
	}
	result, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !called || len(result.Resolvers) != 1 {
		t.Fatalf("called/result = %v/%#v", called, result)
	}
	if result.Resolvers[0].Endpoint.IsTrustedSystem() {
		t.Fatal("injected scutil runner granted native trust")
	}
	if result.Resolvers[0].Endpoint.Zone() != "en7" {
		t.Fatalf("link-local zone = %q", result.Resolvers[0].Endpoint.Zone())
	}
	if _, err := result.SelectTrusted(Selection{Name: "example.com", InterfaceIndex: 7}); !IsErrorCode(err, ErrorMalformed) {
		t.Fatalf("injected resolver entered trusted selection: %v", err)
	}
}

func TestDarwinDiscovererRejectsOversizeInjectedOutput(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	limits.MaxInputBytes = 32
	limits.MaxLineBytes = 32
	discoverer := Discoverer{
		Limits: limits,
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(strings.Repeat("x", 33)), nil
		},
	}
	_, err := discoverer.Discover(context.Background())
	if !IsErrorCode(err, ErrorTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestDarwinDiscovererEnforcesCommandDeadline(t *testing.T) {
	t.Parallel()

	discoverer := Discoverer{
		CommandTimeout: 10 * time.Millisecond,
		RunCommand: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, err := discoverer.Discover(context.Background())
	if !IsErrorCode(err, ErrorTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestDarwinNativeSourceClassification(t *testing.T) {
	t.Parallel()

	if !nativeDiscoverySource(Discoverer{}) {
		t.Fatal("zero-value Darwin discoverer is not native")
	}
	if nativeDiscoverySource(Discoverer{SCUtilPath: "/usr/sbin/scutil"}) {
		t.Fatal("custom scutil path was classified as native")
	}
	if nativeDiscoverySource(Discoverer{RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil }}) {
		t.Fatal("injected command runner was classified as native")
	}
}
