package systemdns

import (
	"context"
	"time"
)

const (
	defaultCommandTimeout = 3 * time.Second
	maxCommandTimeout     = 30 * time.Second
)

// Discover uses the operating system's native DNS configuration source.
func Discover(ctx context.Context) (DiscoveryResult, error) {
	return (Discoverer{}).Discover(ctx)
}

// Discover uses this Discoverer's paths, limits, and optional deterministic
// I/O hooks.
func (discoverer Discoverer) Discover(ctx context.Context) (DiscoveryResult, error) {
	if ctx == nil {
		return DiscoveryResult{}, discoveryError(ErrorInvalidInput, "", "discover", "context", 0, "context must not be nil", nil)
	}
	limits, err := normalizeLimits(discoverer.Limits)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if discoverer.CommandTimeout == 0 {
		discoverer.CommandTimeout = defaultCommandTimeout
	}
	if discoverer.CommandTimeout < 0 || discoverer.CommandTimeout > maxCommandTimeout {
		return DiscoveryResult{}, discoveryError(ErrorInvalidInput, "", "discover", "command_timeout", 0, "must be between 1ns and 30s", nil)
	}
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, contextDiscoveryError("", "discover", err)
	}
	result, err := discoverPlatform(ctx, discoverer, limits)
	if err != nil {
		return DiscoveryResult{}, err
	}
	requireTrusted := nativeDiscoverySource(discoverer)
	if requireTrusted {
		if err := sealDiscoveryResult(&result); err != nil {
			return DiscoveryResult{}, err
		}
	}
	if err := validateResult(result, requireTrusted); err != nil {
		return DiscoveryResult{}, err
	}
	return result, nil
}

func sealDiscoveryResult(result *DiscoveryResult) error {
	for index := range result.Resolvers {
		sealed, err := sealEndpoint(result.Resolvers[index].Endpoint)
		if err != nil {
			return discoveryError(ErrorMalformed, result.Platform, "discover", "endpoint", 0, err.Error(), err)
		}
		result.Resolvers[index].Endpoint = sealed
	}
	if err := sealSnapshot(result); err != nil {
		return discoveryError(ErrorMalformed, result.Platform, "discover", "snapshot", 0, "failed to seal native resolver snapshot", err)
	}
	return nil
}

func contextDiscoveryError(platform Platform, op string, err error) error {
	if err == context.DeadlineExceeded {
		return discoveryError(ErrorTimeout, platform, op, "context", 0, "operation deadline exceeded", err)
	}
	return discoveryError(ErrorCancelled, platform, op, "context", 0, "operation was cancelled", err)
}
