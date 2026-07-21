//go:build !linux && !darwin && !windows

package systemdns

import "context"

func discoverPlatform(context.Context, Discoverer, Limits) (DiscoveryResult, error) {
	return DiscoveryResult{}, discoveryError(ErrorUnsupported, "", "discover", "platform", 0, "system DNS discovery is not supported on this platform", nil)
}

func nativeDiscoverySource(Discoverer) bool { return false }
