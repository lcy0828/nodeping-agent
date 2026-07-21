//go:build darwin

package systemdns

import (
	"context"
	"errors"
)

func discoverPlatform(ctx context.Context, discoverer Discoverer, limits Limits) (DiscoveryResult, error) {
	path := discoverer.SCUtilPath
	if path == "" {
		path = "/usr/sbin/scutil"
	}
	commandContext, cancel := context.WithTimeout(ctx, discoverer.CommandTimeout)
	defer cancel()

	runner := discoverer.RunCommand
	if runner == nil {
		runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return runCommandBounded(ctx, limits.MaxInputBytes, name, args...)
		}
	}
	output, err := runner(commandContext, path, "--dns")
	if err != nil {
		if commandContext.Err() != nil {
			return DiscoveryResult{}, contextDiscoveryError(PlatformDarwin, "run_scutil", commandContext.Err())
		}
		if errors.Is(err, errOutputLimit) {
			return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformDarwin, "run_scutil", "output", 0, "command output exceeds the byte limit", err)
		}
		return DiscoveryResult{}, discoveryError(ErrorCommand, PlatformDarwin, "run_scutil", "command", 0, "scutil --dns failed", err)
	}
	if len(output) > limits.MaxInputBytes {
		return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformDarwin, "run_scutil", "output", 0, "command output exceeds the byte limit", nil)
	}
	if commandContext.Err() != nil {
		return DiscoveryResult{}, contextDiscoveryError(PlatformDarwin, "run_scutil", commandContext.Err())
	}
	return parseSCUtilDNS(output, limits)
}

func nativeDiscoverySource(discoverer Discoverer) bool {
	return discoverer.SCUtilPath == "" && discoverer.RunCommand == nil
}
