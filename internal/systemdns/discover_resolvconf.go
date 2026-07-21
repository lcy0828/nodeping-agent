package systemdns

import (
	"context"
	"errors"
	"io"
	"os"
)

func discoverResolvConf(ctx context.Context, discoverer Discoverer, limits Limits) (DiscoveryResult, error) {
	path := discoverer.ResolvConfPath
	if path == "" {
		path = "/etc/resolv.conf"
	}
	openFile := discoverer.OpenFile
	if openFile == nil {
		openFile = func(path string) (io.ReadCloser, error) {
			return os.Open(path)
		}
	}
	file, err := openFile(path)
	if err != nil {
		return DiscoveryResult{}, discoveryError(ErrorIO, PlatformLinux, "read_resolv_conf", "open", 0, "failed to open resolver configuration", err)
	}
	if file == nil {
		return DiscoveryResult{}, discoveryError(ErrorIO, PlatformLinux, "read_resolv_conf", "open", 0, "resolver configuration hook returned a nil reader", nil)
	}
	data, readErr := readBounded(ctx, file, limits.MaxInputBytes)
	closeErr := file.Close()
	if readErr != nil {
		if closeErr != nil {
			readErr = errors.Join(readErr, closeErr)
		}
		if errors.Is(readErr, errOutputLimit) {
			return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformLinux, "read_resolv_conf", "input", 0, "configuration exceeds the byte limit", readErr)
		}
		if ctx.Err() != nil {
			return DiscoveryResult{}, contextDiscoveryError(PlatformLinux, "read_resolv_conf", ctx.Err())
		}
		return DiscoveryResult{}, discoveryError(ErrorIO, PlatformLinux, "read_resolv_conf", "read", 0, "failed to read resolver configuration", readErr)
	}
	if closeErr != nil {
		return DiscoveryResult{}, discoveryError(ErrorIO, PlatformLinux, "read_resolv_conf", "close", 0, "failed to close resolver configuration", closeErr)
	}
	return parseResolvConf(data, limits)
}
