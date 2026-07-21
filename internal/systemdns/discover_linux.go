//go:build linux

package systemdns

import "context"

func discoverPlatform(ctx context.Context, discoverer Discoverer, limits Limits) (DiscoveryResult, error) {
	return discoverResolvConf(ctx, discoverer, limits)
}

func nativeDiscoverySource(discoverer Discoverer) bool {
	return discoverer.ResolvConfPath == "" && discoverer.OpenFile == nil
}
