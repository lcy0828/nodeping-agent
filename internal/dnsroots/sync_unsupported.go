//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package dnsroots

func syncDirectory(string) error {
	return nil
}
