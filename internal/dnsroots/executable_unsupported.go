//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package dnsroots

import "os"

func executableModeAllowed(_ string, _ os.FileInfo) bool {
	return false
}
