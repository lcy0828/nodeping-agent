//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package dnsroots

import "os"

func executableModeAllowed(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0
}
