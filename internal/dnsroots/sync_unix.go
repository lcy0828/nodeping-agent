//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package dnsroots

import "os"

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
