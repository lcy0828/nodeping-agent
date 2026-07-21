//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package dnsroots

import (
	"context"
	"errors"
	"os"
)

func acquireFileLock(context.Context, string) (*fileLock, error) {
	return nil, errors.New("DNS root material locking is unsupported on this platform")
}

func unlockFile(*os.File) error {
	return nil
}
