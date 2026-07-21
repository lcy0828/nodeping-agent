//go:build windows

package dnsroots

import (
	"os"
	"strings"
)

func executableModeAllowed(path string, _ os.FileInfo) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	header := make([]byte, 2)
	if _, err := file.Read(header); err != nil {
		return false
	}
	return header[0] == 'M' && header[1] == 'Z'
}
