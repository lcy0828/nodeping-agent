//go:build !linux && !darwin && !windows

package dnstapcollector

import (
	"fmt"
	"net"
)

func openPlatformListener(_ string) (*Listener, error) {
	return nil, fmt.Errorf("dnstap listener is not supported on this platform")
}

func validatePlatformPeer(net.Conn) error {
	return fmt.Errorf("dnstap listener is not supported on this platform")
}
