package dnstapcollector

import (
	"fmt"
	"time"
)

const (
	defaultMaxFrameBytes       = 128 * 1024
	defaultMaxEvents           = 512
	defaultMaxTotalFrameBytes  = 4 * 1024 * 1024
	defaultMaxOutstandingQuery = 256
	defaultHandshakeTimeout    = 2 * time.Second

	maxDNSWireBytes  = 65535
	maxIdentityBytes = 256
	maxVersionBytes  = 256
	maxExtraBytes    = 4096
)

type Limits struct {
	MaxFrameBytes       int
	MaxEvents           int
	MaxTotalFrameBytes  int64
	MaxOutstandingQuery int
	HandshakeTimeout    time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxFrameBytes:       defaultMaxFrameBytes,
		MaxEvents:           defaultMaxEvents,
		MaxTotalFrameBytes:  defaultMaxTotalFrameBytes,
		MaxOutstandingQuery: defaultMaxOutstandingQuery,
		HandshakeTimeout:    defaultHandshakeTimeout,
	}
}

func (limits Limits) validate() error {
	switch {
	case limits.MaxFrameBytes < 1024 || limits.MaxFrameBytes > 1024*1024:
		return fmt.Errorf("max frame bytes must be from 1024 to 1048576")
	case limits.MaxEvents < 1 || limits.MaxEvents > 4096:
		return fmt.Errorf("max events must be from 1 to 4096")
	case limits.MaxTotalFrameBytes < int64(limits.MaxFrameBytes) || limits.MaxTotalFrameBytes > 64*1024*1024:
		return fmt.Errorf("max total frame bytes must cover one frame and not exceed 64 MiB")
	case limits.MaxOutstandingQuery < 1 || limits.MaxOutstandingQuery > limits.MaxEvents:
		return fmt.Errorf("max outstanding queries must be from 1 to max events")
	case limits.HandshakeTimeout < 10*time.Millisecond || limits.HandshakeTimeout > 10*time.Second:
		return fmt.Errorf("handshake timeout must be from 10ms to 10s")
	default:
		return nil
	}
}
