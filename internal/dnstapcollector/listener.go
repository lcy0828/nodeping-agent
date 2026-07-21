package dnstapcollector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type Listener struct {
	listener net.Listener
	network  string
	endpoint string
	workDir  string
	cleanup  func() error

	mu        sync.Mutex
	accepting bool
	accepted  bool
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func OpenListener(baseDir string) (*Listener, error) {
	return openPlatformListener(baseDir)
}

func (listener *Listener) Network() string {
	if listener == nil {
		return ""
	}
	return listener.network
}

func (listener *Listener) Endpoint() string {
	if listener == nil {
		return ""
	}
	return listener.endpoint
}

func (listener *Listener) WorkDir() string {
	if listener == nil {
		return ""
	}
	return listener.workDir
}

func (listener *Listener) Accept(ctx context.Context) (net.Conn, error) {
	if listener == nil || ctx == nil {
		return nil, fmt.Errorf("dnstap listener and context are required")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("dnstap accept context must have a deadline")
	}

	listener.mu.Lock()
	if listener.closed {
		listener.mu.Unlock()
		return nil, net.ErrClosed
	}
	if listener.accepting || listener.accepted {
		listener.mu.Unlock()
		return nil, fmt.Errorf("dnstap listener accepts exactly one connection")
	}
	listener.accepting = true
	listener.mu.Unlock()
	defer func() {
		listener.mu.Lock()
		listener.accepting = false
		listener.mu.Unlock()
	}()

	deadlineListener, ok := listener.listener.(interface{ SetDeadline(time.Time) error })
	if !ok {
		return nil, fmt.Errorf("dnstap listener does not support deadlines")
	}
	if err := deadlineListener.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set dnstap accept deadline: %w", err)
	}
	connection, err := listener.listener.Accept()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if err := validatePlatformPeer(connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	listener.mu.Lock()
	listener.accepted = true
	listener.mu.Unlock()
	return connection, nil
}

func (listener *Listener) Close() error {
	if listener == nil {
		return nil
	}
	listener.closeOnce.Do(func() {
		listener.mu.Lock()
		listener.closed = true
		listener.mu.Unlock()
		closeErr := listener.listener.Close()
		cleanupErr := listener.cleanup()
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			listener.closeErr = closeErr
		} else {
			listener.closeErr = cleanupErr
		}
	})
	return listener.closeErr
}
