package dnstapcollector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
)

type Collector struct {
	limits Limits
}

func New(limits Limits) (*Collector, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &Collector{limits: limits}, nil
}

func NewDefault() *Collector {
	collector, err := New(DefaultLimits())
	if err != nil {
		panic(err)
	}
	return collector
}

func (collector *Collector) Collect(ctx context.Context, connection net.Conn) Result {
	startedAt := time.Now().UTC()
	result := Result{Status: CollectionProtocolError, StartedAt: startedAt}
	if ctx == nil || connection == nil {
		return finishResult(result, CollectionProtocolError, ErrorHandshakeFailed, "collector context and connection are required")
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		_ = connection.Close()
		return finishResult(result, CollectionProtocolError, ErrorHandshakeFailed, "collector context must have a deadline")
	}

	tracked := newControlTrackingConn(connection)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = tracked.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer tracked.Close()

	reader, err := framestream.NewReader(tracked, &framestream.ReaderOptions{
		ContentTypes:  [][]byte{[]byte(ContentType)},
		Bidirectional: true,
		Timeout:       collector.limits.HandshakeTimeout,
	})
	if err != nil {
		return finishCollectionError(ctx, result, true, err)
	}
	if state := tracked.controlState(); state.malformed || !state.accepted || state.finished {
		return finishResult(result, CollectionProtocolError, ErrorInvalidControlFlow, "Frame Streams handshake control flow is invalid")
	}
	if err := tracked.SetDeadline(deadline); err != nil {
		return finishResult(result, CollectionIOError, ErrorReadFailed, "set collector deadline failed")
	}

	buffer := make([]byte, collector.limits.MaxFrameBytes)
	for {
		frame, readErr := readFrame(reader, buffer)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				state := tracked.controlState()
				if state.malformed || !state.finished {
					result = finishResult(result, CollectionProtocolError, ErrorUnexpectedEOF, "Frame Streams ended without a valid STOP/FINISH exchange")
				} else {
					result.Status = CollectionComplete
					result.Complete = true
					result.FinishedAt = time.Now().UTC()
				}
				break
			}
			result = finishCollectionError(ctx, result, false, readErr)
			break
		}
		if result.FrameCount >= collector.limits.MaxEvents {
			result = finishResult(result, CollectionLimitExceeded, ErrorEventLimit, "dnstap event limit exceeded")
			break
		}
		if result.FrameBytes+int64(len(frame)) > collector.limits.MaxTotalFrameBytes {
			result = finishResult(result, CollectionLimitExceeded, ErrorByteLimit, "dnstap frame byte limit exceeded")
			break
		}
		event, decodeErr := decodeFrame(frame, uint64(result.FrameCount+1))
		if decodeErr != nil {
			result = finishResult(result, CollectionProtocolError, ErrorInvalidDNSTap, "dnstap event failed strict validation")
			break
		}
		result.FrameCount++
		result.FrameBytes += int64(len(frame))
		result.Events = append(result.Events, event)
	}

	result.Exchanges, result.Pairing = pairEvents(result.Events)
	if result.Pairing.NoResponse > collector.limits.MaxOutstandingQuery && result.Status == CollectionComplete {
		result = finishResult(result, CollectionLimitExceeded, ErrorOutstandingLimit, "dnstap outstanding query limit exceeded")
	}
	return result
}

func readFrame(reader *framestream.Reader, buffer []byte) ([]byte, error) {
	length, err := reader.ReadFrame(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:length], nil
}

func finishCollectionError(ctx context.Context, result Result, handshake bool, err error) Result {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return finishResult(result, CollectionDeadlineExceeded, ErrorDeadlineExceeded, "dnstap collection deadline exceeded")
		}
		return finishResult(result, CollectionCancelled, ErrorCancelled, "dnstap collection cancelled")
	}
	if errors.Is(err, framestream.ErrContentTypeMismatch) {
		return finishResult(result, CollectionProtocolError, ErrorContentType, "Frame Streams content type mismatch")
	}
	if errors.Is(err, framestream.ErrDataFrameTooLarge) {
		return finishResult(result, CollectionLimitExceeded, ErrorFrameTooLarge, "dnstap frame exceeds its limit")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if handshake {
			return finishResult(result, CollectionDeadlineExceeded, ErrorHandshakeFailed, "Frame Streams handshake timed out")
		}
		return finishResult(result, CollectionDeadlineExceeded, ErrorDeadlineExceeded, "dnstap collection deadline exceeded")
	}
	if handshake {
		return finishResult(result, CollectionProtocolError, ErrorHandshakeFailed, "Frame Streams handshake failed")
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, framestream.ErrDecode) ||
		errors.Is(err, framestream.ErrShortRead) || errors.Is(err, framestream.ErrType) {
		return finishResult(result, CollectionProtocolError, ErrorInvalidControlFlow, "Frame Streams control flow is invalid")
	}
	return finishResult(result, CollectionIOError, ErrorReadFailed, "dnstap stream read failed")
}

func finishResult(result Result, status CollectionStatus, code ErrorCode, message string) Result {
	result.Status = status
	result.Complete = false
	result.FinishedAt = time.Now().UTC()
	result.Error = &CollectionError{Code: code, Message: message}
	return result
}

type controlState struct {
	accepted  bool
	finished  bool
	malformed bool
}

type controlTrackingConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
	state   controlState
}

func newControlTrackingConn(connection net.Conn) *controlTrackingConn {
	return &controlTrackingConn{Conn: connection}
}

func (connection *controlTrackingConn) Write(value []byte) (int, error) {
	written, err := connection.Conn.Write(value)
	if written > 0 {
		connection.observeControl(value[:written])
	}
	return written, err
}

func (connection *controlTrackingConn) observeControl(value []byte) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.state.malformed {
		return
	}
	connection.pending = append(connection.pending, value...)
	for len(connection.pending) >= 8 {
		if binary.BigEndian.Uint32(connection.pending[:4]) != 0 {
			connection.state.malformed = true
			connection.pending = nil
			return
		}
		length := int(binary.BigEndian.Uint32(connection.pending[4:8]))
		if length < 4 || length > framestream.CONTROL_FRAME_LENGTH_MAX {
			connection.state.malformed = true
			connection.pending = nil
			return
		}
		if len(connection.pending) < 8+length {
			return
		}
		controlType := binary.BigEndian.Uint32(connection.pending[8:12])
		switch controlType {
		case framestream.CONTROL_ACCEPT:
			if connection.state.accepted || connection.state.finished {
				connection.state.malformed = true
			}
			connection.state.accepted = true
		case framestream.CONTROL_FINISH:
			if !connection.state.accepted || connection.state.finished {
				connection.state.malformed = true
			}
			connection.state.finished = true
		default:
			connection.state.malformed = true
		}
		connection.pending = connection.pending[8+length:]
	}
}

func (connection *controlTrackingConn) controlState() controlState {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.state
}

func (result Result) String() string {
	if result.Error == nil {
		return string(result.Status)
	}
	return fmt.Sprintf("%s: %s", result.Status, result.Error.Code)
}
