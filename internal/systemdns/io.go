package systemdns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

var errOutputLimit = errors.New("output limit exceeded")

func readBounded(ctx context.Context, reader io.Reader, maxBytes int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limited := io.LimitReader(reader, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, errOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maxBytes int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.maxBytes - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return 0, errOutputLimit
	}
	if len(value) > remaining {
		_, _ = buffer.buffer.Write(value[:remaining])
		buffer.overflow = true
		return remaining, errOutputLimit
	}
	return buffer.buffer.Write(value)
}

func runCommandBounded(ctx context.Context, maxBytes int, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdout := &boundedBuffer{maxBytes: maxBytes}
	stderrLimit := maxBytes
	if stderrLimit > 16<<10 {
		stderrLimit = 16 << 10
	}
	stderr := &boundedBuffer{maxBytes: stderrLimit}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, errOutputLimit
	}
	if err != nil {
		message := strings.TrimSpace(stderr.buffer.String())
		if message == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, message)
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}
