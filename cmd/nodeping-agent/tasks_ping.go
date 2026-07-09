package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func runPing(ctx context.Context, target string) (float64, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("ping target is required")
	}
	args := []string{"-c", "1", "-W", "2", target}
	if runtime.GOOS == "darwin" {
		args = []string{"-c", "1", "-W", "2000", target}
	}
	started := time.Now()
	out, err := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ping failed: %s", strings.TrimSpace(string(out)))
	}
	if latency := parsePingLatency(string(out)); latency > 0 {
		return latency, nil
	}
	return elapsedMS(started), nil
}

func runTCPPing(ctx context.Context, target string) (float64, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("tcp_ping target is required")
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return elapsedMS(started), nil
}

func parsePingLatency(out string) float64 {
	for _, marker := range []string{"time=", "time<"} {
		index := strings.Index(out, marker)
		if index < 0 {
			continue
		}
		rest := out[index+len(marker):]
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value := strings.Trim(fields[0], " ms")
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return 0
}
