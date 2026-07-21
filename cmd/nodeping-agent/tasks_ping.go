package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const pingCommandTimeout = 3 * time.Second

type pingCommandSpec struct {
	Name string
	Args []string
}

func runPing(ctx context.Context, target string) (float64, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("ping target is required")
	}
	addr, err := netip.ParseAddr(strings.Trim(target, "[]"))
	if err != nil {
		return 0, fmt.Errorf("ping target must be a resolved IP address: %w", err)
	}
	command, err := pingCommandForAddr(runtime.GOOS, addr)
	if err != nil {
		return 0, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, pingCommandTimeout)
	defer cancel()
	started := time.Now()
	out, err := exec.CommandContext(commandCtx, command.Name, command.Args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ping failed: %s", strings.TrimSpace(string(out)))
	}
	if latency := parsePingLatency(string(out)); latency > 0 {
		return latency, nil
	}
	return elapsedMS(started), nil
}

func pingCommandForAddr(goos string, addr netip.Addr) (pingCommandSpec, error) {
	if !addr.IsValid() {
		return pingCommandSpec{}, errors.New("ping target IP address is invalid")
	}
	addr = addr.Unmap()
	target := addr.String()
	familyFlag := "-6"
	if addr.Is4() {
		familyFlag = "-4"
	}

	switch goos {
	case "linux":
		return pingCommandSpec{Name: "ping", Args: []string{familyFlag, "-c", "1", "-W", "2", target}}, nil
	case "darwin":
		if addr.Is6() {
			// Darwin ping6 uses -W for a node-information query, not a timeout.
			return pingCommandSpec{Name: "ping6", Args: []string{"-c", "1", target}}, nil
		}
		return pingCommandSpec{Name: "ping", Args: []string{"-c", "1", "-W", "2000", target}}, nil
	case "windows":
		return pingCommandSpec{Name: "ping", Args: []string{familyFlag, "-n", "1", "-w", "2000", target}}, nil
	default:
		return pingCommandSpec{}, fmt.Errorf("ping is not supported on %s", goos)
	}
}

func runPingWithOptions(ctx context.Context, target string, options map[string]any) (float64, string, error) {
	resolver := newProbeTargetResolver(options)
	addr, err := resolver.resolveHost(ctx, strings.TrimSpace(target))
	if err != nil {
		return 0, "", err
	}
	latency, err := runPing(ctx, addr.String())
	return latency, addr.String(), err
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

func runTCPPingWithOptions(ctx context.Context, target string, options map[string]any) (float64, string, error) {
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHostPort(ctx, strings.TrimSpace(target))
	if err != nil {
		return 0, "", err
	}
	latency, err := runTCPPing(ctx, net.JoinHostPort(resolved.IP.String(), resolved.Port))
	return latency, resolved.IP.String(), err
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
