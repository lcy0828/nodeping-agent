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

type tracerouteCommandSpec struct {
	Name     string
	Args     []string
	Protocol string
}

func runTraceroute(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("traceroute target is required")
	}
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHost(ctx, target)
	if err != nil {
		return nil, err
	}
	maxHops := intOption(options, "max_hops", 30)
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 64 {
		maxHops = 64
	}
	protocol := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "protocol")))
	command, err := tracerouteCommandForAddr(runtime.GOOS, resolved, maxHops, protocol)
	if err != nil {
		return nil, err
	}
	path, err := exec.LookPath(command.Name)
	if err != nil {
		return nil, fmt.Errorf("%s command not found", command.Name)
	}
	targetIP := resolved.String()
	started := time.Now()
	out, cmdErr := exec.CommandContext(ctx, path, command.Args...).CombinedOutput()
	hops := parseTraceHops(string(out))
	reached := traceReachedTarget(hops, targetIP)
	if cmdErr != nil && len(hops) == 0 {
		return nil, fmt.Errorf("traceroute failed: %s", strings.TrimSpace(string(out)))
	}
	result := map[string]any{
		"traceroute": elapsedMS(started),
		"hops":       hops,
		"hop_count":  len(hops),
		"max_hops":   maxHops,
		"protocol":   command.Protocol,
		"reached":    reached,
		"raw_output": strings.TrimSpace(string(out)),
	}
	if targetIP != "" {
		result["target_ip"] = targetIP
	}
	if cmdErr != nil {
		result["command_error"] = cmdErr.Error()
	}
	return result, nil
}

func tracerouteCommandForAddr(goos string, addr netip.Addr, maxHops int, protocol string) (tracerouteCommandSpec, error) {
	if !addr.IsValid() {
		return tracerouteCommandSpec{}, errors.New("traceroute target IP address is invalid")
	}
	addr = addr.Unmap()
	target := addr.String()
	familyFlag := "-6"
	if addr.Is4() {
		familyFlag = "-4"
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))

	if goos == "windows" {
		if protocol == "" {
			protocol = "icmp"
		}
		if protocol != "icmp" {
			if protocol != "udp" && protocol != "tcp" {
				return tracerouteCommandSpec{}, fmt.Errorf("unsupported traceroute protocol: %s", protocol)
			}
			return tracerouteCommandSpec{}, fmt.Errorf("traceroute protocol %s is not supported on windows", protocol)
		}
		return tracerouteCommandSpec{
			Name:     "tracert",
			Args:     []string{familyFlag, "-d", "-h", strconv.Itoa(maxHops), "-w", "2000", target},
			Protocol: protocol,
		}, nil
	}

	if protocol == "" {
		protocol = "udp"
	}
	if protocol != "udp" && protocol != "icmp" && protocol != "tcp" {
		return tracerouteCommandSpec{}, fmt.Errorf("unsupported traceroute protocol: %s", protocol)
	}

	command := tracerouteCommandSpec{
		Name:     "traceroute",
		Args:     []string{familyFlag, "-n", "-m", strconv.Itoa(maxHops), "-q", "1", "-w", "2"},
		Protocol: protocol,
	}
	switch goos {
	case "linux":
	case "darwin":
		command.Args = command.Args[1:]
		if addr.Is6() {
			command.Name = "traceroute6"
		}
	default:
		return tracerouteCommandSpec{}, fmt.Errorf("traceroute is not supported on %s", goos)
	}
	switch protocol {
	case "icmp":
		command.Args = append(command.Args, "-I")
	case "tcp":
		if goos == "darwin" && addr.Is4() {
			command.Args = append(command.Args, "-P", "tcp")
		} else {
			command.Args = append(command.Args, "-T")
		}
	}
	command.Args = append(command.Args, target)
	return command, nil
}

func parseTraceHops(output string) []map[string]any {
	var hops []map[string]any
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hopNumber, err := strconv.Atoi(strings.TrimSuffix(fields[0], "."))
		if err != nil {
			continue
		}
		hop := map[string]any{"hop": hopNumber}
		var rtts []float64
		timeout := false
		for index := 1; index < len(fields); index++ {
			field := strings.Trim(fields[index], "(),")
			if field == "*" {
				timeout = true
				continue
			}
			if ip := net.ParseIP(field); ip != nil {
				if hop["ip"] == nil {
					hop["ip"] = ip.String()
				}
				continue
			}
			if value, err := strconv.ParseFloat(strings.TrimSuffix(field, "ms"), 64); err == nil {
				if index+1 < len(fields) && strings.EqualFold(strings.Trim(fields[index+1], ","), "ms") {
					rtts = append(rtts, value)
				} else if strings.HasSuffix(fields[index], "ms") {
					rtts = append(rtts, value)
				}
				continue
			}
			if hop["host"] == nil && !strings.EqualFold(field, "ms") {
				hop["host"] = field
			}
		}
		if len(rtts) > 0 {
			hop["rtt_ms"] = rtts[0]
			hop["rtts_ms"] = rtts
		}
		if timeout && hop["ip"] == nil && hop["host"] == nil {
			hop["timeout"] = true
		}
		hops = append(hops, hop)
	}
	return hops
}

func traceReachedTarget(hops []map[string]any, targetIP string) bool {
	targetIP = strings.TrimSpace(targetIP)
	if len(hops) == 0 || targetIP == "" {
		return false
	}
	last := hops[len(hops)-1]
	if strings.TrimSpace(fmt.Sprint(last["ip"])) == targetIP || strings.TrimSpace(fmt.Sprint(last["host"])) == targetIP {
		return true
	}
	for _, path := range tracePathMaps(last["paths"]) {
		if strings.TrimSpace(fmt.Sprint(path["ip"])) == targetIP || strings.TrimSpace(fmt.Sprint(path["host"])) == targetIP {
			return true
		}
	}
	return false
}

func tracePathMaps(raw any) []map[string]any {
	switch paths := raw.(type) {
	case []map[string]any:
		return paths
	case []any:
		out := make([]map[string]any, 0, len(paths))
		for _, item := range paths {
			if path, ok := item.(map[string]any); ok {
				out = append(out, path)
			}
		}
		return out
	default:
		return nil
	}
}
