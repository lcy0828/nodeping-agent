package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func runTraceroute(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("traceroute target is required")
	}
	path, err := exec.LookPath("traceroute")
	if err != nil {
		return nil, errors.New("traceroute command not found")
	}
	maxHops := intOption(options, "max_hops", 30)
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 64 {
		maxHops = 64
	}
	protocol := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "protocol")))
	args := []string{"-n", "-m", strconv.Itoa(maxHops), "-q", "1", "-w", "2"}
	switch protocol {
	case "icmp":
		args = append(args, "-I")
	case "tcp":
		args = append(args, "-T")
	case "", "udp":
		protocol = "udp"
	default:
		return nil, fmt.Errorf("unsupported traceroute protocol: %s", protocol)
	}
	args = append(args, target)
	started := time.Now()
	out, cmdErr := exec.CommandContext(ctx, path, args...).CombinedOutput()
	hops := parseTraceHops(string(out))
	targetIP := firstResolvedIP(ctx, target)
	reached := traceReachedTarget(hops, targetIP)
	if cmdErr != nil && len(hops) == 0 {
		return nil, fmt.Errorf("traceroute failed: %s", strings.TrimSpace(string(out)))
	}
	result := map[string]any{
		"traceroute": elapsedMS(started),
		"hops":       hops,
		"hop_count":  len(hops),
		"max_hops":   maxHops,
		"protocol":   protocol,
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

func firstResolvedIP(ctx context.Context, target string) string {
	host := strings.TrimSpace(target)
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}
