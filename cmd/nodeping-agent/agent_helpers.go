package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

func deadlineTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && (fallback <= 0 || remaining < fallback) {
			return remaining
		}
	}
	return fallback
}

func elapsedMS(started time.Time) float64 {
	return math.Round(float64(time.Since(started).Microseconds())) / 1000
}

func elapsedBetweenMS(started time.Time, finished time.Time) float64 {
	return math.Round(float64(finished.Sub(started).Microseconds())) / 1000
}

func literalIP(value string) string {
	ip := net.ParseIP(strings.Trim(value, "[] "))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func hostLiteralIP(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return literalIP(value)
	}
	return literalIP(host)
}

func remoteAddrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return literalIP(host)
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(values[key]))
}

func stringOptionAny(options map[string]any, key string) string {
	if options == nil {
		return ""
	}
	switch value := options[key].(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case fmt.Stringer:
		return value.String()
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func firstNonEmptyStringAgent(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func intOption(options map[string]any, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	return intFromAnyDefault(options[key], fallback)
}

func boolOptionDefault(options map[string]any, key string, fallback bool) bool {
	if options == nil {
		return fallback
	}
	switch value := options[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	case json.Number:
		parsed, _ := value.Int64()
		return parsed != 0
	case int:
		return value != 0
	case float64:
		return value != 0
	}
	return fallback
}

func intFromAnyDefault(raw any, fallback int) int {
	if value := intFromAny(raw); value != 0 {
		return value
	}
	return fallback
}

func intFromAny(raw any) int {
	switch value := raw.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		if parsed, err := value.Int64(); err == nil {
			return int(parsed)
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return parsed
		}
	}
	return 0
}

func floatFromMap(values map[string]any, key string) float64 {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		parsed, _ := value.Float64()
		return parsed
	default:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(value)), 64)
		return parsed
	}
}

func boolFromMap(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	switch value := values[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "y", "on":
			return true
		}
	case float64:
		return value != 0
	case int:
		return value != 0
	case json.Number:
		parsed, _ := value.Float64()
		return parsed != 0
	}
	return false
}

func minFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}

func maxFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, value := range values[1:] {
		if value > max {
			max = value
		}
	}
	return max
}

func avgFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func jitterStats(values []float64) (float64, float64) {
	if len(values) < 2 {
		return 0, 0
	}
	jitters := make([]float64, 0, len(values)-1)
	for index := 1; index < len(values); index++ {
		jitter := math.Abs(values[index] - values[index-1])
		jitters = append(jitters, jitter)
	}
	return avgFloat(jitters), maxFloat(jitters)
}

func percentileFloat(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	if percentile <= 0 {
		return cp[0]
	}
	if percentile >= 1 {
		return cp[len(cp)-1]
	}
	index := int(math.Ceil(percentile*float64(len(cp)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(cp) {
		index = len(cp) - 1
	}
	return cp[index]
}

func lossPercent(total int, successes int) float64 {
	if total <= 0 {
		return 0
	}
	failures := total - successes
	if failures < 0 {
		failures = 0
	}
	return float64(failures) * 100 / float64(total)
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func floatFromAny(raw any) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func isPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}
