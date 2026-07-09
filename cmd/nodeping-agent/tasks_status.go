package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func runNodeStatus() (map[string]any, error) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	host, _ := os.Hostname()
	result := map[string]any{
		"node_status":        0,
		"hostname":           strings.TrimSpace(host),
		"goos":               runtime.GOOS,
		"goarch":             runtime.GOARCH,
		"go_version":         runtime.Version(),
		"cpu_count":          runtime.NumCPU(),
		"goroutines":         runtime.NumGoroutine(),
		"memory_alloc_bytes": stats.Alloc,
		"memory_sys_bytes":   stats.Sys,
	}
	if loadAvg := readProcField("/proc/loadavg", 0); loadAvg != "" {
		result["loadavg_1m"] = loadAvg
	}
	if uptime := readProcField("/proc/uptime", 0); uptime != "" {
		if parsed, err := strconv.ParseFloat(uptime, 64); err == nil {
			result["uptime_seconds"] = parsed
		}
	}
	if disk := rootDiskUsage(); disk != nil {
		result["disk_total_bytes"] = disk["total"]
		result["disk_free_bytes"] = disk["free"]
		result["disk_used_percent"] = disk["used_percent"]
	}
	return result, nil
}

func readProcField(path string, index int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(raw))
	if index < 0 || index >= len(fields) {
		return ""
	}
	return fields[index]
}
