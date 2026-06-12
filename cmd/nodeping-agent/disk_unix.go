//go:build !windows

package main

import "syscall"

func rootDiskUsage() map[string]any {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return nil
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(total-free) * 100 / float64(total)
	}
	return map[string]any{
		"total":        total,
		"free":         free,
		"used_percent": usedPercent,
	}
}
