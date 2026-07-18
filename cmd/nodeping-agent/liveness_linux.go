//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func checkLocalAgentLiveness() error {
	pid, err := findLocalAgentPID("/proc", os.Getpid())
	if err != nil {
		return err
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.Signal(0))
}

func findLocalAgentPID(procRoot string, selfPID int) (int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid == selfPID {
			continue
		}
		target, readErr := os.Readlink(filepath.Join(procRoot, entry.Name(), "exe"))
		if readErr != nil || !strings.HasPrefix(filepath.Base(target), "nodeping-agent") {
			continue
		}
		if pid == 1 || processParentPID(filepath.Join(procRoot, entry.Name(), "status")) == 1 {
			return pid, nil
		}
	}
	return 0, errors.New("nodeping-agent process is not running under the local init process")
}

func processParentPID(statusPath string) int {
	raw, err := os.ReadFile(statusPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "PPid:" {
			pid, _ := strconv.Atoi(fields[1])
			return pid
		}
	}
	return 0
}
