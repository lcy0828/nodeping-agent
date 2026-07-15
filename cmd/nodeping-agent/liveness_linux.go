//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func checkLocalAgentLiveness() error {
	target, err := os.Readlink("/proc/1/exe")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(filepath.Base(target), "nodeping-agent") {
		return errors.New("container init process is not nodeping-agent")
	}
	process, err := os.FindProcess(1)
	if err != nil {
		return err
	}
	return process.Signal(syscall.Signal(0))
}
