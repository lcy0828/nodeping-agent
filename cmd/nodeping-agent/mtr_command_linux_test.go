//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMTRCommandContextKillsDescendantsOnCancellation(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mtr-with-child")
	childPIDPath := filepath.Join(dir, "child-pid")
	readyPath := filepath.Join(dir, "ready")
	script := `#!/bin/sh
/bin/sh -c 'printf "%s\n" "$$" > "$1"; : > "$2"; exec sleep 30' child "$1" "$2" &
wait
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := mtrCommandContext(ctx, scriptPath, childPIDPath, readyPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	processGroupID := cmd.Process.Pid
	waited := false
	childStopped := false
	t.Cleanup(func() {
		if !childStopped {
			_ = syscall.Kill(-processGroupID, syscall.SIGKILL)
		}
		if !waited {
			_ = cmd.Wait()
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			_ = cmd.Wait()
			waited = true
			t.Fatal("mtr test command did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	childPIDRaw, err := os.ReadFile(childPIDPath)
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(childPIDRaw)))
	if err != nil {
		t.Fatalf("parse child pid %q: %v", childPIDRaw, err)
	}
	if childPID == processGroupID {
		t.Fatalf("child pid unexpectedly matches process group leader %d", processGroupID)
	}
	childProcessGroupID, err := syscall.Getpgid(childPID)
	if err != nil {
		t.Fatalf("get child process group: %v", err)
	}
	if childProcessGroupID != processGroupID {
		t.Fatalf("child process group = %d, want %d", childProcessGroupID, processGroupID)
	}

	cancel()
	_ = cmd.Wait()
	waited = true
	deadline = time.Now().Add(2 * time.Second)
	for {
		stopped, err := processExitedOrZombie(childPID)
		if err != nil {
			t.Fatalf("check mtr child process: %v", err)
		}
		if stopped {
			childStopped = true
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mtr child process %d is still running after cancellation", childPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func processExitedOrZombie(pid int) (bool, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return false, errors.New("invalid process stat")
	}
	return fields[2] == "Z" || fields[2] == "X", nil
}
