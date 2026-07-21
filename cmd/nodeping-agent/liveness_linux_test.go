//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindLocalAgentPIDSupportsContainerInit(t *testing.T) {
	procRoot := t.TempDir()
	writeFakeProcProcess(t, procRoot, "1", "/sbin/docker-init", "PPid:\t0\n")
	writeFakeProcProcess(t, procRoot, "7", "/usr/local/bin/nodeping-agent", "PPid:\t1\n")
	writeFakeProcProcess(t, procRoot, "22", "/usr/local/bin/nodeping-agent", "PPid:\t0\n")

	pid, err := findLocalAgentPID(procRoot, 22)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 7 {
		t.Fatalf("agent pid = %d, want 7", pid)
	}
}

func TestFindLocalAgentPIDSupportsAgentAsPIDOne(t *testing.T) {
	procRoot := t.TempDir()
	writeFakeProcProcess(t, procRoot, "1", "/usr/local/bin/nodeping-agent", "PPid:\t0\n")

	pid, err := findLocalAgentPID(procRoot, 50)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 1 {
		t.Fatalf("agent pid = %d, want 1", pid)
	}
}

func TestFindLocalAgentPIDSupportsContainerSupervisor(t *testing.T) {
	procRoot := t.TempDir()
	writeFakeProcProcess(t, procRoot, "1", "/sbin/docker-init", "PPid:\t0\n")
	writeFakeProcProcess(t, procRoot, "6", "/usr/local/bin/nodeping-agent-entrypoint", "PPid:\t1\n")
	writeFakeProcProcess(t, procRoot, "7", "/opt/nodeping-agent/nodeping-agent", "PPid:\t6\n")
	writeFakeProcProcess(t, procRoot, "22", "/usr/local/lib/nodeping-agent/nodeping-agent", "PPid:\t6\n")

	pid, err := findLocalAgentPID(procRoot, 22)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 7 {
		t.Fatalf("agent pid = %d, want 7", pid)
	}
}

func writeFakeProcProcess(t *testing.T, procRoot, pid, executable, status string) {
	t.Helper()
	dir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}
