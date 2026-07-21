//go:build linux || darwin

package dnstapcollector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixListenerPermissionsSingleAcceptAndCleanup(t *testing.T) {
	baseDir := resolvedTestDir(t)
	listener, err := OpenListener(baseDir)
	if err != nil {
		t.Fatalf("open listener: %v", err)
	}
	workDir := listener.WorkDir()
	socketPath := listener.Endpoint()
	workInfo, err := os.Lstat(workDir)
	if err != nil || !workInfo.IsDir() || workInfo.Mode().Perm() != 0o700 {
		t.Fatalf("work directory = info %+v err %v", workInfo, err)
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("socket = info %+v err %v", socketInfo, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()
	client, err := net.DialTimeout(listener.Network(), listener.Endpoint(), time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := listener.Accept(ctx); err == nil {
		t.Fatal("listener accepted a second connection")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still exists: %v", err)
	}
	if _, err := os.Lstat(workDir); !os.IsNotExist(err) {
		t.Fatalf("work directory still exists: %v", err)
	}
}

func TestUnixListenerRejectsExplicitSymlinkBase(t *testing.T) {
	realBase := t.TempDir()
	linkParent := t.TempDir()
	linkedBase := filepath.Join(linkParent, "linked")
	if err := os.Symlink(realBase, linkedBase); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if listener, err := OpenListener(linkedBase); err == nil {
		_ = listener.Close()
		t.Fatal("listener accepted a symlink base directory")
	}
}

func TestUnixListenerAcceptRequiresDeadline(t *testing.T) {
	listener, err := OpenListener(resolvedTestDir(t))
	if err != nil {
		t.Fatalf("open listener: %v", err)
	}
	defer listener.Close()
	if _, err := listener.Accept(context.Background()); err == nil {
		t.Fatal("listener accepted an unbounded context")
	}
}

func resolvedTestDir(t *testing.T) string {
	t.Helper()
	resolvedRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary root: %v", err)
	}
	return resolvedRoot
}
