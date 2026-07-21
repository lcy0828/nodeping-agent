//go:build linux || darwin

package dnstapcollector

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func openPlatformListener(baseDir string) (*Listener, error) {
	resolvedBase, err := secureListenerBase(baseDir)
	if err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(resolvedBase, "nodeping-dnstap-")
	if err != nil {
		return nil, fmt.Errorf("create dnstap work directory: %w", err)
	}
	cleanupDir := func() { _ = os.Remove(workDir) }
	if err := os.Chmod(workDir, 0o700); err != nil {
		cleanupDir()
		return nil, fmt.Errorf("secure dnstap work directory: %w", err)
	}
	info, err := os.Lstat(workDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		cleanupDir()
		return nil, fmt.Errorf("dnstap work directory failed its security check")
	}

	socketPath := filepath.Join(workDir, "dnstap.sock")
	// Darwin has the shortest sockaddr_un.sun_path among supported Unix
	// targets (104 bytes including the trailing NUL).
	if len(socketPath) >= 104 {
		cleanupDir()
		return nil, fmt.Errorf("dnstap unix socket path is too long")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		cleanupDir()
		return nil, fmt.Errorf("dnstap socket path already exists")
	}
	unixListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		cleanupDir()
		return nil, fmt.Errorf("listen on dnstap unix socket: %w", err)
	}
	unixListener.SetUnlinkOnClose(true)
	fail := func(cause error) (*Listener, error) {
		_ = unixListener.Close()
		_ = os.Remove(socketPath)
		cleanupDir()
		return nil, cause
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fail(fmt.Errorf("secure dnstap unix socket: %w", err))
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode()&os.ModeSymlink != 0 || socketInfo.Mode().Perm() != 0o600 {
		return fail(fmt.Errorf("dnstap unix socket failed its security check"))
	}

	cleanup := func() error {
		if info, statErr := os.Lstat(socketPath); statErr == nil {
			if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to remove a non-socket dnstap path")
			}
			if removeErr := os.Remove(socketPath); removeErr != nil && !os.IsNotExist(removeErr) {
				return removeErr
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		if removeErr := os.Remove(workDir); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		return nil
	}
	return &Listener{
		listener: unixListener,
		network:  "unix",
		endpoint: socketPath,
		workDir:  workDir,
		cleanup:  cleanup,
	}, nil
}

func secureListenerBase(baseDir string) (string, error) {
	implicit := baseDir == ""
	if implicit {
		baseDir = os.TempDir()
	}
	absolute, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve dnstap base directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve dnstap base directory symlinks: %w", err)
	}
	if !implicit && filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", fmt.Errorf("dnstap base directory must not contain symlinks")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("dnstap base directory must be an existing directory")
	}
	return resolved, nil
}

func validatePlatformPeer(connection net.Conn) error {
	if _, ok := connection.RemoteAddr().(*net.UnixAddr); !ok {
		return fmt.Errorf("dnstap unix listener received a non-unix peer")
	}
	return nil
}
