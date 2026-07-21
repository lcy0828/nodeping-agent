package dnsroots

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type UnboundConfig struct {
	AnchorBinary    string
	CheckconfBinary string
	RootHintsPath   string
}

type UnboundAdapter struct {
	anchorBinary    string
	checkconfBinary string
	rootHintsPath   string
	run             commandRunner
}

type commandRunner func(ctx context.Context, path string, args ...string) (int, string, error)

func NewUnboundAdapter(config UnboundConfig) (*UnboundAdapter, error) {
	anchorBinary, err := validateExecutable(config.AnchorBinary)
	if err != nil {
		return nil, fmt.Errorf("unbound-anchor: %w", err)
	}
	checkconfBinary, err := validateExecutable(config.CheckconfBinary)
	if err != nil {
		return nil, fmt.Errorf("unbound-checkconf: %w", err)
	}
	rootHintsPath, err := validateMaterialPath(config.RootHintsPath, maxHintsBytes)
	if err != nil {
		return nil, fmt.Errorf("root hints: %w", err)
	}
	rootHints, err := readRegularFile(rootHintsPath, maxHintsBytes)
	if err != nil {
		return nil, fmt.Errorf("root hints: %w", err)
	}
	if _, err := ParseRootHints(rootHints); err != nil {
		return nil, fmt.Errorf("root hints: %w", err)
	}
	return &UnboundAdapter{
		anchorBinary: anchorBinary, checkconfBinary: checkconfBinary,
		rootHintsPath: rootHintsPath, run: runBoundedCommand,
	}, nil
}

func (adapter *UnboundAdapter) Update(ctx context.Context, candidatePath string) error {
	if adapter == nil || adapter.run == nil {
		return ErrNotConfigured
	}
	exitCode, output, err := adapter.run(ctx, adapter.anchorBinary,
		"-a", candidatePath,
		"-r", adapter.rootHintsPath,
		"-v",
	)
	if err == nil || exitCode == 1 {
		return nil
	}
	return fmt.Errorf("unbound-anchor exit %d: %w: %s", exitCode, err, output)
}

func (adapter *UnboundAdapter) Validate(ctx context.Context, candidatePath string) error {
	if adapter == nil || adapter.run == nil {
		return ErrNotConfigured
	}
	if _, err := validateMaterialPath(candidatePath, maxAnchorBytes); err != nil {
		return err
	}
	directory := filepath.Dir(candidatePath)
	configFile, err := os.CreateTemp("", "nodeping-unbound-anchor-check-*.conf")
	if err != nil {
		return err
	}
	configPath := configFile.Name()
	defer os.Remove(configPath)
	config := "server:\n" +
		"  chroot: \"\"\n" +
		"  directory: " + unboundQuotedPath(directory) + "\n" +
		"  pidfile: " + unboundQuotedPath(filepath.Join(directory, "unbound.pid")) + "\n" +
		"  username: \"\"\n" +
		"  auto-trust-anchor-file: " + unboundQuotedPath(candidatePath) + "\n"
	if err := configFile.Chmod(0o600); err != nil {
		_ = configFile.Close()
		return err
	}
	if _, err := configFile.WriteString(config); err != nil {
		_ = configFile.Close()
		return err
	}
	if err := configFile.Close(); err != nil {
		return err
	}
	exitCode, output, err := adapter.run(ctx, adapter.checkconfBinary, "-q", configPath)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("unbound-checkconf exit %d: %w: %s", exitCode, err, output)
	}
	return nil
}

func validateExecutable(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return "", errors.New("path must be absolute")
	}
	info, err := os.Lstat(value)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !executableModeAllowed(value, info) {
		return "", errors.New("path must be a real executable file")
	}
	return filepath.Clean(value), nil
}

func validateMaterialPath(value string, maximum int64) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return "", errors.New("path must be absolute")
	}
	if _, err := readRegularFile(value, maximum); err != nil {
		return "", err
	}
	return filepath.Clean(value), nil
}

func unboundQuotedPath(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func runBoundedCommand(ctx context.Context, path string, args ...string) (int, string, error) {
	command := exec.CommandContext(ctx, path, args...)
	output := &boundedBuffer{maximum: 64 << 10}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	return exitCode, strings.TrimSpace(output.String()), err
}

type boundedBuffer struct {
	buffer  bytes.Buffer
	maximum int
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = buffer.buffer.Write(value)
	}
	return written, nil
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}
