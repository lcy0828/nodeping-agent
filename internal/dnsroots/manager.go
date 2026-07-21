package dnsroots

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manager struct {
	root string
	keys Keyring
	now  func() time.Time
}

func NewManager(stateDir string, keys Keyring) (*Manager, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, ErrNotConfigured
	}
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve root material state directory: %w", err)
	}
	root := filepath.Join(filepath.Clean(absolute), "dns-root-material")
	if err := ensurePrivateDir(root); err != nil {
		return nil, fmt.Errorf("prepare root material state directory: %w", err)
	}
	keyCopy := make(Keyring, len(keys))
	for id, key := range keys {
		if !validKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid root hints public key %q", id)
		}
		keyCopy[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Manager{root: root, keys: keyCopy, now: time.Now}, nil
}

func (m *Manager) withLock(ctx context.Context, fn func() error) error {
	if m == nil || strings.TrimSpace(m.root) == "" {
		return ErrNotConfigured
	}
	lock, err := acquireFileLock(ctx, filepath.Join(m.root, "manager.lock"))
	if err != nil {
		return fmt.Errorf("acquire DNS root material lock: %w", err)
	}
	defer func() { _ = lock.release() }()
	return fn()
}

// CurrentMaterial acquires the hints and RFC 5011 anchor under one manager
// lock. The validator is built from the selected immutable hints path, so a
// concurrent refresh cannot mix two root-material generations in one run.
func (m *Manager) CurrentMaterial(ctx context.Context, factory AnchorValidatorFactory) (MaterialSnapshot, error) {
	if factory == nil {
		return MaterialSnapshot{}, ErrNotConfigured
	}
	var snapshot MaterialSnapshot
	err := m.withLock(ctx, func() error {
		hints, err := m.currentHintsLocked()
		if err != nil {
			return err
		}
		validator, err := factory(hints.Path)
		if err != nil {
			return err
		}
		if validator == nil {
			return ErrNotConfigured
		}
		anchor, err := m.currentAnchorLocked(ctx, validator)
		if err != nil {
			return err
		}
		snapshot = MaterialSnapshot{RootHints: hints, TrustAnchor: anchor}
		return nil
	})
	return snapshot, err
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a real directory", path)
		}
		return os.Chmod(path, 0o700)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}
