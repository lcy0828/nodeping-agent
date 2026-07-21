package dnsroots

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s has invalid size %d", path, info.Size())
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) != info.Size() {
		return nil, fmt.Errorf("%s changed while reading", path)
	}
	return value, nil
}

func writeFileAtomic(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := ensurePrivateDir(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".nodeping-root-material-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		cleanup()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		cleanup()
		return err
	}
	return syncDirectory(directory)
}

func writeImmutableFile(path string, value []byte) error {
	if existing, err := readRegularFile(path, int64(len(value))); err == nil {
		if !bytes.Equal(existing, value) {
			return fmt.Errorf("immutable file collision at %s", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomic(path, value, 0o600)
}

func sha256Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
