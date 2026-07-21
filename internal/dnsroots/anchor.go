package dnsroots

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	anchorStateSchema    = "nodeping-rfc5011-state/v1"
	anchorSnapshotSchema = "nodeping-rfc5011-snapshot/v1"
)

type anchorPointer struct {
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

type anchorState struct {
	Schema   string         `json:"schema"`
	Current  *anchorPointer `json:"current,omitempty"`
	Previous *anchorPointer `json:"previous,omitempty"`
}

type anchorSnapshotMetadata struct {
	Schema string `json:"schema"`
	anchorPointer
}

func (m *Manager) RefreshAnchor(
	ctx context.Context,
	updater AnchorUpdater,
	validator AnchorValidator,
) (AnchorRefreshResult, error) {
	if updater == nil || validator == nil {
		return AnchorRefreshResult{}, ErrNotConfigured
	}
	var result AnchorRefreshResult
	err := m.withLock(ctx, func() error {
		state, _, _ := m.loadOrDiscoverAnchorState(ctx, validator)
		baseline, baselinePointer, liveValid, recovered := m.anchorBaseline(ctx, state, validator)

		candidatePath, cleanup, err := m.prepareAnchorCandidate(baseline)
		if err != nil {
			return err
		}
		defer cleanup()

		updateErr := updater(ctx, candidatePath)
		if updateErr == nil {
			updateErr = validateAnchorFile(ctx, candidatePath, validator)
		}
		if updateErr != nil {
			if len(baseline) == 0 {
				return fmt.Errorf("%w: %v", ErrNoUsableTrustAnchor, updateErr)
			}
			snapshot, pointer, err := m.publishAnchorSnapshot(baseline, baselinePointer)
			if err != nil {
				return err
			}
			if !liveValid {
				if err := writeFileAtomic(m.anchorLivePath(), baseline, 0o600); err != nil {
					return err
				}
				recovered = true
			}
			if state.Current == nil || state.Current.SHA256 != pointer.SHA256 {
				state = anchorState{Schema: anchorStateSchema, Current: &pointer, Previous: state.Current}
				if err := m.writeAnchorState(state); err != nil {
					return err
				}
			}
			snapshot.Recovered = recovered
			result = AnchorRefreshResult{
				Snapshot: snapshot, Recovered: recovered, WarningCode: ReasonUsingLKG, Warning: updateErr,
			}
			return nil
		}

		candidate, err := readRegularFile(candidatePath, maxAnchorBytes)
		if err != nil {
			return fmt.Errorf("read validated trust anchor candidate: %w", err)
		}
		snapshot, pointer, err := m.publishAnchorSnapshot(candidate, nil)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(m.anchorLivePath(), candidate, 0o600); err != nil {
			return err
		}
		previous := state.Current
		if previous != nil && previous.SHA256 == pointer.SHA256 {
			previous = state.Previous
		}
		if err := m.writeAnchorState(anchorState{Schema: anchorStateSchema, Current: &pointer, Previous: previous}); err != nil {
			return err
		}
		result = AnchorRefreshResult{
			Snapshot: snapshot, Updated: baselinePointer == nil || baselinePointer.SHA256 != pointer.SHA256,
			Recovered: recovered,
		}
		return nil
	})
	return result, err
}

func (m *Manager) CurrentAnchor(ctx context.Context, validator AnchorValidator) (AnchorSnapshot, error) {
	if validator == nil {
		return AnchorSnapshot{}, ErrNotConfigured
	}
	var snapshot AnchorSnapshot
	err := m.withLock(ctx, func() error {
		var err error
		snapshot, err = m.currentAnchorLocked(ctx, validator)
		return err
	})
	return snapshot, err
}

func (m *Manager) currentAnchorLocked(ctx context.Context, validator AnchorValidator) (AnchorSnapshot, error) {
	state, stateRecovered, stateErr := m.loadOrDiscoverAnchorState(ctx, validator)
	if stateErr == nil && state.Current != nil {
		current, err := m.loadAnchorPointer(ctx, *state.Current, validator)
		if err == nil {
			currentBytes, readErr := readRegularFile(current.Path, maxAnchorBytes)
			if readErr != nil {
				return AnchorSnapshot{}, readErr
			}
			live, liveErr := readRegularFile(m.anchorLivePath(), maxAnchorBytes)
			if liveErr != nil || sha256Bytes(live) != current.SHA256 || validateAnchorFile(ctx, m.anchorLivePath(), validator) != nil {
				if writeErr := writeFileAtomic(m.anchorLivePath(), currentBytes, 0o600); writeErr != nil {
					return AnchorSnapshot{}, writeErr
				}
				current.Recovered = true
			}
			current.Recovered = current.Recovered || stateRecovered
			return current, nil
		}
		if state.Previous != nil {
			previous, previousErr := m.loadAnchorPointer(ctx, *state.Previous, validator)
			if previousErr == nil {
				previousBytes, readErr := readRegularFile(previous.Path, maxAnchorBytes)
				if readErr != nil {
					return AnchorSnapshot{}, readErr
				}
				if err := writeFileAtomic(m.anchorLivePath(), previousBytes, 0o600); err != nil {
					return AnchorSnapshot{}, err
				}
				if err := m.writeAnchorState(anchorState{Schema: anchorStateSchema, Current: state.Previous}); err != nil {
					return AnchorSnapshot{}, err
				}
				previous.Recovered = true
				return previous, nil
			}
		}
	}

	live, err := readRegularFile(m.anchorLivePath(), maxAnchorBytes)
	if err != nil || validateAnchorFile(ctx, m.anchorLivePath(), validator) != nil {
		if errors.Is(stateErr, os.ErrNotExist) && errors.Is(err, os.ErrNotExist) {
			return AnchorSnapshot{}, ErrNotConfigured
		}
		return AnchorSnapshot{}, ErrNoUsableTrustAnchor
	}
	current, pointer, err := m.publishAnchorSnapshot(live, nil)
	if err != nil {
		return AnchorSnapshot{}, err
	}
	if err := m.writeAnchorState(anchorState{Schema: anchorStateSchema, Current: &pointer}); err != nil {
		return AnchorSnapshot{}, err
	}
	current.Recovered = stateErr != nil
	return current, nil
}

func (m *Manager) RollbackAnchor(ctx context.Context, validator AnchorValidator) (AnchorSnapshot, error) {
	if validator == nil {
		return AnchorSnapshot{}, ErrNotConfigured
	}
	var snapshot AnchorSnapshot
	err := m.withLock(ctx, func() error {
		state, _, err := m.loadOrDiscoverAnchorState(ctx, validator)
		if err != nil || state.Current == nil || state.Previous == nil {
			return ErrNoUsableTrustAnchor
		}
		previous, err := m.loadAnchorPointer(ctx, *state.Previous, validator)
		if err != nil {
			return fmt.Errorf("validate previous trust anchor: %w", err)
		}
		previousBytes, err := readRegularFile(previous.Path, maxAnchorBytes)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(m.anchorLivePath(), previousBytes, 0o600); err != nil {
			return err
		}
		if err := m.writeAnchorState(anchorState{Schema: anchorStateSchema, Current: state.Previous, Previous: state.Current}); err != nil {
			return err
		}
		snapshot = previous
		return nil
	})
	return snapshot, err
}

func (m *Manager) anchorBaseline(
	ctx context.Context,
	state anchorState,
	validator AnchorValidator,
) ([]byte, *anchorPointer, bool, bool) {
	live, liveErr := readRegularFile(m.anchorLivePath(), maxAnchorBytes)
	if liveErr == nil && validateAnchorFile(ctx, m.anchorLivePath(), validator) == nil {
		pointer := &anchorPointer{SHA256: sha256Bytes(live), Size: int64(len(live))}
		if state.Current != nil && state.Current.SHA256 == pointer.SHA256 {
			pointer = state.Current
		}
		return live, pointer, true, false
	}
	for _, pointer := range []*anchorPointer{state.Current, state.Previous} {
		if pointer == nil {
			continue
		}
		snapshot, err := m.loadAnchorPointer(ctx, *pointer, validator)
		if err != nil {
			continue
		}
		value, err := readRegularFile(snapshot.Path, maxAnchorBytes)
		if err == nil {
			return value, pointer, false, true
		}
	}
	return nil, nil, false, false
}

func (m *Manager) prepareAnchorCandidate(baseline []byte) (string, func(), error) {
	directory := filepath.Join(m.root, "anchors", "candidates")
	if err := ensurePrivateDir(directory); err != nil {
		return "", nil, err
	}
	file, err := os.CreateTemp(directory, ".root-key-*.tmp")
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, err
	}
	if len(baseline) > 0 {
		if _, err := file.Write(baseline); err != nil {
			_ = file.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func (m *Manager) publishAnchorSnapshot(value []byte, existing *anchorPointer) (AnchorSnapshot, anchorPointer, error) {
	sha := sha256Bytes(value)
	path := m.anchorSnapshotPath(sha)
	if metadata, err := m.loadAnchorSnapshotMetadata(sha); err == nil {
		if int64(len(value)) != metadata.Size {
			return AnchorSnapshot{}, anchorPointer{}, fmt.Errorf("anchor snapshot metadata size mismatch")
		}
		if err := writeImmutableFile(path, value); err != nil {
			return AnchorSnapshot{}, anchorPointer{}, err
		}
		return anchorSnapshotFromPointer(metadata.anchorPointer, path), metadata.anchorPointer, nil
	}
	createdAt := m.now().UTC()
	if existing != nil && existing.SHA256 == sha {
		if parsed, err := time.Parse(time.RFC3339Nano, existing.CreatedAt); err == nil {
			createdAt = parsed.UTC()
		}
	}
	pointer := anchorPointer{SHA256: sha, Size: int64(len(value)), CreatedAt: createdAt.Format(time.RFC3339Nano)}
	if err := writeImmutableFile(path, value); err != nil {
		return AnchorSnapshot{}, anchorPointer{}, err
	}
	metadataBytes, err := encodeJSON(anchorSnapshotMetadata{Schema: anchorSnapshotSchema, anchorPointer: pointer})
	if err != nil {
		return AnchorSnapshot{}, anchorPointer{}, err
	}
	if err := writeImmutableFile(m.anchorSnapshotMetadataPath(sha), metadataBytes); err != nil {
		return AnchorSnapshot{}, anchorPointer{}, err
	}
	return anchorSnapshotFromPointer(pointer, path), pointer, nil
}

func (m *Manager) loadAnchorPointer(ctx context.Context, pointer anchorPointer, validator AnchorValidator) (AnchorSnapshot, error) {
	if !validSHA256(pointer.SHA256) || pointer.Size <= 0 || pointer.Size > maxAnchorBytes {
		return AnchorSnapshot{}, ErrNoUsableTrustAnchor
	}
	if _, err := time.Parse(time.RFC3339Nano, pointer.CreatedAt); err != nil {
		return AnchorSnapshot{}, ErrNoUsableTrustAnchor
	}
	metadata, err := m.loadAnchorSnapshotMetadata(pointer.SHA256)
	if err != nil || metadata.anchorPointer != pointer {
		return AnchorSnapshot{}, ErrNoUsableTrustAnchor
	}
	path := m.anchorSnapshotPath(pointer.SHA256)
	value, err := readRegularFile(path, maxAnchorBytes)
	if err != nil || int64(len(value)) != pointer.Size || sha256Bytes(value) != pointer.SHA256 {
		return AnchorSnapshot{}, ErrNoUsableTrustAnchor
	}
	if err := validateAnchorFile(ctx, path, validator); err != nil {
		return AnchorSnapshot{}, err
	}
	return anchorSnapshotFromPointer(pointer, path), nil
}

func validateAnchorFile(ctx context.Context, path string, validator AnchorValidator) error {
	if _, err := readRegularFile(path, maxAnchorBytes); err != nil {
		return err
	}
	return validator(ctx, path)
}

func (m *Manager) loadAnchorState() (anchorState, error) {
	value, err := readRegularFile(m.anchorStatePath(), 8<<10)
	if err != nil {
		return anchorState{Schema: anchorStateSchema}, err
	}
	var state anchorState
	if err := decodeStrictJSON(value, &state); err != nil || state.Schema != anchorStateSchema || state.Current == nil {
		return anchorState{Schema: anchorStateSchema}, ErrNoUsableTrustAnchor
	}
	return state, nil
}

func (m *Manager) loadOrDiscoverAnchorState(ctx context.Context, validator AnchorValidator) (anchorState, bool, error) {
	state, err := m.loadAnchorState()
	if err == nil {
		return state, false, nil
	}
	discovered, discoverErr := m.discoverAnchorState(ctx, validator)
	if discoverErr != nil {
		return state, false, err
	}
	if writeErr := m.writeAnchorState(discovered); writeErr != nil {
		return anchorState{Schema: anchorStateSchema}, false, writeErr
	}
	return discovered, true, nil
}

func (m *Manager) discoverAnchorState(ctx context.Context, validator AnchorValidator) (anchorState, error) {
	directory := filepath.Join(m.root, "anchors", "snapshots")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return anchorState{Schema: anchorStateSchema}, err
	}
	pointers := make([]anchorPointer, 0, 2)
	for _, entry := range entries {
		sha := strings.TrimSpace(entry.Name())
		if !entry.IsDir() || !validSHA256(sha) {
			continue
		}
		metadata, metadataErr := m.loadAnchorSnapshotMetadata(sha)
		if metadataErr != nil {
			continue
		}
		if _, validateErr := m.loadAnchorPointer(ctx, metadata.anchorPointer, validator); validateErr != nil {
			continue
		}
		pointers = append(pointers, metadata.anchorPointer)
	}
	if len(pointers) == 0 {
		return anchorState{Schema: anchorStateSchema}, ErrNoUsableTrustAnchor
	}
	sort.Slice(pointers, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, pointers[i].CreatedAt)
		right, _ := time.Parse(time.RFC3339Nano, pointers[j].CreatedAt)
		if left.Equal(right) {
			return pointers[i].SHA256 > pointers[j].SHA256
		}
		return left.After(right)
	})
	state := anchorState{Schema: anchorStateSchema, Current: &pointers[0]}
	if len(pointers) > 1 {
		state.Previous = &pointers[1]
	}
	return state, nil
}

func (m *Manager) loadAnchorSnapshotMetadata(sha string) (anchorSnapshotMetadata, error) {
	value, err := readRegularFile(m.anchorSnapshotMetadataPath(sha), 4<<10)
	if err != nil {
		return anchorSnapshotMetadata{}, err
	}
	var metadata anchorSnapshotMetadata
	if err := decodeStrictJSON(value, &metadata); err != nil || metadata.Schema != anchorSnapshotSchema ||
		metadata.SHA256 != sha || !validSHA256(metadata.SHA256) || metadata.Size <= 0 || metadata.Size > maxAnchorBytes {
		return anchorSnapshotMetadata{}, ErrNoUsableTrustAnchor
	}
	if _, err := time.Parse(time.RFC3339Nano, metadata.CreatedAt); err != nil {
		return anchorSnapshotMetadata{}, ErrNoUsableTrustAnchor
	}
	return metadata, nil
}

func (m *Manager) writeAnchorState(state anchorState) error {
	value, err := encodeJSON(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(m.anchorStatePath(), value, 0o600)
}

func (m *Manager) anchorStatePath() string {
	return filepath.Join(m.root, "anchors", "state.json")
}

func (m *Manager) anchorLivePath() string {
	return filepath.Join(m.root, "anchors", "rfc5011", "root.key")
}

func (m *Manager) anchorSnapshotPath(sha string) string {
	return filepath.Join(m.root, "anchors", "snapshots", sha, "root.key")
}

func (m *Manager) anchorSnapshotMetadataPath(sha string) string {
	return filepath.Join(m.root, "anchors", "snapshots", sha, "snapshot.json")
}

func anchorSnapshotFromPointer(pointer anchorPointer, path string) AnchorSnapshot {
	createdAt, _ := time.Parse(time.RFC3339Nano, pointer.CreatedAt)
	return AnchorSnapshot{
		Version: "rfc5011-" + pointer.SHA256[:16], CreatedAt: createdAt.UTC(),
		SHA256: pointer.SHA256, Size: pointer.Size, Path: path,
	}
}
