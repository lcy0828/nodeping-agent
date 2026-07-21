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

const hintsStateSchema = "nodeping-root-hints-state/v1"

type hintsPointer struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	ActivatedAt    string `json:"activated_at"`
}

type hintsState struct {
	Schema   string        `json:"schema"`
	Current  *hintsPointer `json:"current,omitempty"`
	Previous *hintsPointer `json:"previous,omitempty"`
}

func (m *Manager) ActivateHintsFiles(ctx context.Context, manifestPath, hintsPath string) (HintsSnapshot, error) {
	manifestBytes, err := readRegularFile(manifestPath, 16<<10)
	if err != nil {
		return HintsSnapshot{}, fmt.Errorf("read root hints manifest: %w", err)
	}
	var manifest HintsManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return HintsSnapshot{}, fmt.Errorf("decode root hints manifest: %w", err)
	}
	hints, err := readRegularFile(hintsPath, maxHintsBytes)
	if err != nil {
		return HintsSnapshot{}, fmt.Errorf("read root hints: %w", err)
	}
	return m.ActivateHints(ctx, manifest, hints)
}

func (m *Manager) ActivateHints(ctx context.Context, manifest HintsManifest, hints []byte) (HintsSnapshot, error) {
	var activated HintsSnapshot
	err := m.withLock(ctx, func() error {
		summary, publishedAt, err := VerifyHintsManifest(manifest, hints, m.keys, m.now().UTC())
		if err != nil {
			return err
		}
		manifestBytes, err := encodeJSON(manifest)
		if err != nil {
			return err
		}
		manifestSHA := sha256Bytes(manifestBytes)
		state, _, _ := m.loadOrDiscoverHintsState()
		current, currentErr := m.loadHintsPointer(state.Current)
		if currentErr == nil {
			if current.ManifestSHA256 == manifestSHA {
				activated = current
				return nil
			}
			if !publishedAt.After(current.PublishedAt) {
				return ErrStaleHints
			}
		}
		if err := m.persistHintsMaterial(manifestSHA, manifestBytes, manifest.SHA256, hints); err != nil {
			return err
		}
		pointer := hintsPointer{
			ManifestSHA256: manifestSHA,
			ActivatedAt:    m.now().UTC().Format(time.RFC3339Nano),
		}
		previous := state.Current
		if previous != nil && previous.ManifestSHA256 == manifestSHA {
			previous = state.Previous
		}
		if err := m.writeHintsState(hintsState{Schema: hintsStateSchema, Current: &pointer, Previous: previous}); err != nil {
			return err
		}
		activated = snapshotFromHints(manifest, manifestSHA, summary, publishedAt, m.hintsBlobPath(manifest.SHA256))
		return nil
	})
	return activated, err
}

func (m *Manager) CurrentHints(ctx context.Context) (HintsSnapshot, error) {
	var snapshot HintsSnapshot
	err := m.withLock(ctx, func() error {
		var err error
		snapshot, err = m.currentHintsLocked()
		return err
	})
	return snapshot, err
}

func (m *Manager) currentHintsLocked() (HintsSnapshot, error) {
	state, stateRecovered, stateErr := m.loadOrDiscoverHintsState()
	current, err := m.loadHintsPointer(state.Current)
	if err == nil {
		current.Recovered = stateRecovered
		return current, nil
	}
	previous, previousErr := m.loadHintsPointer(state.Previous)
	if previousErr != nil {
		discovered, discoverErr := m.discoverHintsState()
		if discoverErr == nil && discovered.Current != nil {
			current, loadErr := m.loadHintsPointer(discovered.Current)
			if loadErr == nil {
				if writeErr := m.writeHintsState(discovered); writeErr != nil {
					return HintsSnapshot{}, writeErr
				}
				current.Recovered = true
				return current, nil
			}
		}
		if errors.Is(stateErr, os.ErrNotExist) {
			return HintsSnapshot{}, ErrNotConfigured
		}
		return HintsSnapshot{}, fmt.Errorf("%w: current=%v previous=%v", ErrNoUsableHints, err, previousErr)
	}
	recoveredPointer := *state.Previous
	recoveredPointer.ActivatedAt = m.now().UTC().Format(time.RFC3339Nano)
	if err := m.writeHintsState(hintsState{Schema: hintsStateSchema, Current: &recoveredPointer}); err != nil {
		return HintsSnapshot{}, err
	}
	previous.Recovered = true
	return previous, nil
}

func (m *Manager) RollbackHints(ctx context.Context) (HintsSnapshot, error) {
	var snapshot HintsSnapshot
	err := m.withLock(ctx, func() error {
		state, _, err := m.loadOrDiscoverHintsState()
		if err != nil || state.Current == nil || state.Previous == nil {
			return ErrNoUsableHints
		}
		_, err = m.loadHintsPointer(state.Current)
		if err != nil {
			return fmt.Errorf("load current root hints: %w", err)
		}
		previous, err := m.loadHintsPointer(state.Previous)
		if err != nil {
			return fmt.Errorf("load previous root hints: %w", err)
		}
		now := m.now().UTC().Format(time.RFC3339Nano)
		newCurrent := *state.Previous
		newPrevious := *state.Current
		newCurrent.ActivatedAt = now
		newPrevious.ActivatedAt = now
		if err := m.writeHintsState(hintsState{Schema: hintsStateSchema, Current: &newCurrent, Previous: &newPrevious}); err != nil {
			return err
		}
		snapshot = previous
		return nil
	})
	return snapshot, err
}

func (m *Manager) persistHintsMaterial(manifestSHA string, manifest []byte, hintsSHA string, hints []byte) error {
	if err := writeImmutableFile(m.hintsManifestPath(manifestSHA), manifest); err != nil {
		return err
	}
	return writeImmutableFile(m.hintsBlobPath(hintsSHA), hints)
}

func (m *Manager) loadHintsPointer(pointer *hintsPointer) (HintsSnapshot, error) {
	if pointer == nil || !validSHA256(pointer.ManifestSHA256) {
		return HintsSnapshot{}, ErrNoUsableHints
	}
	if _, err := time.Parse(time.RFC3339Nano, pointer.ActivatedAt); err != nil {
		return HintsSnapshot{}, ErrNoUsableHints
	}
	manifestBytes, err := readRegularFile(m.hintsManifestPath(pointer.ManifestSHA256), 16<<10)
	if err != nil || sha256Bytes(manifestBytes) != pointer.ManifestSHA256 {
		return HintsSnapshot{}, ErrNoUsableHints
	}
	var manifest HintsManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return HintsSnapshot{}, fmt.Errorf("decode root hints manifest: %w", err)
	}
	hints, err := readRegularFile(m.hintsBlobPath(manifest.SHA256), maxHintsBytes)
	if err != nil {
		return HintsSnapshot{}, err
	}
	summary, publishedAt, err := VerifyHintsManifest(manifest, hints, m.keys, m.now().UTC())
	if err != nil {
		return HintsSnapshot{}, err
	}
	return snapshotFromHints(manifest, pointer.ManifestSHA256, summary, publishedAt, m.hintsBlobPath(manifest.SHA256)), nil
}

func (m *Manager) loadHintsState() (hintsState, error) {
	value, err := readRegularFile(filepath.Join(m.root, "hints", "state.json"), 8<<10)
	if err != nil {
		return hintsState{Schema: hintsStateSchema}, err
	}
	var state hintsState
	if err := decodeStrictJSON(value, &state); err != nil || state.Schema != hintsStateSchema || state.Current == nil {
		return hintsState{Schema: hintsStateSchema}, ErrNoUsableHints
	}
	return state, nil
}

func (m *Manager) loadOrDiscoverHintsState() (hintsState, bool, error) {
	state, err := m.loadHintsState()
	if err == nil {
		return state, false, nil
	}
	discovered, discoverErr := m.discoverHintsState()
	if discoverErr != nil {
		return state, false, err
	}
	if writeErr := m.writeHintsState(discovered); writeErr != nil {
		return hintsState{Schema: hintsStateSchema}, false, writeErr
	}
	return discovered, true, nil
}

func (m *Manager) discoverHintsState() (hintsState, error) {
	directory := filepath.Join(m.root, "hints", "manifests")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return hintsState{Schema: hintsStateSchema}, err
	}
	type candidate struct {
		pointer     hintsPointer
		publishedAt time.Time
	}
	candidates := make([]candidate, 0, 2)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		manifestSHA := strings.TrimSuffix(entry.Name(), ".json")
		if !validSHA256(manifestSHA) {
			continue
		}
		manifestBytes, readErr := readRegularFile(m.hintsManifestPath(manifestSHA), 16<<10)
		if readErr != nil || sha256Bytes(manifestBytes) != manifestSHA {
			continue
		}
		var manifest HintsManifest
		if decodeStrictJSON(manifestBytes, &manifest) != nil {
			continue
		}
		hints, readErr := readRegularFile(m.hintsBlobPath(manifest.SHA256), maxHintsBytes)
		if readErr != nil {
			continue
		}
		_, publishedAt, verifyErr := VerifyHintsManifest(manifest, hints, m.keys, m.now().UTC())
		if verifyErr != nil {
			continue
		}
		candidates = append(candidates, candidate{
			pointer: hintsPointer{
				ManifestSHA256: manifestSHA,
				ActivatedAt:    m.now().UTC().Format(time.RFC3339Nano),
			},
			publishedAt: publishedAt,
		})
	}
	if len(candidates) == 0 {
		return hintsState{Schema: hintsStateSchema}, ErrNoUsableHints
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].publishedAt.Equal(candidates[j].publishedAt) {
			return candidates[i].pointer.ManifestSHA256 > candidates[j].pointer.ManifestSHA256
		}
		return candidates[i].publishedAt.After(candidates[j].publishedAt)
	})
	state := hintsState{Schema: hintsStateSchema, Current: &candidates[0].pointer}
	if len(candidates) > 1 {
		state.Previous = &candidates[1].pointer
	}
	return state, nil
}

func (m *Manager) writeHintsState(state hintsState) error {
	value, err := encodeJSON(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.root, "hints", "state.json"), value, 0o600)
}

func (m *Manager) hintsManifestPath(sha string) string {
	return filepath.Join(m.root, "hints", "manifests", sha+".json")
}

func (m *Manager) hintsBlobPath(sha string) string {
	return filepath.Join(m.root, "hints", "blobs", sha, "named.root")
}

func snapshotFromHints(manifest HintsManifest, manifestSHA string, summary HintsSummary, publishedAt time.Time, path string) HintsSnapshot {
	return HintsSnapshot{
		Version: manifest.Version, PublishedAt: publishedAt, SHA256: manifest.SHA256,
		Size: manifest.Size, ManifestSHA256: manifestSHA, KeyID: manifest.KeyID,
		RootServers: summary.RootServerCount, IPv4Addresses: summary.IPv4Count,
		IPv6Addresses: summary.IPv6Count, Path: path,
	}
}
