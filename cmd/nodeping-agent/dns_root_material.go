package main

import (
	"context"
	"errors"
	"hash/fnv"
	"log"
	"strings"
	"time"

	"nodeping/internal/dnsroots"
)

const dnsRootRefreshJitterWindow = 30 * time.Minute

func collectDNSRootMaterialReadiness(ctx context.Context, cfg config) (doctorComponentReadiness, doctorComponentReadiness) {
	rootHints := unavailableDNSComponent()
	trustAnchor := unavailableDNSComponent()
	if !dnsRootMaterialHasAnyConfig(cfg) {
		return rootHints, trustAnchor
	}
	if !dnsRootMaterialConfigComplete(cfg) {
		invalid := doctorComponentReadiness{ReasonCode: dnsroots.ReasonMaterialInvalid}
		return invalid, invalid
	}
	manager, err := configuredDNSRootManager(cfg)
	if err != nil {
		invalid := dnsRootMaterialErrorReadiness(err)
		return invalid, invalid
	}
	_, hintsWarning, err := activateConfiguredRootHints(ctx, manager, cfg)
	if err != nil {
		invalid := dnsRootMaterialErrorReadiness(err)
		return invalid, unavailableDNSComponent()
	}
	material, err := currentConfiguredDNSRootMaterial(ctx, manager, cfg)
	if err != nil {
		invalid := dnsRootMaterialErrorReadiness(err)
		return invalid, invalid
	}
	if hintsWarning != nil {
		material.RootHints.Recovered = true
	}
	return rootHintsReadiness(material.RootHints), trustAnchorReadiness(material.TrustAnchor)
}

func refreshDNSRootMaterial(ctx context.Context, cfg config) (dnsroots.AnchorRefreshResult, error) {
	if !dnsRootMaterialConfigComplete(cfg) {
		return dnsroots.AnchorRefreshResult{}, dnsroots.ErrNotConfigured
	}
	manager, err := configuredDNSRootManager(cfg)
	if err != nil {
		return dnsroots.AnchorRefreshResult{}, err
	}
	hints, hintsWarning, err := activateConfiguredRootHints(ctx, manager, cfg)
	if err != nil {
		return dnsroots.AnchorRefreshResult{}, err
	}
	adapter, err := dnsroots.NewUnboundAdapter(dnsroots.UnboundConfig{
		AnchorBinary: cfg.DNSAnchorBinary, CheckconfBinary: cfg.DNSCheckconfBinary, RootHintsPath: hints.Path,
	})
	if err != nil {
		return dnsroots.AnchorRefreshResult{}, err
	}
	result, err := manager.RefreshAnchor(ctx, adapter.Update, adapter.Validate)
	if err == nil && hintsWarning != nil && result.Warning == nil {
		result.WarningCode = dnsroots.ReasonUsingLKG
		result.Warning = hintsWarning
	}
	return result, err
}

func activateConfiguredRootHints(
	ctx context.Context,
	manager *dnsroots.Manager,
	cfg config,
) (dnsroots.HintsSnapshot, error, error) {
	snapshot, activationErr := manager.ActivateHintsFiles(ctx, cfg.DNSRootManifest, cfg.DNSRootHintsFile)
	if activationErr == nil {
		return snapshot, nil, nil
	}
	current, currentErr := manager.CurrentHints(ctx)
	if currentErr != nil {
		return dnsroots.HintsSnapshot{}, nil, activationErr
	}
	current.Recovered = true
	return current, activationErr, nil
}

func configuredDNSRootManager(cfg config) (*dnsroots.Manager, error) {
	keys, err := dnsroots.ParseKeyring(cfg.DNSRootPublicKeys)
	if err != nil {
		return nil, err
	}
	return dnsroots.NewManager(cfg.DNSRootStateDir, keys)
}

func currentConfiguredDNSRootMaterial(ctx context.Context, manager *dnsroots.Manager, cfg config) (dnsroots.MaterialSnapshot, error) {
	if manager == nil {
		return dnsroots.MaterialSnapshot{}, dnsroots.ErrNotConfigured
	}
	return manager.CurrentMaterial(ctx, func(rootHintsPath string) (dnsroots.AnchorValidator, error) {
		adapter, err := dnsroots.NewUnboundAdapter(dnsroots.UnboundConfig{
			AnchorBinary: cfg.DNSAnchorBinary, CheckconfBinary: cfg.DNSCheckconfBinary, RootHintsPath: rootHintsPath,
		})
		if err != nil {
			return nil, err
		}
		return adapter.Validate, nil
	})
}

func dnsRootMaterialHasAnyConfig(cfg config) bool {
	return strings.TrimSpace(cfg.DNSRootHintsFile) != "" ||
		strings.TrimSpace(cfg.DNSRootManifest) != "" ||
		strings.TrimSpace(cfg.DNSRootPublicKeys) != "" ||
		strings.TrimSpace(cfg.DNSAnchorBinary) != "" ||
		strings.TrimSpace(cfg.DNSCheckconfBinary) != ""
}

func dnsRootMaterialConfigComplete(cfg config) bool {
	return strings.TrimSpace(cfg.DNSRootStateDir) != "" &&
		strings.TrimSpace(cfg.DNSRootHintsFile) != "" &&
		strings.TrimSpace(cfg.DNSRootManifest) != "" &&
		strings.TrimSpace(cfg.DNSRootPublicKeys) != "" &&
		strings.TrimSpace(cfg.DNSAnchorBinary) != "" &&
		strings.TrimSpace(cfg.DNSCheckconfBinary) != ""
}

func dnsRootMaterialErrorReadiness(err error) doctorComponentReadiness {
	switch {
	case errors.Is(err, dnsroots.ErrNotConfigured):
		return unavailableDNSComponent()
	case errors.Is(err, dnsroots.ErrInvalidSignature):
		return doctorComponentReadiness{ReasonCode: dnsroots.ReasonSignatureInvalid}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return doctorComponentReadiness{ReasonCode: dnsroots.ReasonLockUnavailable}
	default:
		return doctorComponentReadiness{ReasonCode: dnsroots.ReasonMaterialInvalid}
	}
}

func rootHintsReadiness(snapshot dnsroots.HintsSnapshot) doctorComponentReadiness {
	reason := dnsroots.ReasonReady
	if snapshot.Recovered {
		reason = dnsroots.ReasonUsingLKG
	}
	return doctorComponentReadiness{
		Ready: true, ReasonCode: reason, Version: snapshot.Version, SHA256: snapshot.SHA256,
	}
}

func trustAnchorReadiness(snapshot dnsroots.AnchorSnapshot) doctorComponentReadiness {
	reason := dnsroots.ReasonReady
	if snapshot.Recovered {
		reason = dnsroots.ReasonUsingLKG
	}
	return doctorComponentReadiness{
		Ready: true, ReasonCode: reason, Version: snapshot.Version, SHA256: snapshot.SHA256,
	}
}

func dnsRootMaterialLoop(ctx context.Context, cfg config) {
	for {
		next := nextDNSRootMaterialRefresh(time.Now().UTC(), cfg.AgentID)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		result, err := refreshDNSRootMaterial(refreshCtx, cfg)
		cancel()
		if err != nil {
			log.Printf("DNS root material refresh failed: %v", err)
		} else if result.Warning != nil {
			log.Printf("DNS root material refresh kept last-known-good state: %s", result.WarningCode)
		}
		invalidateDependencySnapshot()
	}
}

func nextDNSRootMaterialRefresh(now time.Time, agentID string) time.Time {
	now = now.UTC()
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(agentID)))
	jitter := time.Duration(hasher.Sum32()%uint32(dnsRootRefreshJitterWindow/time.Second)) * time.Second
	candidate := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, time.UTC).Add(jitter)
	if !candidate.After(now) {
		candidate = candidate.Add(24 * time.Hour)
	}
	return candidate
}

func initializeDNSRootMaterial(ctx context.Context, cfg config) {
	if !dnsRootMaterialConfigComplete(cfg) {
		return
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, err := refreshDNSRootMaterial(refreshCtx, cfg)
	if err != nil {
		log.Printf("DNS root material initialization failed; capability remains disabled: %v", err)
		return
	}
	if result.Warning != nil {
		log.Printf("DNS root material initialized from last-known-good state: %s", result.WarningCode)
	}
	invalidateDependencySnapshot()
}

func invalidateDependencySnapshot() {
	dependencySnapshotCache.Lock()
	dependencySnapshotCache.snapshot = doctorSnapshot{}
	dependencySnapshotCache.expires = time.Time{}
	dependencySnapshotCache.Unlock()
}
