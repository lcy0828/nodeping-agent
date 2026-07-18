package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var dependencySnapshotCache struct {
	sync.Mutex
	snapshot doctorSnapshot
	expires  time.Time
}

func runDoctor(ctx context.Context, cfg config) error {
	snapshot := collectDoctorSnapshot(ctx, cfg)
	if cfg.DoctorJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(snapshot); err != nil {
			return err
		}
	} else {
		for _, check := range snapshot.Checks {
			fmt.Println(formatDoctorCheck(check))
		}
		fmt.Printf("%-32s %-12s %s\n", "能力 / capabilities", doctorCheckStatus(snapshot.Status), strings.Join(snapshot.Capabilities, ", "))
	}
	if snapshot.FailedCount > 0 {
		return errors.New("自检发现失败项 / doctor found failed checks")
	}
	return nil
}

func collectDoctorChecks(ctx context.Context, cfg config) []doctorCheck {
	return []doctorCheck{
		checkConfig(cfg),
		checkPingCommand(ctx),
		checkTracerouteCommand(ctx),
		checkMTRCommand(ctx),
		checkDNS(ctx),
		checkPublicIP(ctx),
		checkAgentTokenFile(cfg),
		checkBackendHealth(ctx, cfg),
		checkAgentRegistration(ctx, cfg),
		checkUpgradeControl(cfg),
	}
}

func collectDoctorSnapshot(ctx context.Context, cfg config) doctorSnapshot {
	checks := collectDoctorChecks(ctx, cfg)
	return doctorSnapshotFromChecks(checks, cfg)
}

func collectDependencySnapshot(ctx context.Context, cfg config) doctorSnapshot {
	checks := []doctorCheck{
		checkConfig(cfg),
		checkPingCommand(ctx),
		checkTracerouteCommand(ctx),
		checkMTRCommand(ctx),
		checkDNS(ctx),
		checkAgentTokenFile(cfg),
		checkUpgradeControl(cfg),
	}
	return doctorSnapshotFromChecks(checks, cfg)
}

func cachedDependencySnapshot(ctx context.Context, cfg config) doctorSnapshot {
	now := time.Now().UTC()
	dependencySnapshotCache.Lock()
	if now.Before(dependencySnapshotCache.expires) && dependencySnapshotCache.snapshot.CheckCount > 0 {
		snapshot := dependencySnapshotCache.snapshot
		dependencySnapshotCache.Unlock()
		return snapshot
	}
	dependencySnapshotCache.Unlock()

	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	snapshot := collectDependencySnapshot(checkCtx, cfg)

	dependencySnapshotCache.Lock()
	dependencySnapshotCache.snapshot = snapshot
	dependencySnapshotCache.expires = now.Add(5 * time.Minute)
	dependencySnapshotCache.Unlock()
	return snapshot
}

func doctorSnapshotFromChecks(checks []doctorCheck, cfg config) doctorSnapshot {
	failed := 0
	warnings := 0
	for _, check := range checks {
		if check.Status == "fail" {
			failed++
		}
		if check.Status == "warn" {
			warnings++
		}
	}
	status := "ok"
	if failed > 0 {
		status = "fail"
	} else if warnings > 0 {
		status = "warn"
	}
	return doctorSnapshot{
		Status:       status,
		InstallMode:  detectInstallMode(),
		Version:      cfg.Version,
		AgentID:      cfg.AgentID,
		Capabilities: effectiveCapabilitiesFromChecks(checks),
		Checks:       checks,
		CheckCount:   len(checks),
		FailedCount:  failed,
		WarningCount: warnings,
		GeneratedAt:  time.Now().UTC(),
	}
}

func doctorHasFailures(checks []doctorCheck) bool {
	for _, check := range checks {
		if check.Status == "fail" {
			return true
		}
	}
	return false
}

func runAgentDoctor(ctx context.Context, cfg config) (map[string]any, error) {
	snapshot := collectDoctorSnapshot(ctx, cfg)
	rows := make([]map[string]any, 0, len(snapshot.Checks))
	for _, check := range snapshot.Checks {
		rows = append(rows, map[string]any{
			"key":          check.Key,
			"name":         check.Name,
			"status":       check.Status,
			"issue_code":   check.IssueCode,
			"severity":     check.Severity,
			"message":      check.Message,
			"remediation":  check.Remediation,
			"path":         check.Path,
			"version":      check.Version,
			"capabilities": check.Capabilities,
			"required":     check.Required,
		})
	}
	result := map[string]any{
		"agent_doctor":  snapshot.Status,
		"status":        snapshot.Status,
		"install_mode":  snapshot.InstallMode,
		"capabilities":  snapshot.Capabilities,
		"checks":        rows,
		"check_count":   snapshot.CheckCount,
		"failed_count":  snapshot.FailedCount,
		"warning_count": snapshot.WarningCount,
		"version":       cfg.Version,
		"agent_id":      cfg.AgentID,
		"generated_at":  snapshot.GeneratedAt,
	}
	if snapshot.FailedCount > 0 {
		return result, fmt.Errorf("doctor found %d failed checks", snapshot.FailedCount)
	}
	return result, nil
}
