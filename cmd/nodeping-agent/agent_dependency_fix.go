package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type dependencyFixPlan struct {
	Manager string
	Command string
	Args    []string
	Message string
}

func runAgentDependencyFix(ctx context.Context, cfg config, payload map[string]any, options map[string]any) (map[string]any, error) {
	dependency := normalizeDependencyFixName(firstNonEmptyStringAgent(
		stringFromMap(payload, "dependency"),
		stringFromMap(payload, "agent_dependency_fix"),
		stringOptionAny(options, "dependency"),
	))
	action := normalizeDependencyFixAction(firstNonEmptyStringAgent(
		stringFromMap(payload, "action"),
		stringOptionAny(options, "action"),
	))
	if dependency == "" {
		return nil, errors.New("unsupported dependency; allowed values: ping, traceroute, mtr")
	}
	plan, err := dependencyFixPlanFor(dependency, action)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	output, runErr := exec.CommandContext(runCtx, plan.Command, plan.Args...).CombinedOutput()
	snapshot := collectDependencySnapshot(ctx, cfg)
	result := map[string]any{
		"agent_dependency_fix": elapsedMS(started),
		"dependency":           dependency,
		"action":               action,
		"package_manager":      plan.Manager,
		"command":              strings.TrimSpace(plan.Command + " " + strings.Join(plan.Args, " ")),
		"output":               trimCommandOutput(string(output), 4096),
		"dependency_status":    snapshot,
	}
	if runErr != nil {
		return result, fmt.Errorf("%s failed: %w", plan.Message, runErr)
	}
	return result, nil
}

func normalizeDependencyFixName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, "_command")
	switch value {
	case "ping", "traceroute", "mtr":
		return value
	default:
		return ""
	}
}

func normalizeDependencyFixAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "upgrade":
		return "upgrade"
	default:
		return "install"
	}
}

func dependencyFixPlanFor(dependency string, action string) (dependencyFixPlan, error) {
	if path, err := exec.LookPath("apt-get"); err == nil {
		pkg := dependencyPackageName(dependency, "apt-get")
		if pkg == "" {
			return dependencyFixPlan{}, errors.New("unsupported dependency")
		}
		args := []string{"install", "-y", pkg}
		if action == "upgrade" {
			args = []string{"install", "--only-upgrade", "-y", pkg}
		}
		return dependencyFixPlan{Manager: "apt-get", Command: path, Args: args, Message: "apt-get dependency fix"}, nil
	}
	if path, err := exec.LookPath("apk"); err == nil {
		pkg := dependencyPackageName(dependency, "apk")
		if pkg == "" {
			return dependencyFixPlan{}, errors.New("unsupported dependency")
		}
		args := []string{"add", pkg}
		if action == "upgrade" {
			args = []string{"upgrade", pkg}
		}
		return dependencyFixPlan{Manager: "apk", Command: path, Args: args, Message: "apk dependency fix"}, nil
	}
	if path, err := exec.LookPath("dnf"); err == nil {
		pkg := dependencyPackageName(dependency, "dnf")
		if pkg == "" {
			return dependencyFixPlan{}, errors.New("unsupported dependency")
		}
		args := []string{"install", "-y", pkg}
		if action == "upgrade" {
			args = []string{"upgrade", "-y", pkg}
		}
		return dependencyFixPlan{Manager: "dnf", Command: path, Args: args, Message: "dnf dependency fix"}, nil
	}
	if path, err := exec.LookPath("yum"); err == nil {
		pkg := dependencyPackageName(dependency, "yum")
		if pkg == "" {
			return dependencyFixPlan{}, errors.New("unsupported dependency")
		}
		args := []string{"install", "-y", pkg}
		if action == "upgrade" {
			args = []string{"update", "-y", pkg}
		}
		return dependencyFixPlan{Manager: "yum", Command: path, Args: args, Message: "yum dependency fix"}, nil
	}
	return dependencyFixPlan{}, errors.New("supported package manager not found; install manually: " + installHint(dependency))
}

func dependencyPackageName(dependency string, manager string) string {
	switch dependency {
	case "ping":
		if manager == "apk" || manager == "dnf" || manager == "yum" {
			return "iputils"
		}
		return "iputils-ping"
	case "traceroute":
		return "traceroute"
	case "mtr":
		if manager == "apt-get" {
			return "mtr-tiny"
		}
		return "mtr"
	default:
		return ""
	}
}

func trimCommandOutput(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit > 0 && len(value) > limit {
		return value[:limit] + "...(truncated)"
	}
	return value
}
