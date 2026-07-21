package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"runtime"
	"strings"
	"time"
)

func registerAgent(ctx context.Context, cfg config) (registerResponse, error) {
	var out registerResponse
	dependencies := cachedDependencySnapshot(ctx, cfg)
	if err := postJSONWithToken(ctx, cfg, cfg.Token, "/api/agent/v1/register", map[string]any{
		"agent_id":          cfg.AgentID,
		"agent_token":       cfg.AgentToken,
		"server_url":        cfg.ServerURL,
		"name":              cfg.Name,
		"version":           cfg.Version,
		"hostname":          hostname(),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"capabilities":      dependencies.Capabilities,
		"concurrency":       cfg.Concurrency,
		"dependency_status": dependencies,
	}, &out); err != nil {
		return registerResponse{}, fmt.Errorf("register: %w", err)
	}
	return out, nil
}

func agentTokenCanContinue(ctx context.Context, cfg config) bool {
	if cfg.AgentToken == "" || cfg.AgentID == "" {
		return false
	}
	statusCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err := getAgentStatusWithToken(statusCtx, cfg, cfg.AgentToken)
	if err != nil {
		log.Printf("stored agent token status check failed: %v", err)
		return false
	}
	return status.Registered
}

func heartbeatLoop(ctx context.Context, cfg config) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		dependencies := cachedDependencySnapshot(ctx, cfg)
		var response heartbeatResponse
		if err := postAgentJSON(ctx, cfg, "/api/agent/v1/heartbeat", map[string]any{
			"agent_id":          cfg.AgentID,
			"agent_token":       cfg.AgentToken,
			"server_url":        cfg.ServerURL,
			"name":              cfg.Name,
			"version":           cfg.Version,
			"capabilities":      dependencies.Capabilities,
			"concurrency":       cfg.Concurrency,
			"dependency_status": dependencies,
		}, &response); err != nil {
			log.Printf("heartbeat failed: %v", err)
		} else {
			if response.ReleaseProxies != nil {
				if err := persistAgentReleaseProxies(cfg.ReleaseProxyFile, response.ReleaseProxies); err != nil {
					log.Printf("store release proxy catalog failed: %v", err)
				}
			}
			if strings.TrimSpace(response.LatestVersion) != "" {
				if err := persistAgentLatestVersion(cfg.LatestVersionFile, response.LatestVersion); err != nil {
					log.Printf("store latest agent version failed: %v", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func getAgentStatus(ctx context.Context, cfg config) (agentStatusResponse, error) {
	return getAgentStatusWithToken(ctx, cfg, cfg.Token)
}

func getAgentStatusWithToken(ctx context.Context, cfg config, token string) (agentStatusResponse, error) {
	var out agentStatusResponse
	path := "/api/agent/v1/status?agent_id=" + url.QueryEscape(cfg.AgentID)
	if err := getJSONWithToken(ctx, cfg, token, path, &out); err != nil {
		return agentStatusResponse{}, err
	}
	return out, nil
}

func publicIPLoop(ctx context.Context, cfg config) {
	reportPublicIP(ctx, cfg)
	ticker := time.NewTicker(cfg.PublicIPInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reportPublicIP(ctx, cfg)
		}
	}
}

func reportPublicIP(ctx context.Context, cfg config) {
	discovery := discoverPublicIPs(ctx)
	if err := postPublicIPReport(ctx, cfg, discovery); err != nil {
		log.Printf("public IP report failed: %v", err)
	}
}

func postPublicIPReport(ctx context.Context, cfg config, discovery publicIPDiscovery) error {
	payload := map[string]any{"agent_id": cfg.AgentID, "source": "nodeping_agent"}
	if primary := discovery.primary(); primary != "" {
		payload["public_ip"] = primary
	}
	if discovery.IPv4 != "" {
		payload["public_ipv4"] = discovery.IPv4
	}
	if discovery.IPv6 != "" {
		payload["public_ipv6"] = discovery.IPv6
	}
	if families := discovery.families(); len(families) > 0 {
		payload["public_ip_families"] = families
	}
	return postAgentJSON(ctx, cfg, "/api/agent/v1/public-ip", payload, nil)
}
