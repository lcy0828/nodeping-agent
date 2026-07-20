package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func postJSON(ctx context.Context, cfg config, path string, payload any, out any) error {
	return postJSONWithToken(ctx, cfg, cfg.Token, path, payload, out)
}

func postAgentJSON(ctx context.Context, cfg config, path string, payload any, out any) error {
	return postJSONWithToken(ctx, cfg, cfg.AgentToken, path, payload, out)
}

func getJSONWithToken(ctx context.Context, cfg config, token string, path string, out any) error {
	endpoint, err := controlPlaneEndpoint(cfg.ServerURL, path, cfg.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := cfg.HTTPClient
	if client == nil {
		client = newControlPlaneHTTPClient(30*time.Second, cfg.AllowInsecureHTTP)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func postJSONWithToken(ctx context.Context, cfg config, token string, path string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint, err := controlPlaneEndpoint(cfg.ServerURL, path, cfg.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := cfg.HTTPClient
	if client == nil {
		client = newControlPlaneHTTPClient(30*time.Second, cfg.AllowInsecureHTTP)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}
