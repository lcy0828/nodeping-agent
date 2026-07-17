package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.PrintVersion {
		fmt.Printf("nodeping-agent version=%s commit=%s date=%s\n", version, commit, buildDate)
		return
	}
	if cfg.Liveness {
		if err := checkLocalAgentLiveness(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cfg.Doctor {
		if err := runDoctor(ctx, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg config) error {
	if err := prepareAgentState(cfg); err != nil {
		return err
	}
	if cfg.AgentToken != "" && agentTokenCanContinue(ctx, cfg) {
		log.Printf("continuing with stored agent token agent_id=%s server=%s", cfg.AgentID, cfg.ServerURL)
	} else {
		if strings.TrimSpace(cfg.Token) == "" {
			return errors.New("stored agent token is invalid or missing; NODEPING_TOKEN is required to register again")
		}
		registerResp, err := registerAgent(ctx, cfg)
		if err != nil {
			return err
		}
		if agentID := strings.TrimSpace(registerResp.AgentID); agentID != "" {
			cfg.AgentID = agentID
			if err := writeAgentIDFile(cfg.AgentIDFile, cfg.AgentID); err != nil {
				return fmt.Errorf("store registered agent id: %w", err)
			}
		}
		cfg.AgentToken = strings.TrimSpace(registerResp.AgentToken)
		if cfg.AgentToken == "" {
			return errors.New("register response did not include agent_token")
		}
		if registerResp.ReleaseProxies != nil {
			if err := persistAgentReleaseProxies(cfg.ReleaseProxyFile, registerResp.ReleaseProxies); err != nil {
				log.Printf("store release proxy catalog failed: %v", err)
			}
		}
		if strings.TrimSpace(registerResp.LatestVersion) != "" {
			if err := persistAgentLatestVersion(cfg.LatestVersionFile, registerResp.LatestVersion); err != nil {
				log.Printf("store latest agent version failed: %v", err)
			}
		}
	}
	if cfg.AgentToken == "" {
		return errors.New("register response did not include agent_token")
	}
	if err := writeAgentTokenFile(cfg.AgentTokenFile, cfg.AgentToken); err != nil {
		return fmt.Errorf("store agent token: %w", err)
	}
	log.Printf("registered agent_id=%s server=%s", cfg.AgentID, cfg.ServerURL)
	var wg sync.WaitGroup
	loopCtx, cancelLoops := context.WithCancel(ctx)
	defer cancelLoops()
	taskExecutor := newAgentTaskExecutor(context.WithoutCancel(ctx), cfg)
	defer taskExecutor.Cancel()
	wg.Add(3)
	go func() {
		defer wg.Done()
		heartbeatLoop(loopCtx, cfg)
	}()
	go func() {
		defer wg.Done()
		publicIPLoop(loopCtx, cfg)
	}()
	go func() {
		defer wg.Done()
		taskStreamLoop(loopCtx, cfg, taskExecutor)
	}()
	<-ctx.Done()
	taskExecutor.StopAccepting()
	cancelLoops()
	wg.Wait()
	if !taskExecutor.Wait(cfg.ShutdownDrain) {
		log.Printf("task drain timed out after %s; canceling running tasks", cfg.ShutdownDrain)
		taskExecutor.Cancel()
		if !taskExecutor.Wait(15 * time.Second) {
			log.Printf("running tasks did not stop within final reporting window")
		}
	}
	return ctx.Err()
}

func prepareAgentState(cfg config) error {
	if strings.TrimSpace(cfg.AgentIDFile) == "" {
		return errors.New("NODEPING_AGENT_ID_FILE is required")
	}
	if err := writeAgentIDFile(cfg.AgentIDFile, cfg.AgentID); err != nil {
		return fmt.Errorf("store agent id before startup: %w", err)
	}
	if strings.TrimSpace(cfg.AgentTokenFile) == "" {
		return errors.New("NODEPING_AGENT_TOKEN_FILE is required")
	}
	if err := ensureStateFileWritable(cfg.AgentTokenFile); err != nil {
		return fmt.Errorf("prepare agent token file before startup: %w", err)
	}
	return nil
}

func ensureStateFileWritable(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("state file path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		file, openErr := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
		if openErr != nil {
			return openErr
		}
		return file.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".nodeping-agent-write-test-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if closeErr := temporary.Close(); closeErr != nil {
		_ = os.Remove(temporaryPath)
		return closeErr
	}
	return os.Remove(temporaryPath)
}
