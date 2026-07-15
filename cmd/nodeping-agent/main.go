package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
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
			if err := writeAgentIDFile(defaultAgentIDFile(), cfg.AgentID); err != nil {
				log.Printf("store agent id failed: %v", err)
			}
		}
		cfg.AgentToken = strings.TrimSpace(registerResp.AgentToken)
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
		log.Printf("store agent token failed: %v", err)
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
