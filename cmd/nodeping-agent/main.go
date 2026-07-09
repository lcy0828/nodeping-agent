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
	}
	if cfg.AgentToken == "" {
		return errors.New("register response did not include agent_token")
	}
	if err := writeAgentTokenFile(cfg.AgentTokenFile, cfg.AgentToken); err != nil {
		log.Printf("store agent token failed: %v", err)
	}
	log.Printf("registered agent_id=%s server=%s", cfg.AgentID, cfg.ServerURL)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Add(3)
	go func() {
		defer wg.Done()
		heartbeatLoop(ctx, cfg)
	}()
	go func() {
		defer wg.Done()
		publicIPLoop(ctx, cfg)
	}()
	go func() {
		defer wg.Done()
		taskStreamLoop(ctx, cfg)
	}()
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}
