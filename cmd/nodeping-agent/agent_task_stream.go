package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func taskStreamLoop(ctx context.Context, cfg config) {
	sem := make(chan struct{}, cfg.Concurrency)
	retryDelay := cfg.StreamRetryMin
	for {
		connected, err := consumeTaskStream(ctx, cfg, sem)
		if err != nil && ctx.Err() == nil {
			if connected {
				retryDelay = cfg.StreamRetryMin
			}
			log.Printf("task stream stopped: %v; reconnecting in %s", err, retryDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
			}
			retryDelay *= 2
			if retryDelay > cfg.StreamRetryMax {
				retryDelay = cfg.StreamRetryMax
			}
			continue
		}
		if ctx.Err() == nil {
			retryDelay = cfg.StreamRetryMin
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func consumeTaskStream(ctx context.Context, cfg config, sem chan struct{}) (bool, error) {
	endpoint := cfg.ServerURL + "/api/agent/v1/tasks/stream?agent_id=" + url.QueryEscape(cfg.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := taskStreamHTTPClient(cfg).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("stream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	log.Printf("task stream connected")
	err = readSSETasks(ctx, resp.Body, cfg.StreamIdleTimeout, func(task taskRequest) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			executeAndReport(ctx, cfg, task)
		}()
	})
	if err == nil {
		return true, errors.New("task stream closed")
	}
	return true, err
}

func taskStreamHTTPClient(cfg config) *http.Client {
	if cfg.HTTPClient == nil {
		return &http.Client{}
	}
	client := *cfg.HTTPClient
	client.Timeout = 0
	return &client
}

func readSSETasks(ctx context.Context, body io.Reader, idleTimeout time.Duration, handle func(taskRequest)) error {
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var event string
	var data bytes.Buffer
	lines := make(chan string)
	errCh := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(lines)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-done:
				errCh <- nil
				return
			}
		}
		errCh <- scanner.Err()
	}()
	flush := func() {
		if event != "task" || data.Len() == 0 {
			event = ""
			data.Reset()
			return
		}
		var task taskRequest
		if err := json.Unmarshal(data.Bytes(), &task); err != nil {
			log.Printf("decode task failed: %v", err)
		} else {
			handle(task)
		}
		event = ""
		data.Reset()
	}
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	resetIdleTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(idleTimeout)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("task stream idle for %s", idleTimeout)
		case line, ok := <-lines:
			if !ok {
				flush()
				if err := <-errCh; err != nil {
					return err
				}
				return nil
			}
			resetIdleTimer()
			if strings.HasPrefix(line, ":") {
				continue
			}
			if line == "" {
				flush()
				continue
			}
			if strings.HasPrefix(line, "event:") {
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				continue
			}
			if strings.HasPrefix(line, "data:") {
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
}
