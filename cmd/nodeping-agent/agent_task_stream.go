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
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func taskStreamLoop(ctx context.Context, cfg config, executor *agentTaskExecutor) {
	limiter := newTaskConcurrencyLimiter(cfg.Concurrency)
	retryDelay := cfg.StreamRetryMin
	for {
		connected, err := consumeTaskStream(ctx, cfg, limiter, executor)
		if err != nil && ctx.Err() == nil {
			if connected {
				retryDelay = cfg.StreamRetryMin
			}
			wait := taskStreamReconnectDelay(retryDelay)
			log.Printf("task stream stopped: %v; reconnecting in %s", err, wait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
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

func taskStreamReconnectDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	spread := base / 5
	if spread <= 0 {
		return base
	}
	return base - time.Duration(rand.Int64N(int64(spread)+1))
}

func consumeTaskStream(ctx context.Context, cfg config, limiter *taskConcurrencyLimiter, executor *agentTaskExecutor) (bool, error) {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	endpoint, err := controlPlaneEndpoint(cfg.ServerURL, "/api/agent/v1/tasks/stream?agent_id="+url.QueryEscape(cfg.AgentID))
	if err != nil {
		return false, err
	}
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
	err = readSSETasks(streamCtx, resp.Body, cfg.StreamIdleTimeout, func(task taskRequest) {
		if strings.EqualFold(strings.TrimSpace(task.Operation), "cancel") {
			if executor != nil {
				executor.CancelTask(strings.TrimSpace(task.CancelTaskID))
			}
			return
		}
		if task.MaxConcurrency > 0 {
			limiter.SetLimit(task.MaxConcurrency)
		}
		go func() {
			if !limiter.Acquire(streamCtx) {
				return
			}
			if executor == nil || !executor.Start(task, limiter) {
				limiter.Release()
			}
		}()
	})
	if err == nil {
		return true, errors.New("task stream closed")
	}
	return true, err
}

func taskStreamHTTPClient(cfg config) *http.Client {
	if cfg.HTTPClient == nil {
		client := newControlPlaneHTTPClient(0)
		client.Timeout = 0
		return client
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
