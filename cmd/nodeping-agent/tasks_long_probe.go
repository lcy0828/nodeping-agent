package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

func runLongPing(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	return runPinnedLongPing(ctx, "long_ping", target, options)
}

func runLongTCPPing(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	return runPinnedLongTCPPing(ctx, "long_tcp_ping", target, options)
}

func runLongPingWithProgress(ctx context.Context, cfg config, task taskRequest, target string) (map[string]any, error) {
	emitter := newLongProbeProgressEmitter(ctx, cfg, task, "long_ping")
	defer emitter.Close()
	return runPinnedLongPing(ctx, "long_ping", target, task.Options, emitter.Emit)
}

func runLongTCPPingWithProgress(ctx context.Context, cfg config, task taskRequest, target string) (map[string]any, error) {
	emitter := newLongProbeProgressEmitter(ctx, cfg, task, "long_tcp_ping")
	defer emitter.Close()
	return runPinnedLongTCPPing(ctx, "long_tcp_ping", target, task.Options, emitter.Emit)
}

func runPinnedLongPing(ctx context.Context, taskKey string, target string, options map[string]any, onProgress ...func(map[string]any)) (map[string]any, error) {
	resolver := newProbeTargetResolver(options)
	addr, err := resolver.resolveHost(ctx, strings.TrimSpace(target))
	if err != nil {
		return nil, err
	}
	result, err := runLongProbe(ctx, taskKey, addr.String(), options, runPing, onProgress...)
	if result != nil {
		result["response_ip"] = addr.String()
	}
	return result, err
}

func runPinnedLongTCPPing(ctx context.Context, taskKey string, target string, options map[string]any, onProgress ...func(map[string]any)) (map[string]any, error) {
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHostPort(ctx, strings.TrimSpace(target))
	if err != nil {
		return nil, err
	}
	pinned := net.JoinHostPort(resolved.IP.String(), resolved.Port)
	result, err := runLongProbe(ctx, taskKey, pinned, options, runTCPPing, onProgress...)
	if result != nil {
		result["response_ip"] = resolved.IP.String()
	}
	return result, err
}

var waitLongProbeInterval = func(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func runLongProbe(ctx context.Context, taskKey string, target string, options map[string]any, probe func(context.Context, string) (float64, error), onProgress ...func(map[string]any)) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("%s target is required", taskKey)
	}
	count := intOption(options, "sample_count", 100)
	if count < 2 {
		count = 2
	}
	if count > 5000 {
		count = 5000
	}
	intervalMS := intOption(options, "interval_ms", 1000)
	if intervalMS < 200 {
		intervalMS = 200
	}
	if intervalMS > 10000 {
		intervalMS = 10000
	}
	started := time.Now()
	samples := make([]map[string]any, 0, count)
	latencies := make([]float64, 0, count)
	failures := 0
	for index := 0; index < count; index++ {
		if index > 0 {
			if err := waitLongProbeInterval(ctx, time.Duration(intervalMS)*time.Millisecond); err != nil {
				return longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, err), nil
			}
		}
		sampleStarted := time.Now()
		latency, err := probe(ctx, target)
		sample := map[string]any{
			"seq":        index + 1,
			"started_at": sampleStarted.UTC(),
		}
		if err != nil {
			failures++
			sample["success"] = false
			sample["error"] = err.Error()
		} else {
			sample["success"] = true
			sample["latency_ms"] = latency
			latencies = append(latencies, latency)
		}
		samples = append(samples, sample)
		if len(onProgress) > 0 && onProgress[0] != nil {
			onProgress[0](longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, nil))
		}
	}
	return longProbeSummary(taskKey, started, count, intervalMS, samples, latencies, failures, nil), nil
}

func longProbeProgressReporter(ctx context.Context, cfg config, task taskRequest, taskKey string) func(map[string]any) {
	return func(summary map[string]any) {
		completed := intFromAnyDefault(summary["completed_count"], 0)
		total := intFromAnyDefault(summary["sample_count"], 0)
		if completed <= 0 || total <= 0 {
			return
		}
		progress := int(math.Round(float64(completed) * 100 / float64(total)))
		if progress < 1 {
			progress = 1
		}
		if progress > 100 {
			progress = 100
		}
		extra := cloneAnyMap(summary)
		if sample := latestLongProbeSample(summary["samples"]); sample != nil {
			extra["latest_sample"] = sample
		}
		delete(extra, "samples")
		extra["event_kind"] = "long_probe_sample"
		extra["task_type"] = taskKey
		event := taskEvent{
			TaskID:    task.ID,
			Status:    "running",
			Message:   fmt.Sprintf("%s sample %d/%d", taskKey, completed, total),
			Progress:  progress,
			Extra:     extra,
			CreatedAt: time.Now().UTC(),
		}
		reportCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := postAgentJSON(reportCtx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/events", event, nil); err != nil {
			log.Printf("report task event failed task_id=%s: %v", task.ID, err)
		}
	}
}

type longProbeProgressEmitter struct {
	updates   chan map[string]any
	done      chan struct{}
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
}

func newLongProbeProgressEmitter(parent context.Context, cfg config, task taskRequest, taskKey string) *longProbeProgressEmitter {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	emitter := &longProbeProgressEmitter{
		updates: make(chan map[string]any, 1),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	report := longProbeProgressReporter(ctx, cfg, task, taskKey)
	go func() {
		defer close(emitter.done)
		for summary := range emitter.updates {
			report(summary)
		}
	}()
	return emitter
}

func (e *longProbeProgressEmitter) Emit(summary map[string]any) {
	if e == nil || summary == nil {
		return
	}
	snapshot := cloneAnyMap(summary)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	select {
	case e.updates <- snapshot:
		return
	default:
	}
	select {
	case <-e.updates:
	default:
	}
	select {
	case e.updates <- snapshot:
	default:
	}
}

func (e *longProbeProgressEmitter) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.updates)
		e.mu.Unlock()
		e.cancel()
		select {
		case <-e.done:
		case <-time.After(time.Second):
		}
	})
}

func latestLongProbeSample(raw any) map[string]any {
	switch samples := raw.(type) {
	case []map[string]any:
		if len(samples) > 0 {
			return cloneAnyMap(samples[len(samples)-1])
		}
	case []any:
		if len(samples) > 0 {
			if sample, ok := samples[len(samples)-1].(map[string]any); ok {
				return cloneAnyMap(sample)
			}
		}
	}
	return nil
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func longProbeSummary(taskKey string, started time.Time, requestedCount int, intervalMS int, samples []map[string]any, latencies []float64, failures int, stopErr error) map[string]any {
	successCount := len(latencies)
	result := map[string]any{
		taskKey:           avgFloat(latencies),
		"samples":         samples,
		"sample_count":    requestedCount,
		"completed_count": len(samples),
		"success_count":   successCount,
		"failure_count":   failures,
		"loss_percent":    lossPercent(len(samples), successCount),
		"interval_ms":     intervalMS,
		"duration_ms":     elapsedMS(started),
	}
	if successCount > 0 {
		result["min_latency_ms"] = minFloat(latencies)
		result["max_latency_ms"] = maxFloat(latencies)
		result["avg_latency_ms"] = avgFloat(latencies)
		result["p95_latency_ms"] = percentileFloat(latencies, 0.95)
		avgJitter, maxJitter := jitterStats(latencies)
		result["jitter_ms"] = avgJitter
		result["max_jitter_ms"] = maxJitter
	}
	if stopErr != nil {
		result["stopped_early"] = true
		result["stop_reason"] = stopErr.Error()
	}
	return result
}
