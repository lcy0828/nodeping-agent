package main

import (
	"context"
	"sync"
	"time"
)

type agentTaskExecutor struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    config
	run    func(context.Context, config, taskRequest)

	mu        sync.Mutex
	accepting bool
	wg        sync.WaitGroup
	running   map[string]context.CancelFunc
	cancelled map[string]time.Time
	completed map[string]time.Time
}

const (
	cancelledTaskTTL  = 10 * time.Minute
	maxCancelledTasks = 4096
)

func newAgentTaskExecutor(parent context.Context, cfg config) *agentTaskExecutor {
	ctx, cancel := context.WithCancel(parent)
	return &agentTaskExecutor{
		ctx: ctx, cancel: cancel, cfg: cfg, run: executeAndReport, accepting: true,
		running: map[string]context.CancelFunc{}, cancelled: map[string]time.Time{}, completed: map[string]time.Time{},
	}
}

func (e *agentTaskExecutor) Start(task taskRequest, limiter *taskConcurrencyLimiter) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	e.cleanupTaskTombstonesLocked(time.Now())
	if !e.accepting {
		e.mu.Unlock()
		return false
	}
	if task.ID != "" {
		if _, running := e.running[task.ID]; running {
			e.mu.Unlock()
			return false
		}
		if _, cancelled := e.cancelled[task.ID]; cancelled {
			e.mu.Unlock()
			return false
		}
		if _, completed := e.completed[task.ID]; completed {
			e.mu.Unlock()
			return false
		}
	}
	taskCtx, cancelTask := context.WithCancel(e.ctx)
	if task.ID != "" {
		e.running[task.ID] = cancelTask
	}
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer func() {
			cancelTask()
			e.mu.Lock()
			if task.ID != "" {
				delete(e.running, task.ID)
				e.completed[task.ID] = time.Now()
				e.cleanupTaskTombstonesLocked(time.Now())
				e.trimTaskTombstonesLocked(e.completed)
			}
			e.mu.Unlock()
		}()
		if limiter != nil {
			defer limiter.Release()
		}
		e.run(taskCtx, e.cfg, task)
	}()
	return true
}

func (e *agentTaskExecutor) CancelTask(taskID string) {
	if e == nil || taskID == "" {
		return
	}
	e.mu.Lock()
	now := time.Now()
	e.cleanupTaskTombstonesLocked(now)
	if cancel := e.running[taskID]; cancel != nil {
		cancel()
		e.mu.Unlock()
		return
	}
	if _, exists := e.cancelled[taskID]; exists {
		e.mu.Unlock()
		return
	}
	e.cancelled[taskID] = now
	e.trimTaskTombstonesLocked(e.cancelled)
	cfg := e.cfg
	ctx := e.ctx
	e.mu.Unlock()
	go func() {
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		result := taskResult{
			TaskID: taskID, Status: "cancelled", Success: false,
			ErrorCode: "TASK_CANCELLED", ErrorMessage: "task cancelled before execution", FinishedAt: time.Now().UTC(),
		}
		_ = postAgentResultWithRetry(reportCtx, cfg, taskID, result)
	}()
}

func (e *agentTaskExecutor) cleanupCancelledLocked(now time.Time) {
	e.cleanupTaskTombstonesLocked(now)
}

func (e *agentTaskExecutor) cleanupTaskTombstonesLocked(now time.Time) {
	if e == nil {
		return
	}
	for _, items := range []map[string]time.Time{e.cancelled, e.completed} {
		for taskID, createdAt := range items {
			if createdAt.IsZero() || now.Sub(createdAt) >= cancelledTaskTTL {
				delete(items, taskID)
			}
		}
	}
}

func (e *agentTaskExecutor) trimCancelledLocked() {
	e.trimTaskTombstonesLocked(e.cancelled)
}

func (e *agentTaskExecutor) trimTaskTombstonesLocked(items map[string]time.Time) {
	for len(items) > maxCancelledTasks {
		oldestID := ""
		var oldestAt time.Time
		for taskID, createdAt := range items {
			if oldestID == "" || createdAt.Before(oldestAt) {
				oldestID = taskID
				oldestAt = createdAt
			}
		}
		if oldestID == "" {
			return
		}
		delete(items, oldestID)
	}
}

func (e *agentTaskExecutor) StopAccepting() {
	if e != nil {
		e.mu.Lock()
		e.accepting = false
		e.mu.Unlock()
	}
}

func (e *agentTaskExecutor) Cancel() {
	if e != nil {
		e.cancel()
	}
}

func (e *agentTaskExecutor) Wait(timeout time.Duration) bool {
	if e == nil {
		return true
	}
	// Prevent any Add from racing with Wait, even if a caller omits StopAccepting.
	e.StopAccepting()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.wg.Wait()
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
