package main

import (
	"context"
	"sync"
)

type taskConcurrencyLimiter struct {
	mu      sync.Mutex
	limit   int
	running int
	changed chan struct{}
}

func newTaskConcurrencyLimiter(limit int) *taskConcurrencyLimiter {
	return &taskConcurrencyLimiter{
		limit:   normalizeTaskConcurrencyLimit(limit),
		changed: make(chan struct{}),
	}
}

func (l *taskConcurrencyLimiter) SetLimit(limit int) {
	if l == nil || limit <= 0 {
		return
	}
	limit = normalizeTaskConcurrencyLimit(limit)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limit == limit {
		return
	}
	l.limit = limit
	l.notifyLocked()
}

func (l *taskConcurrencyLimiter) Acquire(ctx context.Context) bool {
	if l == nil {
		return false
	}
	for {
		l.mu.Lock()
		if l.running < l.limit {
			l.running++
			l.mu.Unlock()
			return true
		}
		changed := l.changed
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return false
		case <-changed:
		}
	}
}

func (l *taskConcurrencyLimiter) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running > 0 {
		l.running--
	}
	l.notifyLocked()
}

func (l *taskConcurrencyLimiter) Limit() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

func (l *taskConcurrencyLimiter) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

func normalizeTaskConcurrencyLimit(limit int) int {
	if limit < 1 {
		return defaultAgentTaskConcurrency
	}
	if limit > maxAgentTaskConcurrency {
		return maxAgentTaskConcurrency
	}
	return limit
}
