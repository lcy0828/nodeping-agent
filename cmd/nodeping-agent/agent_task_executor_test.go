package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentTaskExecutorWaitStopsAccepting(t *testing.T) {
	executor := newAgentTaskExecutor(context.Background(), config{})
	executor.run = func(context.Context, config, taskRequest) {}

	if !executor.Wait(time.Second) {
		t.Fatal("Wait timed out with no running tasks")
	}
	if executor.Start(taskRequest{}, nil) {
		t.Fatal("Start accepted a task after Wait began")
	}
}

func TestAgentTaskExecutorConcurrentStartAndWait(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		executor := newAgentTaskExecutor(context.Background(), config{})
		var executed atomic.Int64
		executor.run = func(context.Context, config, taskRequest) {
			executed.Add(1)
		}

		start := make(chan struct{})
		var callers sync.WaitGroup
		var accepted atomic.Int64
		for i := 0; i < 16; i++ {
			callers.Add(1)
			go func() {
				defer callers.Done()
				<-start
				if executor.Start(taskRequest{}, nil) {
					accepted.Add(1)
				}
			}()
		}
		close(start)
		if !executor.Wait(time.Second) {
			t.Fatalf("iteration %d: Wait timed out", iteration)
		}
		callers.Wait()
		if executor.Start(taskRequest{}, nil) {
			t.Fatalf("iteration %d: accepted task after Wait", iteration)
		}
		if got, want := executed.Load(), accepted.Load(); got != want {
			t.Fatalf("iteration %d: executed=%d accepted=%d", iteration, got, want)
		}
	}
}

func TestAgentTaskExecutorDeduplicatesRunningAndCompletedTaskIDs(t *testing.T) {
	executor := newAgentTaskExecutor(context.Background(), config{})
	started := make(chan struct{})
	release := make(chan struct{})
	var executed atomic.Int64
	executor.run = func(context.Context, config, taskRequest) {
		executed.Add(1)
		close(started)
		<-release
	}
	task := taskRequest{ID: "same-task"}
	if !executor.Start(task, nil) {
		t.Fatal("first delivery was rejected")
	}
	<-started
	if executor.Start(task, nil) {
		t.Fatal("running duplicate task was accepted")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		executor.mu.Lock()
		_, completed := executor.completed[task.ID]
		executor.mu.Unlock()
		if completed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("task did not reach completed tombstone")
		}
		time.Sleep(time.Millisecond)
	}
	if executor.Start(task, nil) {
		t.Fatal("completed duplicate task was accepted")
	}
	if got := executed.Load(); got != 1 {
		t.Fatalf("task executed %d times, want 1", got)
	}
	if !executor.Wait(time.Second) {
		t.Fatal("executor did not drain")
	}
}

func TestAgentTaskExecutorKeepsCancellationTombstoneAfterDelivery(t *testing.T) {
	executor := newAgentTaskExecutor(context.Background(), config{})
	var executed atomic.Int64
	executor.run = func(context.Context, config, taskRequest) { executed.Add(1) }
	task := taskRequest{ID: "cancel-before-delivery"}
	executor.CancelTask(task.ID)
	if executor.Start(task, nil) {
		t.Fatal("first cancelled task delivery was accepted")
	}
	if executor.Start(task, nil) {
		t.Fatal("replayed cancelled task delivery was accepted")
	}
	if got := executed.Load(); got != 0 {
		t.Fatalf("cancelled task executed %d times", got)
	}
}
