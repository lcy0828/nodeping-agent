package main

import (
	"context"
	"testing"
	"time"
)

func TestDeadlineTimeoutUsesOperationLimitWhenTaskDeadlineIsLonger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if got := deadlineTimeout(ctx, 100*time.Millisecond); got != 100*time.Millisecond {
		t.Fatalf("deadlineTimeout() = %s, want operation limit 100ms", got)
	}
}

func TestDeadlineTimeoutUsesRemainingTaskTimeWhenItIsShorter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	got := deadlineTimeout(ctx, 2*time.Second)
	if got <= 0 || got > 250*time.Millisecond {
		t.Fatalf("deadlineTimeout() = %s, want positive remaining task time no greater than 250ms", got)
	}
}

func TestDeadlineTimeoutUsesOperationLimitWithoutTaskDeadline(t *testing.T) {
	if got := deadlineTimeout(context.Background(), 3*time.Second); got != 3*time.Second {
		t.Fatalf("deadlineTimeout() = %s, want operation limit 3s", got)
	}
}
