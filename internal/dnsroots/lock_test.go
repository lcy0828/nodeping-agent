package dnsroots

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagerLockHonorsContextAndSerializesWriters(t *testing.T) {
	manager := newTestManager(t, nil, time.Now().UTC())
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- manager.withLock(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	err := manager.withLock(ctx, func() error {
		t.Fatal("second writer entered while first held the lock")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second writer error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first writer: %v", err)
	}
}
