package dnsengine

import (
	"context"
	"testing"
	"time"
)

func TestSelfCheckExercisesLocalUDPToTCPObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := SelfCheck(ctx)
	if !result.Ready || result.ReasonCode != SelfCheckReady {
		t.Fatalf("SelfCheck() = %+v", result)
	}
}

func TestSelfCheckRequiresBoundedLiveContext(t *testing.T) {
	if result := SelfCheck(context.Background()); result.Ready || result.ReasonCode != SelfCheckDeadlineExceeded {
		t.Fatalf("unbounded SelfCheck() = %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := SelfCheck(ctx); result.Ready || result.ReasonCode != SelfCheckDeadlineExceeded {
		t.Fatalf("cancelled SelfCheck() = %+v", result)
	}
}
