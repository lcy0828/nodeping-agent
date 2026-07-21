package dnstapcollector

import (
	"context"
	"testing"
	"time"
)

func TestSelfCheckExercisesListenerHandshakeDecodeAndPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := SelfCheck(ctx, "")
	if !result.Ready || result.ReasonCode != SelfCheckReady {
		t.Fatalf("self-check = %+v", result)
	}
}

func TestSelfCheckFailsClosedWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := SelfCheck(ctx, "")
	if result.Ready || result.ReasonCode == SelfCheckReady {
		t.Fatalf("self-check = %+v", result)
	}
}
