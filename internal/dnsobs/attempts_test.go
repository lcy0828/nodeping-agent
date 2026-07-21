package dnsobs

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAttemptTranscriptRequiresExplicitArray(t *testing.T) {
	valid := validObservation()
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "attempts")
	missing, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	object["attempts"] = json.RawMessage("null")
	nullValue, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{"missing": missing, "null": nullValue} {
		t.Run(name, func(t *testing.T) {
			var observation Observation
			if err := json.Unmarshal(candidate, &observation); err != nil {
				t.Fatal(err)
			}
			_, err := NormalizeObservation(observation)
			assertObservationValidationCode(t, err, "MISSING_ATTEMPT_TRANSCRIPT")
		})
	}
	if _, err := NormalizeObservation(unstartedCancellationObservation()); err != nil {
		t.Fatalf("explicit empty transcript: %v", err)
	}
}

func TestAttemptTranscriptAcceptsFivePhysicalSequences(t *testing.T) {
	for name, build := range map[string]func() Observation{
		"single": func() Observation { return validObservation() },
		"same protocol retry": func() Observation {
			observation := validObservation()
			setSameProtocolRetrySuccess(&observation)
			return observation
		},
		"UDP TCP": func() Observation {
			observation := validObservation()
			setSuccessfulFallback(&observation)
			return observation
		},
		"UDP UDP TCP": func() Observation { return threeAttemptFallbackObservation(false) },
		"UDP TCP TCP": func() Observation { return threeAttemptFallbackObservation(true) },
	} {
		t.Run(name, func(t *testing.T) {
			observation := build()
			normalized, err := NormalizeObservation(observation)
			if err != nil {
				t.Fatalf("NormalizeObservation: %v", err)
			}
			if normalized.AttemptCount != len(normalized.Attempts) || normalized.ResponseAttempt < 1 {
				t.Fatalf("normalized transcript = %+v", normalized)
			}
		})
	}
}

func TestAttemptTranscriptRejectsInvalidSequencesAndEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*Observation){
		"count mismatch": func(value *Observation) { value.AttemptCount++ },
		"same protocol after success": func(value *Observation) {
			setSameProtocolRetrySuccess(value)
			value.Attempts[0].TransportStatus = TransportSuccess
			value.Attempts[0].Error = nil
			value.Attempts[0].PeerIP = value.PeerIP
			value.Attempts[0].ResponseSizeBytes = 12
		},
		"nonretryable intermediate failure": func(value *Observation) {
			setSameProtocolRetrySuccess(value)
			value.Attempts[0].TransportStatus = TransportNetworkError
			value.Attempts[0].Error = &AttemptError{Code: "RESPONSE_TOO_LARGE"}
		},
		"fallback without TC": func(value *Observation) {
			setSuccessfulFallback(value)
			value.Attempts[0].ResponseTruncated = false
		},
		"final UDP TC without fallback": func(value *Observation) {
			value.Attempts[0].ResponseTruncated = true
			value.ResponseTruncated = true
			value.Flags.Truncated = true
		},
		"retried UDP TC without fallback": func(value *Observation) {
			setSameProtocolRetrySuccess(value)
			value.Attempts[1].ResponseTruncated = true
			value.ResponseTruncated = true
			value.Flags.Truncated = true
		},
		"failed TC": func(value *Observation) {
			setSuccessfulFallback(value)
			value.Attempts[0].TransportStatus = TransportTimeout
			value.Attempts[0].Error = &AttemptError{Code: "TIMEOUT", Retryable: true}
		},
		"short TC": func(value *Observation) {
			setSuccessfulFallback(value)
			value.Attempts[0].ResponseSizeBytes = 11
		},
		"TCP back to UDP": func(value *Observation) {
			*value = threeAttemptFallbackObservation(true)
			value.Attempts[2].Protocol = ProtocolUDP
			value.Protocol = ProtocolUDP
		},
		"overlap": func(value *Observation) {
			setSameProtocolRetrySuccess(value)
			value.Attempts[1].StartedAt = value.Attempts[0].FinishedAt.Add(-time.Nanosecond)
			value.Attempts[1].DurationMS = value.Attempts[1].FinishedAt.Sub(value.Attempts[1].StartedAt).Milliseconds()
		},
		"attempt error mismatch": func(value *Observation) {
			*value = observationWithOutcome(DNSOutcomeNotObserved)
			value.Attempts[0].Error.Code = "NETWORK_ERROR"
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := validObservation()
			mutate(&observation)
			if _, err := NormalizeObservation(observation); err == nil {
				t.Fatalf("invalid transcript accepted: %+v", observation)
			}
		})
	}
}

func TestRequestReservesUDPTruncationFallbackAttempt(t *testing.T) {
	request := validRequest()
	request.Limits.MaxAttempts = 1
	_, err := NormalizeRequest(request)
	assertObservationValidationCode(t, err, "UDP_FALLBACK_ATTEMPT_REQUIRED")

	request.Operations[0].Endpoint.Protocol = ProtocolTCP
	if _, err := NormalizeRequest(request); err != nil {
		t.Fatalf("single-attempt TCP request: %v", err)
	}
}

func TestResponseAttemptOwnsAllTopLevelResponseMetadata(t *testing.T) {
	base := validObservation()
	setFailedFallback(&base, TransportTimeout, AttemptError{Code: "TIMEOUT", Retryable: true})
	base.Error = &ObservationError{Code: "TIMEOUT", Message: "TCP fallback timed out", Retryable: true}

	for name, mutate := range map[string]func(*Observation){
		"zero owner":         func(value *Observation) { value.ResponseAttempt = 0 },
		"final failed owner": func(value *Observation) { value.ResponseAttempt = 2 },
		"peer":               func(value *Observation) { value.PeerIP = "1.1.1.1" },
		"size":               func(value *Observation) { value.ResponseSizeBytes++ },
		"TC":                 func(value *Observation) { value.ResponseTruncated = false; value.Flags.Truncated = false },
		"observed time":      func(value *Observation) { value.ObservedAt = value.ObservedAt.Add(time.Nanosecond) },
		"owner transport": func(value *Observation) {
			value.Attempts[0].TransportStatus = TransportTimeout
			value.Attempts[0].Error = &AttemptError{Code: "TIMEOUT", Retryable: true}
			value.Attempts[0].ResponseTruncated = false
		},
		"ambiguous UDP owner": func(value *Observation) {
			value.Attempts = append([]WireAttempt{value.Attempts[0]}, value.Attempts...)
			value.Attempts[1].StartedAt = value.Attempts[0].FinishedAt
			value.Attempts[0].FinishedAt = value.Attempts[0].StartedAt.Add(time.Millisecond)
			value.Attempts[0].DurationMS = 1
			value.AttemptCount = 3
			value.ResponseAttempt = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := cloneObservation(base)
			mutate(&observation)
			if _, err := NormalizeObservation(observation); err == nil {
				t.Fatalf("owner mutation accepted: %+v", observation)
			}
		})
	}
}

func TestAttemptTranscriptAllowsOnlyRetryGapCancellationOrDeadline(t *testing.T) {
	for _, terminal := range []struct {
		status TransportStatus
		code   string
	}{
		{status: TransportCancelled, code: "CANCELLED"},
		{status: TransportTimeout, code: "TIMEOUT"},
	} {
		observation := observationWithOutcome(DNSOutcomeNotObserved)
		observation.Attempts[0].TransportStatus = TransportNetworkError
		observation.Attempts[0].Error = &AttemptError{Code: "NETWORK_ERROR", Retryable: true}
		observation.Attempts[0].FinishedAt = observation.FinishedAt.Add(-2 * time.Millisecond)
		observation.Attempts[0].DurationMS = observation.Attempts[0].FinishedAt.Sub(observation.Attempts[0].StartedAt).Milliseconds()
		observation.TransportStatus = terminal.status
		observation.Error = &ObservationError{Code: terminal.code, Message: "operation terminated in retry gap", Retryable: terminal.status == TransportTimeout}
		if _, err := NormalizeObservation(observation); err != nil {
			t.Fatalf("gap %s: %v", terminal.status, err)
		}

		invalid := cloneObservation(observation)
		invalid.Attempts[0].TransportStatus = TransportNetworkError
		invalid.Attempts[0].Error = &AttemptError{Code: "RESPONSE_TOO_LARGE"}
		if _, err := NormalizeObservation(invalid); err == nil {
			t.Fatalf("nonretryable gap %s accepted", terminal.status)
		}
	}

	exhausted := observationWithOutcome(DNSOutcomeNotObserved)
	firstFinished := exhausted.StartedAt.Add(4 * time.Millisecond)
	secondStarted := firstFinished.Add(time.Millisecond)
	exhausted.AttemptCount = 2
	exhausted.Attempts = []WireAttempt{
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: exhausted.StartedAt, FinishedAt: firstFinished, DurationMS: 4, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
		{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: secondStarted, FinishedAt: exhausted.FinishedAt, DurationMS: exhausted.FinishedAt.Sub(secondStarted).Milliseconds(), Error: &AttemptError{Code: "TIMEOUT", Retryable: true}},
	}
	exhausted.TransportStatus = TransportCancelled
	exhausted.Error = &ObservationError{Code: "CANCELLED", Message: "cancelled after retry"}
	if _, err := NormalizeObservation(exhausted); err == nil {
		t.Fatal("gap override after the same-protocol retry was exhausted")
	}
}

func TestBatchRejectsRetryGapWithoutFrozenAttemptBudget(t *testing.T) {
	request := validRequest()
	request.Limits.MaxAttempts = 2
	observation := observationForOperation(request.RoundID, request.Operations[0])
	setFailedFallback(&observation, TransportTimeout, AttemptError{Code: "TIMEOUT", Retryable: true})
	observation.TransportStatus = TransportCancelled
	observation.Error = &ObservationError{Code: "CANCELLED", Message: "cancelled in retry gap"}
	if _, err := NormalizeObservation(observation); err != nil {
		t.Fatalf("standalone gap shape: %v", err)
	}
	_, err := NormalizeBatchResultForRequest(request, BatchResult{Schema: SchemaV1, RoundID: request.RoundID, Observations: []Observation{observation}})
	assertObservationValidationCode(t, err, "RETRY_GAP_BUDGET_EXCEEDED")
}

func TestZeroAttemptInternalFailureIsDistinctFromUnstartedCancellation(t *testing.T) {
	internal := unstartedCancellationObservation()
	internal.TransportStatus = TransportNetworkError
	internal.FinishedAt = internal.StartedAt.Add(2 * time.Millisecond)
	internal.ObservedAt = internal.FinishedAt
	internal.DurationMS = 2
	internal.Error = &ObservationError{Code: "INTERNAL_ERROR", Message: "DNS operation failed after execution started"}
	if _, err := NormalizeObservation(internal); err != nil {
		t.Fatalf("zero-attempt internal failure: %v", err)
	}

	wrongCancel := internal
	wrongCancel.TransportStatus = TransportCancelled
	wrongCancel.Error = &ObservationError{Code: "CANCELLED", Message: "cancelled"}
	if _, err := NormalizeObservation(wrongCancel); err == nil {
		t.Fatal("elapsed zero-attempt cancellation accepted")
	}
	wrongInternal := unstartedCancellationObservation()
	wrongInternal.TransportStatus = TransportNetworkError
	wrongInternal.Error = &ObservationError{Code: "NETWORK_ERROR", Message: "network error", Retryable: true}
	if _, err := NormalizeObservation(wrongInternal); err == nil {
		t.Fatal("zero-attempt wire error accepted as internal failure")
	}
}

func TestNormalizeObservationDeepClonesAttemptErrors(t *testing.T) {
	input := observationWithOutcome(DNSOutcomeNotObserved)
	input.Attempts[0].Error.Code = " timeout "
	input.Error.Code = " timeout "
	normalized, err := NormalizeObservation(input)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Attempts[0].Error.Code != "TIMEOUT" || input.Attempts[0].Error.Code != " timeout " {
		t.Fatalf("attempt error clone input=%q normalized=%q", input.Attempts[0].Error.Code, normalized.Attempts[0].Error.Code)
	}
}

func threeAttemptFallbackObservation(tcpRetry bool) Observation {
	observation := validObservation()
	firstFinished := observation.StartedAt.Add(2 * time.Millisecond)
	secondStarted := firstFinished.Add(time.Millisecond)
	secondFinished := secondStarted.Add(2 * time.Millisecond)
	thirdStarted := secondFinished.Add(time.Millisecond)
	first := WireAttempt{Protocol: ProtocolUDP, TransportStatus: TransportTimeout, StartedAt: observation.StartedAt, FinishedAt: firstFinished, DurationMS: 2, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}}
	second := WireAttempt{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: secondStarted, FinishedAt: secondFinished, DurationMS: 2, PeerIP: observation.PeerIP, ResponseSizeBytes: 28, ResponseTruncated: true}
	if tcpRetry {
		first = WireAttempt{Protocol: ProtocolUDP, TransportStatus: TransportSuccess, StartedAt: observation.StartedAt, FinishedAt: firstFinished, DurationMS: 2, PeerIP: observation.PeerIP, ResponseSizeBytes: 28, ResponseTruncated: true}
		second = WireAttempt{Protocol: ProtocolTCP, TransportStatus: TransportTimeout, StartedAt: secondStarted, FinishedAt: secondFinished, DurationMS: 2, Error: &AttemptError{Code: "TIMEOUT", Retryable: true}}
	}
	observation.Protocol = ProtocolTCP
	observation.UDPToTCPFallback = true
	observation.AttemptCount = 3
	observation.Attempts = []WireAttempt{
		first,
		second,
		{Protocol: ProtocolTCP, TransportStatus: TransportSuccess, StartedAt: thirdStarted, FinishedAt: observation.FinishedAt, DurationMS: observation.FinishedAt.Sub(thirdStarted).Milliseconds(), PeerIP: observation.PeerIP, ResponseSizeBytes: observation.ResponseSizeBytes},
	}
	observation.ResponseAttempt = 3
	return observation
}

func assertObservationValidationCode(t testing.TB, err error, code string) {
	t.Helper()
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != code {
		t.Fatalf("error = %#v, want validation code %s", err, code)
	}
}
