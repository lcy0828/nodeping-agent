package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nodeping/internal/dnsengine"
	"nodeping/internal/dnsobs"
	"nodeping/internal/systemdns"

	"github.com/miekg/dns"
)

type dnsObserverStep func(context.Context, dnsengine.Endpoint, dnsengine.Query) (*dnsengine.Result, error)

type scriptedDNSObserver struct {
	mu        sync.Mutex
	steps     []dnsObserverStep
	protocols []dnsengine.Protocol
	endpoints []dnsengine.Endpoint
}

func (o *scriptedDNSObserver) Observe(ctx context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
	o.mu.Lock()
	o.protocols = append(o.protocols, endpoint.Protocol)
	o.endpoints = append(o.endpoints, endpoint)
	if len(o.steps) == 0 {
		o.mu.Unlock()
		return nil, errors.New("unexpected DNS exchange")
	}
	step := o.steps[0]
	o.steps = o.steps[1:]
	o.mu.Unlock()
	return step(ctx, endpoint, query)
}

func (o *scriptedDNSObserver) observedEndpoints() []dnsengine.Endpoint {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]dnsengine.Endpoint(nil), o.endpoints...)
}

func (o *scriptedDNSObserver) observedProtocols() []dnsengine.Protocol {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]dnsengine.Protocol(nil), o.protocols...)
}

type delayedDNSObserver struct {
	delay time.Duration
}

func (o delayedDNSObserver) Observe(ctx context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
	timer := time.NewTimer(o.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return failedDNSResult(endpoint, query, ctx.Err()), ctx.Err()
	case <-timer.C:
		return successfulDNSResult(endpoint, query), nil
	}
}

type blockingDNSObserver struct {
	started chan<- struct{}
}

func (o blockingDNSObserver) Observe(ctx context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
	select {
	case o.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return failedDNSResult(endpoint, query, ctx.Err()), ctx.Err()
}

type countingDNSObserver struct {
	active atomic.Int32
	max    atomic.Int32
	delay  time.Duration
}

func (o *countingDNSObserver) Observe(ctx context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
	active := o.active.Add(1)
	defer o.active.Add(-1)
	for {
		maximum := o.max.Load()
		if active <= maximum || o.max.CompareAndSwap(maximum, active) {
			break
		}
	}
	timer := time.NewTimer(o.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return failedDNSResult(endpoint, query, ctx.Err()), ctx.Err()
	case <-timer.C:
		return successfulDNSResult(endpoint, query), nil
	}
}

func TestDecodeDNSObservationRequestIsStrictAndBounded(t *testing.T) {
	raw, err := json.Marshal(testDNSRequest("round-strict", 1, 3))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if _, err := decodeDNSObservationRequest(raw); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	unknown := append([]byte(`{"unexpected":true,`), raw[1:]...)
	if _, err := decodeDNSObservationRequest(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	trailing := append(append([]byte(nil), raw...), []byte(` {}`)...)
	if _, err := decodeDNSObservationRequest(trailing); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("trailing JSON error = %v", err)
	}
	oversized := json.RawMessage(strings.Repeat(" ", dnsobs.MaxEventBytes+1))
	if _, err := decodeDNSObservationRequest(oversized); err == nil {
		t.Fatal("oversized DNS task payload was accepted")
	} else {
		var tooLarge *agentPayloadTooLargeError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("oversized error = %T %v", err, err)
		}
	}
}

func TestSystemDNSPortIsRejectedBeforeDiscoveryOrEngineInitialization(t *testing.T) {
	request := testSystemDNSRequest("round-invalid-system-port")
	request.Operations[0].Endpoint.Port = 5353
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, decodeErr := decodeDNSObservationRequest(raw); decodeErr == nil {
		t.Fatal("invalid system DNS port decoded successfully")
	} else {
		var taskErr *dnsTaskError
		if !errors.As(decodeErr, &taskErr) || taskErr.Code != "INVALID_SYSTEM_DNS_PORT" {
			t.Fatalf("decode error = %#v", decodeErr)
		}
	}

	plannerCalls := 0
	factoryCalls := 0
	_, executeErr := executeDNSObservationRequestWithDependencies(
		context.Background(),
		request,
		func(time.Duration, uint16) (dnsWireObserver, error) {
			factoryCalls++
			return delayedDNSObserver{}, nil
		},
		newDNSOperationGate(1),
		nil,
		func(context.Context) error { return nil },
		func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
			plannerCalls++
			return nil, nil
		},
	)
	var validationErr *dnsobs.ValidationError
	if !errors.As(executeErr, &validationErr) || validationErr.Code != "INVALID_SYSTEM_DNS_PORT" || plannerCalls != 0 || factoryCalls != 0 {
		t.Fatalf("execute error=%#v planner_calls=%d factory_calls=%d", executeErr, plannerCalls, factoryCalls)
	}
}

func TestDefaultDNSWireEngineFactoryAcceptsContractLimits(t *testing.T) {
	observer, err := defaultDNSWireEngineFactory(500*time.Millisecond, dnsobs.DefaultEDNSUDPSize)
	if err != nil || observer == nil {
		t.Fatalf("default DNS wire engine: observer=%v err=%v", observer, err)
	}
}

func TestDNSObserveCapabilityCannotBeDispatchedAsTask(t *testing.T) {
	result := executeTask(context.Background(), config{}, taskRequest{ID: "task-capability", TaskType: dnsObserveCapability})
	if result.Success || result.Status != "failed" || result.ErrorCode != "UNSUPPORTED_TASK" {
		t.Fatalf("direct capability task result = %+v", result)
	}
}

func TestDNSObservationCompletionEventsAndFinalOrder(t *testing.T) {
	request := testDNSRequest("round-order", 2, 3)
	observers := []dnsWireObserver{
		delayedDNSObserver{delay: 60 * time.Millisecond},
		delayedDNSObserver{delay: 5 * time.Millisecond},
	}
	factory := observerSequenceFactory(observers...)
	var events []string
	batch, err := executeDNSObservationRequest(context.Background(), request, factory, newDNSOperationGate(2), func(observation dnsobs.Observation, _, _ int) error {
		events = append(events, observation.OperationID)
		return nil
	})
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	if got := strings.Join(events, ","); got != "op-2,op-1" {
		t.Fatalf("completion event order = %s", got)
	}
	if len(batch.Observations) != 2 || batch.Observations[0].OperationID != "op-1" || batch.Observations[1].OperationID != "op-2" {
		t.Fatalf("final batch order = %+v", batch.Observations)
	}
}

func TestDNSObservationInternalFailureStillReturnsCompleteBatch(t *testing.T) {
	request := testDNSRequest("round-internal", 2, 3)
	badObserver := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			result := successfulDNSResult(endpoint, query)
			result.Question.Name = "other.example."
			return result, nil
		},
	}}
	events := make(map[string]dnsobs.Observation)
	batch, executeErr := executeDNSObservationRequest(
		context.Background(),
		request,
		observerSequenceFactory(delayedDNSObserver{}, badObserver),
		newDNSOperationGate(2),
		func(observation dnsobs.Observation, _, _ int) error {
			events[observation.OperationID] = observation
			return nil
		},
	)
	if executeErr == nil || !strings.Contains(executeErr.Error(), "conversion failed") {
		t.Fatalf("internal execution error = %v", executeErr)
	}
	if len(batch.Observations) != len(request.Operations) {
		t.Fatalf("complete batch observations = %+v", batch.Observations)
	}
	if batch.Observations[0].OperationID != "op-1" || batch.Observations[0].TransportStatus != dnsobs.TransportSuccess {
		t.Fatalf("successful observation = %+v", batch.Observations[0])
	}
	failure := batch.Observations[1]
	if failure.OperationID != "op-2" || failure.TransportStatus != dnsobs.TransportNetworkError || failure.AttemptCount != 0 || failure.Attempts == nil || failure.ResponseAttempt != 0 || failure.Outcome != dnsobs.DNSOutcomeNotObserved || failure.PeerIP != "" || failure.ResponseSizeBytes != 0 {
		t.Fatalf("internal failure observation = %+v", failure)
	}
	if failure.Error == nil || failure.Error.Code != "INTERNAL_ERROR" || failure.Error.Retryable || failure.Comparison != dnsobs.ComparisonUnknown || failure.DNSSEC.Status != dnsobs.DNSSECIndeterminate {
		t.Fatalf("internal failure contract = %+v", failure)
	}
	if len(events) != 2 || events["op-1"].Schema == "" || events["op-2"].Schema == "" {
		t.Fatalf("completion events = %+v", events)
	}
	if _, err := dnsobs.NormalizeBatchResultForRequest(request, batch); err != nil {
		t.Fatalf("normalize complete failure batch: %v", err)
	}
}

func TestDNSObservationEmitFailureKeepsNormalizedFinalBatch(t *testing.T) {
	request := testDNSRequest("round-emit-failure", 2, 3)
	var emitted int
	batch, executeErr := executeDNSObservationRequest(
		context.Background(),
		request,
		observerSequenceFactory(delayedDNSObserver{}, delayedDNSObserver{}),
		newDNSOperationGate(2),
		func(dnsobs.Observation, int, int) error {
			emitted++
			return errors.New("event delivery failed")
		},
	)
	if executeErr == nil || !strings.Contains(executeErr.Error(), "event delivery failed") {
		t.Fatalf("emit error = %v", executeErr)
	}
	if emitted != 2 || len(batch.Observations) != 2 || batch.Observations[0].OperationID != "op-1" || batch.Observations[1].OperationID != "op-2" {
		t.Fatalf("final batch after emit failure = %+v; emitted=%d", batch, emitted)
	}
	if _, err := dnsobs.NormalizeBatchResultForRequest(request, batch); err != nil {
		t.Fatalf("normalize emit-failure batch: %v", err)
	}
}

func TestDNSObservationMissingWireResultProducesBoundedInternalObservation(t *testing.T) {
	request := testDNSRequest("round-missing-wire-result", 1, 3)
	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(context.Context, dnsengine.Endpoint, dnsengine.Query) (*dnsengine.Result, error) {
			return nil, errors.New("observer contract failure")
		},
	}}
	batch, executeErr := executeDNSObservationRequest(context.Background(), request, observerSequenceFactory(observer), newDNSOperationGate(1), nil)
	if executeErr == nil || !strings.Contains(executeErr.Error(), "returned no DNS wire result") {
		t.Fatalf("missing result error = %v", executeErr)
	}
	if len(batch.Observations) != 1 || batch.Observations[0].AttemptCount != 0 || batch.Observations[0].Attempts == nil || batch.Observations[0].ResponseAttempt != 0 || batch.Observations[0].TransportStatus != dnsobs.TransportNetworkError || batch.Observations[0].Error == nil || batch.Observations[0].Error.Code != "INTERNAL_ERROR" {
		t.Fatalf("missing result observation = %+v", batch.Observations)
	}
}

func TestDNSObservationCancellationMarksUnstartedOperation(t *testing.T) {
	request := testDNSRequest("round-cancel", 2, 3)
	request.Limits.Parallel = 1
	started := make(chan struct{}, 1)
	factory := observerSequenceFactory(
		blockingDNSObserver{started: started},
		delayedDNSObserver{},
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var batch dnsobs.BatchResult
	var executeErr error
	go func() {
		defer close(done)
		batch, executeErr = executeDNSObservationRequest(ctx, request, factory, newDNSOperationGate(1), nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first operation did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled batch did not finish")
	}
	if executeErr != nil {
		t.Fatalf("cancelled observations should form a valid batch: %v", executeErr)
	}
	if batch.Observations[0].TransportStatus != dnsobs.TransportCancelled || batch.Observations[0].AttemptCount != 1 {
		t.Fatalf("started cancellation = %+v", batch.Observations[0])
	}
	if batch.Observations[1].TransportStatus != dnsobs.TransportCancelled || batch.Observations[1].AttemptCount != 0 || batch.Observations[1].Outcome != dnsobs.DNSOutcomeNotObserved {
		t.Fatalf("unstarted cancellation = %+v", batch.Observations[1])
	}
}

func TestProcessDNSOperationGateCapsConcurrentTasks(t *testing.T) {
	observer := &countingDNSObserver{delay: 20 * time.Millisecond}
	gate := newDNSOperationGate(2)
	factory := func(time.Duration, uint16) (dnsWireObserver, error) { return observer, nil }
	requests := []dnsobs.Request{
		testDNSRequest("round-gate-a", 4, 3),
		testDNSRequest("round-gate-b", 4, 3),
	}
	var wait sync.WaitGroup
	errorsCh := make(chan error, len(requests))
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := executeDNSObservationRequest(context.Background(), request, factory, gate, nil)
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("execute gated request: %v", err)
		}
	}
	if maximum := observer.max.Load(); maximum != 2 {
		t.Fatalf("process operation concurrency = %d, want 2", maximum)
	}
}

func TestDNSRetryMatrix(t *testing.T) {
	t.Run("udp timeout retry then TC fallback", func(t *testing.T) {
		observer := &scriptedDNSObserver{steps: []dnsObserverStep{
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return failedDNSResult(endpoint, query, context.DeadlineExceeded), context.DeadlineExceeded
			},
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return successfulFallbackDNSResult(endpoint, query), nil
			},
		}}
		observation := executeSingleDNSOperation(t, observer)
		if got := observer.observedProtocols(); len(got) != 2 || got[0] != dnsengine.ProtocolUDP || got[1] != dnsengine.ProtocolUDP {
			t.Fatalf("wire calls = %v", got)
		}
		if observation.AttemptCount != 3 || !observation.UDPToTCPFallback || observation.Protocol != dnsobs.ProtocolTCP || observation.TransportStatus != dnsobs.TransportSuccess {
			t.Fatalf("observation = %+v", observation)
		}
	})

	t.Run("failed TCP fallback retries only TCP", func(t *testing.T) {
		observer := &scriptedDNSObserver{steps: []dnsObserverStep{
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return retainedHeaderFallbackResult(endpoint, query), context.DeadlineExceeded
			},
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return successfulDNSResult(endpoint, query), nil
			},
		}}
		observation := executeSingleDNSOperation(t, observer)
		if got := observer.observedProtocols(); len(got) != 2 || got[0] != dnsengine.ProtocolUDP || got[1] != dnsengine.ProtocolTCP {
			t.Fatalf("wire calls = %v", got)
		}
		if observation.AttemptCount != 3 || !observation.UDPToTCPFallback || observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeAnswer {
			t.Fatalf("observation = %+v", observation)
		}
	})

	t.Run("malformed TCP retry replaces old UDP header", func(t *testing.T) {
		observer := &scriptedDNSObserver{steps: []dnsObserverStep{
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return retainedHeaderFallbackResult(endpoint, query), context.DeadlineExceeded
			},
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return malformedDNSResult(endpoint, query), dnsengine.ErrMalformedResponse
			},
		}}
		observation := executeSingleDNSOperation(t, observer)
		if observation.AttemptCount != 3 || observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeMalformed || observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" || observation.Error.Retryable {
			t.Fatalf("observation = %+v", observation)
		}
		if observation.RCode != nil || observation.Flags != (dnsobs.DNSFlags{}) || observation.Sections.RecordCount() != 0 || observation.ResponseSizeBytes != 8 {
			t.Fatalf("malformed TCP retry retained old UDP evidence: %+v", observation)
		}
	})

	t.Run("only final validated TCP TC header is retained", func(t *testing.T) {
		observer := &scriptedDNSObserver{steps: []dnsObserverStep{
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return retainedHeaderFallbackResult(endpoint, query), context.DeadlineExceeded
			},
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return malformedTCPHeaderResult(endpoint, query), dnsengine.ErrMalformedResponse
			},
		}}
		observation := executeSingleDNSOperation(t, observer)
		if observation.AttemptCount != 3 || observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeTruncatedResponse || observation.RCode == nil || *observation.RCode != dns.RcodeRefused || observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" {
			t.Fatalf("observation = %+v", observation)
		}
	})

	t.Run("malformed UDP response is not retried", func(t *testing.T) {
		observer := &scriptedDNSObserver{steps: []dnsObserverStep{
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				return malformedDNSResult(endpoint, query), dnsengine.ErrMalformedResponse
			},
			func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
				t.Fatal("malformed response was retried")
				return nil, nil
			},
		}}
		observation := executeSingleDNSOperation(t, observer)
		if len(observer.observedProtocols()) != 1 || observation.AttemptCount != 1 || observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeMalformed {
			t.Fatalf("observation = %+v; calls=%v", observation, observer.observedProtocols())
		}
	})
}

func TestDNSRetryRealEnginePreservesThirdMalformedTCPHeader(t *testing.T) {
	endpoint, responseSizes, serverDone := startThirdTCPMalformedResolver(t)
	engine, err := dnsengine.New(dnsengine.Config{
		Timeout:               40 * time.Millisecond,
		UDPSize:               dnsobs.DefaultEDNSUDPSize,
		MaxResponseBytes:      dnsengine.DefaultMaxResponseBytes,
		MaxRecordsPerSection:  dnsobs.DefaultSectionRecordLimit,
		AllowPrivateConnectIP: true,
	})
	if err != nil {
		t.Fatalf("new DNS engine: %v", err)
	}
	operation := dnsobs.Operation{
		OperationID: "op-real-fallback",
		Mode:        dnsobs.ModeRecursive,
		Question:    dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
		Endpoint:    dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53},
		Flags:       dnsobs.QueryFlags{RecursionDesired: true, EDNSUDPSize: dnsobs.DefaultEDNSUDPSize},
	}
	prepared := preparedDNSOperation{
		operation: operation,
		endpoint:  endpoint,
		query: dnsengine.Query{
			Name: operation.Question.Name, Type: dns.TypeA, Class: dns.ClassINET,
			Mode: dnsengine.QueryModeRecursive, RecursionDesired: true,
		},
		observer: engine,
	}
	started := time.Now().UTC()
	observation, err := executePreparedDNSOperation(
		context.Background(),
		"round-real-fallback",
		dnsobs.Limits{Parallel: 1, AttemptTimeoutMS: 40, MaxAttempts: 3},
		prepared,
		func(context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("execute real fallback: %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("real fallback resolver: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real fallback resolver did not finish")
	}
	responseSize := <-responseSizes

	if observation.AttemptCount != 3 || !observation.UDPToTCPFallback || observation.Protocol != dnsobs.ProtocolTCP {
		t.Fatalf("physical fallback attempts = %+v", observation)
	}
	if observation.TransportStatus != dnsobs.TransportSuccess || observation.Outcome != dnsobs.DNSOutcomeTruncatedResponse || observation.Error == nil || observation.Error.Code != "MALFORMED_DNS" || observation.Error.Retryable {
		t.Fatalf("third TCP classification = %+v", observation)
	}
	if observation.RCode == nil || *observation.RCode != dns.RcodeRefused || !observation.Flags.Response || !observation.Flags.Authoritative || !observation.Flags.Truncated || !observation.Flags.CheckingDisabled || observation.Flags.RecursionAvailable {
		t.Fatalf("third TCP header evidence = %+v", observation)
	}
	if observation.PeerIP != "127.0.0.1" || observation.ResponseSizeBytes != responseSize {
		t.Fatalf("third TCP provenance = peer %q size %d, want 127.0.0.1/%d", observation.PeerIP, observation.ResponseSizeBytes, responseSize)
	}
	if observation.StartedAt.Before(started) || observation.ObservedAt.Before(observation.StartedAt) || observation.ObservedAt.After(observation.FinishedAt) || !observation.ObservedAt.Before(observation.FinishedAt) || observation.DurationMS != observation.FinishedAt.Sub(observation.StartedAt).Milliseconds() {
		t.Fatalf("operation timeline = %s/%s/%s duration=%d", observation.StartedAt, observation.ObservedAt, observation.FinishedAt, observation.DurationMS)
	}
}

func TestDNSInternalFailurePreservesThreeAttemptFallbackMetadata(t *testing.T) {
	request := testDNSRequest("round-internal-fallback", 1, 3)
	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			result := successfulFallbackDNSResult(endpoint, query)
			first := dnsengine.Attempt{
				Protocol: dnsengine.ProtocolUDP, StartedAt: result.StartedAt,
				Error: context.DeadlineExceeded.Error(),
			}
			result.Attempts = append([]dnsengine.Attempt{first}, result.Attempts...)
			result.Question.Name = "other.example."
			return result, nil
		},
	}}
	batch, executeErr := executeDNSObservationRequestWithRetryWait(
		context.Background(), request, observerSequenceFactory(observer), newDNSOperationGate(1), nil,
		func(context.Context) error { return nil },
	)
	if executeErr == nil || !strings.Contains(executeErr.Error(), "conversion failed") {
		t.Fatalf("conversion error = %v", executeErr)
	}
	if len(batch.Observations) != 1 {
		t.Fatalf("internal fallback batch = %+v", batch)
	}
	failure := batch.Observations[0]
	if failure.AttemptCount != 0 || failure.Attempts == nil || failure.ResponseAttempt != 0 || failure.UDPToTCPFallback || failure.Protocol != dnsobs.ProtocolUDP || failure.Outcome != dnsobs.DNSOutcomeNotObserved || failure.Error == nil || failure.Error.Code != "INTERNAL_ERROR" {
		t.Fatalf("internal fallback provenance = %+v", failure)
	}
}

func TestDNSFailureFallbackMetadataRequiresRealRetryErrors(t *testing.T) {
	cleanUDPTrigger := dnsengine.Attempt{Protocol: dnsengine.ProtocolUDP, Truncated: true}
	failedUDP := dnsengine.Attempt{Protocol: dnsengine.ProtocolUDP, Error: context.DeadlineExceeded.Error()}
	failedTCP := dnsengine.Attempt{Protocol: dnsengine.ProtocolTCP, Error: context.DeadlineExceeded.Error()}
	finalTCP := dnsengine.Attempt{Protocol: dnsengine.ProtocolTCP}

	tests := []struct {
		name     string
		attempts []dnsengine.Attempt
		want     bool
	}{
		{name: "direct fallback", attempts: []dnsengine.Attempt{cleanUDPTrigger, finalTCP}, want: true},
		{name: "UDP retry then fallback", attempts: []dnsengine.Attempt{failedUDP, cleanUDPTrigger, finalTCP}, want: true},
		{name: "TCP fallback retry", attempts: []dnsengine.Attempt{cleanUDPTrigger, failedTCP, finalTCP}, want: true},
		{name: "UDP retry missing error", attempts: []dnsengine.Attempt{{Protocol: dnsengine.ProtocolUDP}, cleanUDPTrigger, finalTCP}},
		{name: "TCP retry missing error", attempts: []dnsengine.Attempt{cleanUDPTrigger, dnsengine.Attempt{Protocol: dnsengine.ProtocolTCP}, finalTCP}},
		{name: "TC trigger carries transport error", attempts: []dnsengine.Attempt{{Protocol: dnsengine.ProtocolUDP, Truncated: true, Error: context.DeadlineExceeded.Error()}, finalTCP}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validDNSFailureFallbackAttempts(test.attempts); got != test.want {
				t.Fatalf("validDNSFailureFallbackAttempts()=%t, want %t for %+v", got, test.want, test.attempts)
			}
		})
	}
}

func TestDNSRetryJitterIsBoundedAndCancellationStopsRetry(t *testing.T) {
	for range 1000 {
		delay := dnsRetryJitterDuration()
		if delay < minDNSRetryJitter || delay > maxDNSRetryJitter {
			t.Fatalf("retry jitter = %s, want [%s,%s]", delay, minDNSRetryJitter, maxDNSRetryJitter)
		}
	}

	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return failedDNSResult(endpoint, query, context.DeadlineExceeded), context.DeadlineExceeded
		},
		func(_ context.Context, _ dnsengine.Endpoint, _ dnsengine.Query) (*dnsengine.Result, error) {
			t.Fatal("wire retry ran after cancellation during jitter")
			return nil, nil
		},
	}}
	waiting := make(chan struct{}, 1)
	waiter := func(ctx context.Context) error {
		waiting <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var batch dnsobs.BatchResult
	var executeErr error
	go func() {
		defer close(done)
		batch, executeErr = executeDNSObservationRequestWithRetryWait(ctx, testDNSRequest("round-jitter-cancel", 1, 3), observerSequenceFactory(observer), newDNSOperationGate(1), nil, waiter)
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("retry did not enter jitter wait")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("jitter cancellation did not finish")
	}
	if executeErr != nil {
		t.Fatalf("cancelled retry should produce a valid observation: %v", executeErr)
	}
	if len(observer.observedProtocols()) != 1 || batch.Observations[0].AttemptCount != 1 || batch.Observations[0].TransportStatus != dnsobs.TransportCancelled {
		t.Fatalf("cancelled jitter observation=%+v calls=%v", batch.Observations[0], observer.observedProtocols())
	}
}

func TestDoHEndpointKeepsAuthoritySNIAndConnectIPIndependent(t *testing.T) {
	endpoint, err := dnsEngineEndpoint(dnsobs.Endpoint{
		Kind:          dnsobs.EndpointCatalog,
		Protocol:      dnsobs.ProtocolDoH,
		ConnectIP:     "8.8.8.8",
		ServerName:    "certificate.example",
		HTTPAuthority: "resolver.example",
		Port:          8443,
		HTTPPath:      "/custom%2Fdns-query",
	})
	if err != nil {
		t.Fatalf("build DoH endpoint: %v", err)
	}
	parsed, err := url.Parse(endpoint.Address)
	if err != nil {
		t.Fatalf("parse DoH URL: %v", err)
	}
	if parsed.Host != "resolver.example:8443" || parsed.EscapedPath() != "/custom%2Fdns-query" || endpoint.ConnectIP != "8.8.8.8" || endpoint.ServerName != "certificate.example" {
		t.Fatalf("DoH endpoint = %+v; URL=%+v", endpoint, parsed)
	}
}

func TestUnavailableIterativeDNSModeFailsClosedBeforeWireExecution(t *testing.T) {
	var factoryCalls int
	request := dnsobs.Request{
		Schema: dnsobs.SchemaV1, RoundID: "round-unavailable-iterative",
		Operations: []dnsobs.Operation{{
			OperationID: "op-iterative", Mode: dnsobs.ModeIterative,
			Question: dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeNS, Class: dnsobs.DNSClassIN},
			Endpoint: dnsobs.Endpoint{Kind: dnsobs.EndpointRootHints, Protocol: dnsobs.ProtocolUDP, Port: 53},
			Flags:    dnsobs.QueryFlags{EDNSUDPSize: 1232},
		}},
		Limits: dnsobs.Limits{Parallel: 1, AttemptTimeoutMS: 100, MaxAttempts: 3},
	}
	_, err := executeDNSObservationRequest(context.Background(), request, func(time.Duration, uint16) (dnsWireObserver, error) {
		factoryCalls++
		return delayedDNSObserver{}, nil
	}, newDNSOperationGate(1), nil)
	var taskErr *dnsTaskError
	if !errors.As(err, &taskErr) || taskErr.Code != "CAPABILITY_UNAVAILABLE" || factoryCalls != 0 {
		t.Fatalf("fail-closed error=%#v factory_calls=%d", err, factoryCalls)
	}
}

func TestSystemDNSOrdinaryRetryUsesNextSelectedResolver(t *testing.T) {
	for _, test := range []struct {
		name          string
		endpoints     []dnsengine.Endpoint
		wantAddresses []string
	}{
		{
			name: "next resolver",
			endpoints: []dnsengine.Endpoint{
				{Protocol: dnsengine.ProtocolUDP, Address: "10.0.0.53", ConnectIP: "10.0.0.53", Port: 53},
				{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.54", ConnectIP: "127.0.0.54", Port: 53},
			},
			wantAddresses: []string{"10.0.0.53", "127.0.0.54"},
		},
		{
			name: "single resolver reused",
			endpoints: []dnsengine.Endpoint{
				{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.53", ConnectIP: "127.0.0.53", Port: 53},
			},
			wantAddresses: []string{"127.0.0.53", "127.0.0.53"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := &scriptedDNSObserver{steps: []dnsObserverStep{
				func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
					result := setDNSResultPeer(failedDNSResult(endpoint, query, context.DeadlineExceeded), endpoint.ConnectIP)
					return result, context.DeadlineExceeded
				},
				func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
					return setDNSResultPeer(successfulDNSResult(endpoint, query), endpoint.ConnectIP), nil
				},
			}}
			plannerCalls := 0
			planner := func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
				plannerCalls++
				return map[int][]dnsengine.Endpoint{0: append([]dnsengine.Endpoint(nil), test.endpoints...)}, nil
			}
			batch, executeErr := executeDNSObservationRequestWithDependencies(
				context.Background(),
				testSystemDNSRequest("round-system-retry"),
				observerSequenceFactory(observer),
				newDNSOperationGate(1),
				nil,
				func(context.Context) error { return nil },
				planner,
			)
			if executeErr != nil {
				t.Fatalf("execute system request: %v", executeErr)
			}
			calls := observer.observedEndpoints()
			if plannerCalls != 1 || len(calls) != 2 {
				t.Fatalf("planner_calls=%d endpoint_calls=%+v", plannerCalls, calls)
			}
			for index, want := range test.wantAddresses {
				if calls[index].Address != want || calls[index].Protocol != dnsengine.ProtocolUDP {
					t.Fatalf("endpoint call %d = %+v, want address=%s protocol=udp", index, calls[index], want)
				}
			}
			observation := batch.Observations[0]
			if observation.Endpoint.Kind != dnsobs.EndpointSystem || observation.AttemptCount != 2 || observation.ResponseAttempt != 2 || observation.PeerIP != test.wantAddresses[1] {
				t.Fatalf("system retry observation = %+v", observation)
			}
			if observation.Attempts[0].PeerIP != test.wantAddresses[0] || observation.Attempts[1].PeerIP != test.wantAddresses[1] || observation.Attempts[0].Protocol != dnsobs.ProtocolUDP || observation.Attempts[1].Protocol != dnsobs.ProtocolUDP {
				t.Fatalf("system retry transcript = %+v", observation.Attempts)
			}
		})
	}
}

func TestSystemDNSTCPFallbackRetryStaysOnTriggeringResolver(t *testing.T) {
	primary := dnsengine.Endpoint{Protocol: dnsengine.ProtocolUDP, Address: "10.0.0.53", ConnectIP: "10.0.0.53", Port: 53}
	next := dnsengine.Endpoint{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.54", ConnectIP: "127.0.0.54", Port: 53}
	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			result := setDNSResultPeer(retainedHeaderFallbackResult(endpoint, query), endpoint.ConnectIP)
			return result, context.DeadlineExceeded
		},
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return setDNSResultPeer(successfulDNSResult(endpoint, query), endpoint.ConnectIP), nil
		},
	}}
	planner := func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
		return map[int][]dnsengine.Endpoint{0: {primary, next}}, nil
	}
	batch, executeErr := executeDNSObservationRequestWithDependencies(
		context.Background(),
		testSystemDNSRequest("round-system-fallback"),
		observerSequenceFactory(observer),
		newDNSOperationGate(1),
		nil,
		func(context.Context) error { return nil },
		planner,
	)
	if executeErr != nil {
		t.Fatalf("execute system fallback: %v", executeErr)
	}
	calls := observer.observedEndpoints()
	if len(calls) != 2 || calls[0].Address != primary.Address || calls[1].Address != primary.Address || calls[0].Protocol != dnsengine.ProtocolUDP || calls[1].Protocol != dnsengine.ProtocolTCP {
		t.Fatalf("fallback endpoints = %+v", calls)
	}
	observation := batch.Observations[0]
	if !observation.UDPToTCPFallback || observation.AttemptCount != 3 || observation.ResponseAttempt != 3 || observation.PeerIP != primary.ConnectIP {
		t.Fatalf("fallback observation = %+v", observation)
	}
	wantProtocols := []dnsobs.Protocol{dnsobs.ProtocolUDP, dnsobs.ProtocolTCP, dnsobs.ProtocolTCP}
	for index, attempt := range observation.Attempts {
		if attempt.Protocol != wantProtocols[index] || attempt.PeerIP != primary.ConnectIP {
			t.Fatalf("fallback attempt %d = %+v", index, attempt)
		}
	}
}

func TestSystemDNSRetryOnNextResolverCanCompleteUDPToTCPFallback(t *testing.T) {
	primary := dnsengine.Endpoint{Protocol: dnsengine.ProtocolUDP, Address: "10.0.0.53", ConnectIP: "10.0.0.53", Port: 53}
	next := dnsengine.Endpoint{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.54", ConnectIP: "127.0.0.54", Port: 53}
	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return setDNSResultPeer(failedDNSResult(endpoint, query, context.DeadlineExceeded), endpoint.ConnectIP), context.DeadlineExceeded
		},
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return setDNSResultPeer(successfulFallbackDNSResult(endpoint, query), endpoint.ConnectIP), nil
		},
	}}
	planner := func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
		return map[int][]dnsengine.Endpoint{0: {primary, next}}, nil
	}
	batch, executeErr := executeDNSObservationRequestWithDependencies(
		context.Background(),
		testSystemDNSRequest("round-system-next-fallback"),
		observerSequenceFactory(observer),
		newDNSOperationGate(1),
		nil,
		func(context.Context) error { return nil },
		planner,
	)
	if executeErr != nil {
		t.Fatalf("execute next-resolver fallback: %v", executeErr)
	}
	calls := observer.observedEndpoints()
	if len(calls) != 2 || calls[0].Address != primary.Address || calls[1].Address != next.Address || calls[0].Protocol != dnsengine.ProtocolUDP || calls[1].Protocol != dnsengine.ProtocolUDP {
		t.Fatalf("next-resolver fallback calls = %+v", calls)
	}
	observation := batch.Observations[0]
	if !observation.UDPToTCPFallback || observation.AttemptCount != 3 || observation.ResponseAttempt != 3 || observation.PeerIP != next.ConnectIP {
		t.Fatalf("next-resolver fallback observation = %+v", observation)
	}
	wantProtocols := []dnsobs.Protocol{dnsobs.ProtocolUDP, dnsobs.ProtocolUDP, dnsobs.ProtocolTCP}
	wantPeers := []string{primary.ConnectIP, next.ConnectIP, next.ConnectIP}
	for index, attempt := range observation.Attempts {
		if attempt.Protocol != wantProtocols[index] || attempt.PeerIP != wantPeers[index] {
			t.Fatalf("next-resolver fallback attempt %d = %+v", index, attempt)
		}
	}
}

func TestSystemDNSTCPRetryUsesNextSelectedResolver(t *testing.T) {
	primary := dnsengine.Endpoint{Protocol: dnsengine.ProtocolTCP, Address: "10.0.0.53", ConnectIP: "10.0.0.53", Port: 53}
	next := dnsengine.Endpoint{Protocol: dnsengine.ProtocolTCP, Address: "127.0.0.54", ConnectIP: "127.0.0.54", Port: 53}
	observer := &scriptedDNSObserver{steps: []dnsObserverStep{
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return setDNSResultPeer(failedDNSResult(endpoint, query, context.DeadlineExceeded), endpoint.ConnectIP), context.DeadlineExceeded
		},
		func(_ context.Context, endpoint dnsengine.Endpoint, query dnsengine.Query) (*dnsengine.Result, error) {
			return setDNSResultPeer(successfulDNSResult(endpoint, query), endpoint.ConnectIP), nil
		},
	}}
	request := testSystemDNSRequest("round-system-tcp-retry")
	request.Operations[0].Endpoint.Protocol = dnsobs.ProtocolTCP
	planner := func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
		return map[int][]dnsengine.Endpoint{0: {primary, next}}, nil
	}
	batch, executeErr := executeDNSObservationRequestWithDependencies(
		context.Background(), request, observerSequenceFactory(observer), newDNSOperationGate(1), nil,
		func(context.Context) error { return nil }, planner,
	)
	if executeErr != nil {
		t.Fatalf("execute system TCP retry: %v", executeErr)
	}
	calls := observer.observedEndpoints()
	if len(calls) != 2 || calls[0].Address != primary.Address || calls[1].Address != next.Address || calls[0].Protocol != dnsengine.ProtocolTCP || calls[1].Protocol != dnsengine.ProtocolTCP {
		t.Fatalf("system TCP retry calls = %+v", calls)
	}
	observation := batch.Observations[0]
	if observation.AttemptCount != 2 || observation.ResponseAttempt != 2 || observation.PeerIP != next.ConnectIP || observation.Attempts[0].Protocol != dnsobs.ProtocolTCP || observation.Attempts[1].Protocol != dnsobs.ProtocolTCP {
		t.Fatalf("system TCP retry observation = %+v", observation)
	}
}

func TestSystemEndpointPlannerRunsOnceForMultipleOperations(t *testing.T) {
	request := testDNSRequest("round-system-plan-once", 2, 3)
	for index := range request.Operations {
		request.Operations[index].Endpoint = dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53}
	}
	plannerCalls := 0
	planner := func(_ context.Context, operations []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
		plannerCalls++
		if len(operations) != 2 {
			t.Fatalf("planner operations = %d", len(operations))
		}
		return map[int][]dnsengine.Endpoint{
			0: {{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.53", ConnectIP: "127.0.0.53", Port: 53}},
			1: {{Protocol: dnsengine.ProtocolUDP, Address: "127.0.0.54", ConnectIP: "127.0.0.54", Port: 53}},
		}, nil
	}
	batch, executeErr := executeDNSObservationRequestWithDependencies(
		context.Background(), request,
		observerSequenceFactory(delayedDNSObserver{}, delayedDNSObserver{}),
		newDNSOperationGate(2), nil,
		func(context.Context) error { return nil }, planner,
	)
	if executeErr != nil {
		t.Fatalf("execute multi-system request: %v", executeErr)
	}
	if plannerCalls != 1 || len(batch.Observations) != 2 {
		t.Fatalf("planner_calls=%d batch=%+v", plannerCalls, batch)
	}
}

func TestSystemDNSDiscoveryFixturesCannotEnterTrustedPlanner(t *testing.T) {
	resolv, err := systemdns.ParseResolvConf([]byte("nameserver 127.0.0.53\n"))
	if err != nil {
		t.Fatal(err)
	}
	scutil, err := systemdns.ParseSCUtilDNS([]byte("resolver #1\n  nameserver[0] : 10.0.0.53\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		result systemdns.DiscoveryResult
	}{
		{name: "resolv.conf parser", result: resolv},
		{name: "scutil parser", result: scutil},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoints, planErr := planDNSSystemEndpointsFromDiscovery(
				context.Background(),
				testSystemDNSRequest("round-untrusted-system").Operations,
				func(context.Context) (systemdns.DiscoveryResult, error) { return test.result, nil },
			)
			var taskErr *dnsTaskError
			if endpoints != nil || !errors.As(planErr, &taskErr) || taskErr.Code != "SYSTEM_DNS_UNAVAILABLE" {
				t.Fatalf("untrusted plan endpoints=%+v error=%#v", endpoints, planErr)
			}
		})
	}
}

func TestDNSAgentEnvelopeSizeErrorsAreExplicit(t *testing.T) {
	value := struct {
		Data string `json:"data"`
	}{Data: strings.Repeat("x", 128)}
	err := ensureAgentJSONEnvelopeSize("test envelope", value, 32)
	var tooLarge *agentPayloadTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Size <= tooLarge.Limit {
		t.Fatalf("size error = %#v", err)
	}

	largeBatch := &dnsobs.BatchResult{Schema: dnsobs.SchemaV1, RoundID: "round-large", Observations: make([]dnsobs.Observation, dnsobs.MaxOperations)}
	for i := range largeBatch.Observations {
		largeBatch.Observations[i].Sections.Answer = []dnsobs.ResourceRecord{{DisplayRData: strings.Repeat("x", dnsobs.MaxRDataBytes), CanonicalRData: strings.Repeat("x", dnsobs.MaxRDataBytes), RRSetRecordCount: 1}}
	}
	bounded := boundDNSAgentResult(taskResult{TaskID: "task-large", Status: "completed", Success: true, DNSResult: largeBatch, FinishedAt: time.Now().UTC()})
	if bounded.ErrorCode != "PAYLOAD_TOO_LARGE" || bounded.DNSResult != nil || bounded.Success {
		t.Fatalf("bounded task result = %+v", bounded)
	}
}

func TestDNSBatchAndFinalEnvelopeFitEveryOperationWithAtomicRRsets(t *testing.T) {
	request := testDNSRequest("round-batch-fit", dnsobs.MaxOperations, 3)
	observations := make([]dnsobs.Observation, len(request.Operations))
	for index, operation := range request.Operations {
		records := make([]dnsobs.ResourceRecord, 0, 8)
		for rrset := 0; rrset < 4; rrset++ {
			owner := fmt.Sprintf("set-%d.example.com.", rrset)
			for member := 0; member < 2; member++ {
				value := strings.Repeat(string(rune('a'+rrset)), 2047) + strconv.Itoa(member)
				display, canonical := txtRecordDataAgentTest(t, value)
				records = append(records, dnsobs.ResourceRecord{
					Owner: owner, Type: dnsobs.RRTypeTXT, Class: dnsobs.DNSClassIN, TTL: 60,
					DisplayRData: display, CanonicalRData: canonical, RRSetRecordCount: 2,
				})
			}
		}
		finishedAt := time.Now().UTC()
		observation, err := dnsobs.NormalizeObservation(dnsobs.Observation{
			Schema: dnsobs.SchemaV1, RoundID: request.RoundID, OperationID: operation.OperationID,
			Question: operation.Question, Endpoint: operation.Endpoint,
			TransportStatus: dnsobs.TransportSuccess, AttemptCount: 1, PeerIP: operation.Endpoint.ConnectIP,
			Attempts: []dnsobs.WireAttempt{{
				Protocol: operation.Endpoint.Protocol, TransportStatus: dnsobs.TransportSuccess,
				StartedAt: finishedAt.Add(-time.Millisecond), FinishedAt: finishedAt, DurationMS: 1,
				PeerIP: operation.Endpoint.ConnectIP, ResponseSizeBytes: 96,
			}},
			ResponseAttempt: 1,
			Protocol:        operation.Endpoint.Protocol, StartedAt: finishedAt.Add(-time.Millisecond), ObservedAt: finishedAt, FinishedAt: finishedAt, DurationMS: 1,
			RCode: bytePointerAgent(0), Flags: dnsobs.DNSFlags{Response: true}, Outcome: dnsobs.DNSOutcomeAnswer,
			Comparison: dnsobs.ComparisonUnknown, DNSSEC: dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
			Sections:          dnsobs.Sections{Additional: records},
			ResponseSizeBytes: 96,
		})
		if err != nil {
			t.Fatalf("normalize large observation %d: %v", index, err)
		}
		observations[index] = observation
	}

	batch, err := composeBoundedDNSBatch(request, observations)
	if err != nil {
		t.Fatalf("compose bounded batch: %v", err)
	}
	batchRaw, err := json.Marshal(batch)
	if err != nil || len(batchRaw) > dnsobs.MaxTaskResultBytes || len(batch.Observations) != dnsobs.MaxOperations {
		t.Fatalf("bounded batch bytes=%d observations=%d err=%v", len(batchRaw), len(batch.Observations), err)
	}
	for _, observation := range batch.Observations {
		if !observation.ResultTruncated || observation.ResponseTruncated || observation.Comparison != dnsobs.ComparisonUnknown || observation.DNSSEC.Status != dnsobs.DNSSECIndeterminate {
			t.Fatalf("cropped observation markers = %+v", observation)
		}
		members := make(map[string]int)
		for _, record := range observation.Sections.Additional {
			members[record.Owner]++
		}
		for owner, count := range members {
			if count != 2 {
				t.Fatalf("RRset %s retained %d members, want 2", owner, count)
			}
		}
	}

	result := boundDNSAgentResult(taskResult{TaskID: "task-batch-fit", Status: "completed", Success: true, DNSResult: &batch, FinishedAt: time.Now().UTC()})
	resultRaw, err := json.Marshal(result)
	if err != nil || len(resultRaw) > dnsobs.MaxTaskResultBytes || result.DNSResult == nil || len(result.DNSResult.Observations) != dnsobs.MaxOperations || !result.Success {
		t.Fatalf("bounded Agent result bytes=%d result=%+v err=%v", len(resultRaw), result, err)
	}
}

func txtRecordDataAgentTest(t testing.TB, value string) (string, string) {
	t.Helper()
	chunks := make([]string, 0, len(value)/255+1)
	for len(value) > 255 {
		chunks = append(chunks, value[:255])
		value = value[255:]
	}
	chunks = append(chunks, value)
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: chunks,
	}
	display, canonical, comparable, err := dnsobs.CanonicalRecordDataForRR(record)
	if err != nil || !comparable {
		t.Fatalf("canonicalize TXT Agent fixture: comparable=%t err=%v", comparable, err)
	}
	return display, canonical
}

func TestDNSObservationEventUsesTypedPayload(t *testing.T) {
	request := testDNSRequest("round-event", 1, 3)
	batch, err := executeDNSObservationRequest(context.Background(), request, observerSequenceFactory(delayedDNSObserver{}), newDNSOperationGate(1), nil)
	if err != nil {
		t.Fatalf("execute observation: %v", err)
	}
	event := taskEvent{
		TaskID:         "task-event",
		Status:         "running",
		EventKind:      dnsobs.EventKindDNSObservation,
		DNSObservation: &batch.Observations[0],
		CreatedAt:      time.Now().UTC(),
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"event_kind":"dns_observation"`) || !strings.Contains(text, `"dns_observation":{`) || strings.Contains(text, `"extra":`) {
		t.Fatalf("typed DNS event JSON = %s", text)
	}
	if len(raw) > dnsobs.MaxEventBytes {
		t.Fatalf("typed event is %d bytes", len(raw))
	}
}

func TestCanRetryDNSExchangeReservesMandatoryTCPFallback(t *testing.T) {
	if canRetryDNSExchange(dnsobs.ProtocolUDP, 1, 2) {
		t.Fatal("UDP retry must not consume the only slot reserved for mandatory TCP fallback")
	}
	if !canRetryDNSExchange(dnsobs.ProtocolUDP, 1, 3) {
		t.Fatal("UDP retry should run when both retry and fallback slots remain")
	}
	if !canRetryDNSExchange(dnsobs.ProtocolTCP, 1, 2) {
		t.Fatal("direct TCP transient failure should retry when one slot remains")
	}
}

func TestComposeDNSOperationTimelineCoversCoarseWallClockBoundary(t *testing.T) {
	started := time.Date(2026, time.July, 19, 10, 32, 9, 127595000, time.UTC)
	finished := started.Add(time.Microsecond)

	normalizedStart, duration := composeDNSOperationTimeline(started, finished, 958*time.Nanosecond)
	if !normalizedStart.Equal(started) || duration != time.Microsecond {
		t.Fatalf("operation timeline = %s + %s, want %s + %s", normalizedStart, duration, started, time.Microsecond)
	}
	if finished.After(normalizedStart.Add(duration)) {
		t.Fatal("operation timeline does not contain its wall-clock finish")
	}
}

func TestUDPRequestRejectsAttemptLimitWithoutFallbackSlot(t *testing.T) {
	request := testDNSRequest("round-one-attempt", 1, 1)
	_, err := executeDNSObservationRequest(context.Background(), request, observerSequenceFactory(delayedDNSObserver{}), newDNSOperationGate(1), nil)
	var validationErr *dnsobs.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "UDP_FALLBACK_ATTEMPT_REQUIRED" {
		t.Fatalf("one-attempt UDP error = %#v", err)
	}
}

func executeSingleDNSOperation(t *testing.T, observer dnsWireObserver) dnsobs.Observation {
	t.Helper()
	request := testDNSRequest("round-retry", 1, 3)
	batch, err := executeDNSObservationRequestWithRetryWait(context.Background(), request, observerSequenceFactory(observer), newDNSOperationGate(1), nil, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("execute operation: %v", err)
	}
	return batch.Observations[0]
}

func observerSequenceFactory(observers ...dnsWireObserver) dnsWireEngineFactory {
	var mu sync.Mutex
	index := 0
	return func(time.Duration, uint16) (dnsWireObserver, error) {
		mu.Lock()
		defer mu.Unlock()
		if index >= len(observers) {
			return nil, errors.New("unexpected DNS engine initialization")
		}
		observer := observers[index]
		index++
		return observer, nil
	}
}

func testDNSRequest(roundID string, operationCount int, maxAttempts int) dnsobs.Request {
	operations := make([]dnsobs.Operation, operationCount)
	for i := range operations {
		operations[i] = dnsobs.Operation{
			OperationID: "op-" + strconv.Itoa(i+1),
			Mode:        dnsobs.ModeRecursive,
			Question:    dnsobs.Question{Name: "example.com.", Type: dnsobs.RRTypeA, Class: dnsobs.DNSClassIN},
			Endpoint: dnsobs.Endpoint{
				Kind: dnsobs.EndpointCatalog, Protocol: dnsobs.ProtocolUDP,
				ConnectIP: "8.8.8.8", Port: 53,
			},
			Flags: dnsobs.QueryFlags{RecursionDesired: true, DNSSECOK: true, EDNSUDPSize: dnsobs.DefaultEDNSUDPSize},
		}
	}
	return dnsobs.Request{
		Schema: dnsobs.SchemaV1, RoundID: roundID, Operations: operations,
		Limits: dnsobs.Limits{Parallel: min(operationCount, dnsobs.MaxParallel), AttemptTimeoutMS: 500, MaxAttempts: maxAttempts},
	}
}

func testSystemDNSRequest(roundID string) dnsobs.Request {
	request := testDNSRequest(roundID, 1, 3)
	request.Operations[0].Endpoint = dnsobs.Endpoint{Kind: dnsobs.EndpointSystem, Protocol: dnsobs.ProtocolUDP, Port: 53}
	return request
}

func setDNSResultPeer(result *dnsengine.Result, peer string) *dnsengine.Result {
	if result == nil {
		return nil
	}
	result.PeerIP = peer
	for index := range result.Attempts {
		result.Attempts[index].PeerIP = peer
	}
	return result
}

func bytePointerAgent(value uint8) *uint8 {
	return &value
}

func successfulDNSResult(endpoint dnsengine.Endpoint, query dnsengine.Query) *dnsengine.Result {
	now := time.Now().UTC()
	return &dnsengine.Result{
		Question:       dns.Question{Name: query.Name, Qtype: query.Type, Qclass: query.Class},
		Protocol:       endpoint.Protocol,
		PeerIP:         "8.8.8.8",
		StartedAt:      now,
		Duration:       0,
		Attempts:       []dnsengine.Attempt{{Protocol: endpoint.Protocol, StartedAt: now, PeerIP: "8.8.8.8", ResponseSize: 32}},
		RCode:          0,
		Flags:          dnsengine.Flags{Response: true, RecursionDesired: query.RecursionDesired},
		Outcome:        dnsengine.OutcomeAnswer,
		ResponseSize:   32,
		ResponseParsed: true,
	}
}

func successfulFallbackDNSResult(endpoint dnsengine.Endpoint, query dnsengine.Query) *dnsengine.Result {
	result := successfulDNSResult(endpoint, query)
	result.Attempts = []dnsengine.Attempt{
		{Protocol: dnsengine.ProtocolUDP, StartedAt: result.StartedAt, PeerIP: "8.8.8.8", ResponseSize: 12, Truncated: true},
		{Protocol: dnsengine.ProtocolTCP, StartedAt: result.StartedAt, PeerIP: "8.8.8.8", ResponseSize: 32},
	}
	result.UDPToTCPFallback = true
	return result
}

func retainedHeaderFallbackResult(endpoint dnsengine.Endpoint, query dnsengine.Query) *dnsengine.Result {
	now := time.Now().UTC()
	return &dnsengine.Result{
		Question:                dns.Question{Name: query.Name, Qtype: query.Type, Qclass: query.Class},
		Protocol:                endpoint.Protocol,
		PeerIP:                  "8.8.8.8",
		StartedAt:               now,
		Duration:                2 * time.Millisecond,
		Attempts:                []dnsengine.Attempt{{Protocol: dnsengine.ProtocolUDP, StartedAt: now, PeerIP: "8.8.8.8", ResponseSize: 12, Truncated: true}, {Protocol: dnsengine.ProtocolTCP, StartedAt: now, PeerIP: "8.8.8.8", Error: context.DeadlineExceeded.Error()}},
		UDPToTCPFallback:        true,
		RCode:                   0,
		Flags:                   dnsengine.Flags{Response: true, Truncated: true},
		Outcome:                 dnsengine.OutcomeTruncatedResponse,
		ResponseSize:            12,
		ResponseHeaderValidated: true,
		ResponseTruncated:       true,
	}
}

func failedDNSResult(endpoint dnsengine.Endpoint, query dnsengine.Query, exchangeErr error) *dnsengine.Result {
	now := time.Now().UTC()
	if exchangeErr == nil {
		exchangeErr = errors.New("exchange failed")
	}
	return &dnsengine.Result{
		Question:          dns.Question{Name: query.Name, Qtype: query.Type, Qclass: query.Class},
		Protocol:          endpoint.Protocol,
		PeerIP:            "8.8.8.8",
		StartedAt:         now,
		Duration:          0,
		Attempts:          []dnsengine.Attempt{{Protocol: endpoint.Protocol, StartedAt: now, PeerIP: "8.8.8.8", Error: exchangeErr.Error()}},
		Outcome:           "",
		ResponseTruncated: false,
	}
}

func malformedDNSResult(endpoint dnsengine.Endpoint, query dnsengine.Query) *dnsengine.Result {
	result := failedDNSResult(endpoint, query, errors.New("exchange failed"))
	result.Outcome = dnsengine.OutcomeMalformed
	result.ResponseSize = 8
	result.Attempts[0].ResponseSize = 8
	result.Attempts[0].Error = ""
	return result
}

func malformedTCPHeaderResult(endpoint dnsengine.Endpoint, query dnsengine.Query) *dnsengine.Result {
	result := malformedDNSResult(endpoint, query)
	result.RCode = dns.RcodeRefused
	result.Flags = dnsengine.Flags{Response: true, Truncated: true, Authoritative: true}
	result.Outcome = dnsengine.OutcomeTruncatedResponse
	result.ResponseSize = 24
	result.ResponseHeaderValidated = true
	result.ResponseTruncated = true
	result.Attempts[0].ResponseSize = 24
	result.Attempts[0].Truncated = true
	return result
}

func startThirdTCPMalformedResolver(t *testing.T) (dnsengine.Endpoint, <-chan int, <-chan error) {
	t.Helper()
	udpConn, tcpListener, port := listenAgentUDPAndTCP(t)
	t.Cleanup(func() {
		_ = udpConn.Close()
		_ = tcpListener.Close()
	})
	responseSize := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		_ = udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, peer, err := udpConn.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		udpQuery := new(dns.Msg)
		if err := udpQuery.Unpack(buffer[:n]); err != nil {
			done <- err
			return
		}
		udpResponse := new(dns.Msg)
		udpResponse.SetReply(udpQuery)
		udpResponse.Rcode = dns.RcodeNameError
		udpResponse.Truncated = true
		udpResponse.RecursionAvailable = true
		wire, err := udpResponse.Pack()
		if err == nil {
			_, err = udpConn.WriteTo(wire, peer)
		}
		if err != nil {
			done <- err
			return
		}

		first, err := tcpListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer first.Close()
		_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := readAgentDNSFrame(first); err != nil {
			done <- err
			return
		}

		second, err := tcpListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer second.Close()
		_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
		queryWire, err := readAgentDNSFrame(second)
		if err != nil {
			done <- err
			return
		}
		tcpQuery := new(dns.Msg)
		if err := tcpQuery.Unpack(queryWire); err != nil {
			done <- err
			return
		}
		tcpResponse := new(dns.Msg)
		tcpResponse.SetReply(tcpQuery)
		tcpResponse.Rcode = dns.RcodeRefused
		tcpResponse.Authoritative = true
		tcpResponse.Truncated = true
		tcpResponse.CheckingDisabled = true
		wire, err = tcpResponse.Pack()
		if err == nil {
			wire = append(wire, 0xa5)
			responseSize <- len(wire)
			err = writeAgentDNSFrame(second, wire)
		}
		done <- err
	}()
	return dnsengine.Endpoint{Protocol: dnsengine.ProtocolUDP, Address: "resolver.test", ConnectIP: "127.0.0.1", Port: uint16(port)}, responseSize, done
}

func listenAgentUDPAndTCP(t *testing.T) (net.PacketConn, net.Listener, int) {
	t.Helper()
	var lastErr error
	for range 32 {
		udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen UDP fixture: %v", err)
		}
		port := udpConn.LocalAddr().(*net.UDPAddr).Port
		tcpListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return udpConn, tcpListener, port
		}
		lastErr = err
		_ = udpConn.Close()
	}
	t.Fatalf("bind UDP and TCP fixtures to one port: %v", lastErr)
	return nil, nil, 0
}

func readAgentDNSFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(header[:])))
	_, err := io.ReadFull(reader, wire)
	return wire, err
}

func writeAgentDNSFrame(writer io.Writer, wire []byte) error {
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	for len(frame) != 0 {
		written, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}
