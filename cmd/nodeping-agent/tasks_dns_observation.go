package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"nodeping/internal/dnsengine"
	"nodeping/internal/dnsobs"
	"nodeping/internal/systemdns"

	"github.com/miekg/dns"
)

const (
	dnsPropagationTaskType = "dns_propagation"
	dnsObserveCapability   = "dns_observe_v1"
	minDNSRetryJitter      = 25 * time.Millisecond
	maxDNSRetryJitter      = 100 * time.Millisecond
)

type dnsWireObserver interface {
	Observe(context.Context, dnsengine.Endpoint, dnsengine.Query) (*dnsengine.Result, error)
}

type dnsWireEngineFactory func(time.Duration, uint16) (dnsWireObserver, error)

type dnsRetryWaiter func(context.Context) error

type dnsSystemEndpointPlanner func(context.Context, []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error)

type dnsSystemDiscoverer func(context.Context) (systemdns.DiscoveryResult, error)

type dnsOperationGate struct {
	tokens chan struct{}
}

var processDNSOperationGate = newDNSOperationGate(dnsobs.MaxParallel)

var dnsSystemRotation atomic.Uint64

type dnsTaskError struct {
	Code    string
	Message string
}

func (e *dnsTaskError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type agentPayloadTooLargeError struct {
	Kind  string
	Size  int
	Limit int
}

func (e *agentPayloadTooLargeError) Error() string {
	return fmt.Sprintf("%s JSON envelope is %d bytes; limit is %d bytes", e.Kind, e.Size, e.Limit)
}

type preparedDNSOperation struct {
	index         int
	operation     dnsobs.Operation
	endpoint      dnsengine.Endpoint
	retryEndpoint dnsengine.Endpoint
	query         dnsengine.Query
	observer      dnsWireObserver
}

type completedDNSOperation struct {
	index       int
	observation dnsobs.Observation
	err         error
}

func newDNSOperationGate(limit int) *dnsOperationGate {
	if limit < 1 {
		limit = 1
	}
	return &dnsOperationGate{tokens: make(chan struct{}, limit)}
}

func (g *dnsOperationGate) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if g == nil {
		return true
	}
	select {
	case g.tokens <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (g *dnsOperationGate) release() {
	if g != nil {
		<-g.tokens
	}
}

func decodeDNSObservationRequest(raw json.RawMessage) (dnsobs.Request, error) {
	if len(raw) > dnsobs.MaxEventBytes {
		return dnsobs.Request{}, &agentPayloadTooLargeError{Kind: "DNS task payload", Size: len(raw), Limit: dnsobs.MaxEventBytes}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request dnsobs.Request
	if err := decoder.Decode(&request); err != nil {
		return dnsobs.Request{}, &dnsTaskError{Code: "INVALID_PAYLOAD", Message: "decode DNS task payload: " + err.Error()}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		return dnsobs.Request{}, &dnsTaskError{Code: "INVALID_PAYLOAD", Message: "decode DNS task payload: " + err.Error()}
	}
	normalized, err := dnsobs.NormalizeRequest(request)
	if err != nil {
		code := "INVALID_PAYLOAD"
		var validationErr *dnsobs.ValidationError
		if errors.As(err, &validationErr) && validationErr.Code != "" {
			code = validationErr.Code
		}
		return dnsobs.Request{}, &dnsTaskError{Code: code, Message: err.Error()}
	}
	return normalized, nil
}

func executeDNSPropagationTask(ctx context.Context, cfg config, task taskRequest, started time.Time) taskResult {
	request, err := decodeDNSObservationRequest(task.Payload)
	if err != nil {
		return dnsTaskFailure(task.ID, started, nil, err)
	}
	emit := func(observation dnsobs.Observation, completed int, total int) error {
		event := taskEvent{
			TaskID:         task.ID,
			Status:         "running",
			Progress:       completed * 100 / total,
			EventKind:      dnsobs.EventKindDNSObservation,
			DNSObservation: &observation,
			CreatedAt:      observation.FinishedAt,
		}
		if err := ensureAgentJSONEnvelopeSize("DNS observation event", event, dnsobs.MaxEventBytes); err != nil {
			return err
		}
		if err := postAgentJSON(ctx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/events", event, nil); err != nil && ctx.Err() == nil {
			log.Printf("report DNS observation failed task_id=%s operation_id=%s: %v", task.ID, observation.OperationID, err)
		}
		return nil
	}
	batch, err := executeDNSObservationRequest(ctx, request, defaultDNSWireEngineFactory, processDNSOperationGate, emit)
	if err != nil {
		if completeDNSBatch(batch, len(request.Operations)) {
			return dnsTaskFailure(task.ID, started, &batch, err)
		}
		return dnsTaskFailure(task.ID, started, nil, err)
	}

	result := taskResult{
		TaskID:     task.ID,
		Status:     "completed",
		Success:    true,
		LatencyMS:  elapsedMS(started),
		DNSResult:  &batch,
		Extra:      taskResultExtra(task, request.Operations[0].Question.Name),
		FinishedAt: time.Now().UTC(),
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		result.Status = "cancelled"
		result.Success = false
		result.ErrorCode = "TASK_CANCELLED"
		result.ErrorMessage = "task cancelled"
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status = "timeout"
		result.Success = false
		result.ErrorCode = "TASK_TIMEOUT"
		result.ErrorMessage = "task timed out"
	}
	return boundDNSAgentResult(result)
}

func completeDNSBatch(batch dnsobs.BatchResult, expected int) bool {
	if len(batch.Observations) != expected {
		return false
	}
	for i := range batch.Observations {
		if batch.Observations[i].Schema == "" {
			return false
		}
	}
	return true
}

func dnsTaskFailure(taskID string, started time.Time, batch *dnsobs.BatchResult, err error) taskResult {
	code := "DNS_EXECUTION_FAILED"
	var taskErr *dnsTaskError
	var tooLarge *agentPayloadTooLargeError
	var validationErr *dnsobs.ValidationError
	switch {
	case errors.As(err, &tooLarge):
		code = "PAYLOAD_TOO_LARGE"
	case errors.As(err, &validationErr) && (validationErr.Code == "TASK_RESULT_TOO_LARGE" || validationErr.Code == "OBSERVATION_TOO_LARGE"):
		code = "PAYLOAD_TOO_LARGE"
	case errors.As(err, &taskErr) && taskErr.Code != "":
		code = taskErr.Code
	}
	result := taskResult{
		TaskID:       taskID,
		Status:       "failed",
		Success:      false,
		LatencyMS:    elapsedMS(started),
		DNSResult:    batch,
		ErrorCode:    code,
		ErrorMessage: err.Error(),
		FinishedAt:   time.Now().UTC(),
	}
	return boundDNSAgentResult(result)
}

func boundDNSAgentResult(result taskResult) taskResult {
	if result.DNSResult == nil {
		return result
	}
	if err := ensureAgentJSONEnvelopeSize("DNS task result", result, dnsobs.MaxTaskResultBytes); err == nil {
		return result
	} else {
		if fitted, fitErr := fitDNSAgentResultEnvelope(result); fitErr == nil {
			return fitted
		}
		return taskResult{
			TaskID:       result.TaskID,
			Status:       "failed",
			Success:      false,
			LatencyMS:    result.LatencyMS,
			ErrorCode:    "PAYLOAD_TOO_LARGE",
			ErrorMessage: err.Error(),
			FinishedAt:   time.Now().UTC(),
		}
	}
}

func fitDNSAgentResultEnvelope(result taskResult) (taskResult, error) {
	if result.DNSResult == nil || len(result.DNSResult.Observations) == 0 {
		return taskResult{}, errors.New("DNS task result has no observations to fit")
	}
	emptyResult := result
	emptyBatch := *result.DNSResult
	emptyBatch.Observations = make([]dnsobs.Observation, 0)
	emptyResult.DNSResult = &emptyBatch
	emptyRaw, err := json.Marshal(emptyResult)
	if err != nil {
		return taskResult{}, fmt.Errorf("encode empty DNS task result: %w", err)
	}
	perObservation, err := perItemJSONLimit(dnsobs.MaxTaskResultBytes, len(emptyRaw), len(result.DNSResult.Observations))
	if err != nil {
		return taskResult{}, err
	}
	fittedBatch := *result.DNSResult
	fittedBatch.Observations = make([]dnsobs.Observation, len(result.DNSResult.Observations))
	for index := range result.DNSResult.Observations {
		fittedBatch.Observations[index], _, err = dnsengine.FitObservationToBytes(result.DNSResult.Observations[index], min(perObservation, dnsobs.MaxObservationBytes))
		if err != nil {
			return taskResult{}, fmt.Errorf("fit DNS observation %q into Agent result: %w", result.DNSResult.Observations[index].OperationID, err)
		}
	}
	result.DNSResult = &fittedBatch
	if err := ensureAgentJSONEnvelopeSize("DNS task result", result, dnsobs.MaxTaskResultBytes); err != nil {
		return taskResult{}, err
	}
	return result, nil
}

func ensureAgentJSONEnvelopeSize(kind string, value any, limit int) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", kind, err)
	}
	if len(raw) > limit {
		return &agentPayloadTooLargeError{Kind: kind, Size: len(raw), Limit: limit}
	}
	return nil
}

func defaultDNSWireEngineFactory(timeout time.Duration, udpSize uint16) (dnsWireObserver, error) {
	return dnsengine.New(dnsengine.Config{
		Timeout:              timeout,
		UDPSize:              udpSize,
		MaxResponseBytes:     dnsengine.DefaultMaxResponseBytes,
		MaxRecordsPerSection: dnsobs.DefaultSectionRecordLimit,
	})
}

func executeDNSObservationRequest(
	ctx context.Context,
	request dnsobs.Request,
	factory dnsWireEngineFactory,
	gate *dnsOperationGate,
	emit func(dnsobs.Observation, int, int) error,
) (dnsobs.BatchResult, error) {
	return executeDNSObservationRequestWithRetryWait(ctx, request, factory, gate, emit, waitDNSRetryJitter)
}

func executeDNSObservationRequestWithRetryWait(
	ctx context.Context,
	request dnsobs.Request,
	factory dnsWireEngineFactory,
	gate *dnsOperationGate,
	emit func(dnsobs.Observation, int, int) error,
	retryWait dnsRetryWaiter,
) (dnsobs.BatchResult, error) {
	return executeDNSObservationRequestWithDependencies(ctx, request, factory, gate, emit, retryWait, defaultDNSSystemEndpointPlanner)
}

func executeDNSObservationRequestWithDependencies(
	ctx context.Context,
	request dnsobs.Request,
	factory dnsWireEngineFactory,
	gate *dnsOperationGate,
	emit func(dnsobs.Observation, int, int) error,
	retryWait dnsRetryWaiter,
	systemPlanner dnsSystemEndpointPlanner,
) (dnsobs.BatchResult, error) {
	request, err := dnsobs.NormalizeRequest(request)
	if err != nil {
		return dnsobs.BatchResult{}, err
	}
	prepared, err := prepareDNSOperations(ctx, request, factory, systemPlanner)
	if err != nil {
		return dnsobs.BatchResult{}, err
	}

	jobs := make(chan preparedDNSOperation, len(prepared))
	completed := make(chan completedDNSOperation, len(prepared))
	for _, operation := range prepared {
		jobs <- operation
	}
	close(jobs)

	parallel := min(request.Limits.Parallel, len(prepared))
	for range parallel {
		go func() {
			for operation := range jobs {
				if !gate.acquire(ctx) {
					observation, cancelErr := cancelledDNSObservation(request.RoundID, operation.operation)
					completed <- completedDNSOperation{index: operation.index, observation: observation, err: cancelErr}
					continue
				}
				observation, executeErr := executePreparedDNSOperation(ctx, request.RoundID, request.Limits, operation, retryWait)
				gate.release()
				completed <- completedDNSOperation{index: operation.index, observation: observation, err: executeErr}
			}
		}()
	}

	observations := make([]dnsobs.Observation, len(prepared))
	var firstErr error
	for completedCount := 1; completedCount <= len(prepared); completedCount++ {
		result := <-completed
		if result.observation.Schema == "" {
			cause := result.err
			if cause == nil {
				cause = errors.New("DNS operation completed without an observation")
			}
			result.observation, result.err = composeDNSExecutionFailure(
				request.RoundID,
				prepared[result.index].operation,
				time.Now(),
				nil,
				1,
				cause,
			)
		}
		if result.observation.Schema != "" {
			observations[result.index] = result.observation
			if emit != nil {
				if err := emit(result.observation, completedCount, len(prepared)); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
		}
	}
	batch, normalizeErr := composeBoundedDNSBatch(request, observations)
	if normalizeErr != nil {
		if firstErr != nil {
			return dnsobs.BatchResult{}, errors.Join(firstErr, normalizeErr)
		}
		return dnsobs.BatchResult{}, normalizeErr
	}
	return batch, firstErr
}

func composeBoundedDNSBatch(request dnsobs.Request, observations []dnsobs.Observation) (dnsobs.BatchResult, error) {
	batch := dnsobs.BatchResult{Schema: dnsobs.SchemaV1, RoundID: request.RoundID, Observations: observations}
	normalized, err := dnsobs.NormalizeBatchResultForRequest(request, batch)
	if err == nil {
		return normalized, nil
	}
	var validationErr *dnsobs.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Code != "TASK_RESULT_TOO_LARGE" {
		return dnsobs.BatchResult{}, err
	}
	empty := dnsobs.BatchResult{Schema: dnsobs.SchemaV1, RoundID: request.RoundID, Observations: make([]dnsobs.Observation, 0)}
	emptyRaw, marshalErr := json.Marshal(empty)
	if marshalErr != nil {
		return dnsobs.BatchResult{}, fmt.Errorf("encode empty DNS batch: %w", marshalErr)
	}
	perObservation, limitErr := perItemJSONLimit(dnsobs.MaxTaskResultBytes, len(emptyRaw), len(observations))
	if limitErr != nil {
		return dnsobs.BatchResult{}, limitErr
	}
	fitted := make([]dnsobs.Observation, len(observations))
	for index := range observations {
		fitted[index], _, err = dnsengine.FitObservationToBytes(observations[index], min(perObservation, dnsobs.MaxObservationBytes))
		if err != nil {
			return dnsobs.BatchResult{}, fmt.Errorf("fit DNS observation %q into final batch: %w", request.Operations[index].OperationID, err)
		}
	}
	return dnsobs.NormalizeBatchResultForRequest(request, dnsobs.BatchResult{
		Schema:       dnsobs.SchemaV1,
		RoundID:      request.RoundID,
		Observations: fitted,
	})
}

func perItemJSONLimit(maxBytes int, emptyEnvelopeBytes int, count int) (int, error) {
	if count < 1 {
		return 0, errors.New("JSON envelope requires at least one item")
	}
	// Replace the empty [] with count item objects and their separating commas.
	overhead := emptyEnvelopeBytes - 2 + count - 1
	available := maxBytes - overhead
	if available < count {
		return 0, errors.New("JSON envelope metadata leaves no bounded item budget")
	}
	return available / count, nil
}

func prepareDNSOperations(ctx context.Context, request dnsobs.Request, factory dnsWireEngineFactory, systemPlanner dnsSystemEndpointPlanner) ([]preparedDNSOperation, error) {
	if factory == nil {
		return nil, &dnsTaskError{Code: "DNS_ENGINE_UNAVAILABLE", Message: "DNS wire engine is unavailable"}
	}
	for _, operation := range request.Operations {
		if operation.Mode == dnsobs.ModeIterative {
			return nil, &dnsTaskError{Code: "CAPABILITY_UNAVAILABLE", Message: "iterative DNS observation is unavailable until the isolated validating worker is ready"}
		}
	}
	systemEndpoints, err := planDNSSystemEndpoints(ctx, request.Operations, systemPlanner)
	if err != nil {
		return nil, err
	}
	prepared := make([]preparedDNSOperation, len(request.Operations))
	for index, operation := range request.Operations {
		if operation.Endpoint.Protocol == dnsobs.ProtocolUDP && request.Limits.MaxAttempts < 2 {
			return nil, &dnsTaskError{Code: "INVALID_ATTEMPT_LIMIT", Message: fmt.Sprintf("operation %q requires at least two attempts so every UDP TC response can fall back to TCP", operation.OperationID)}
		}
		resolverEndpoints := systemEndpoints[index]
		var endpoint dnsengine.Endpoint
		if operation.Endpoint.Kind == dnsobs.EndpointSystem {
			if len(resolverEndpoints) == 0 {
				return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: fmt.Sprintf("operation %q has no trusted system resolver endpoint", operation.OperationID)}
			}
			endpoint = resolverEndpoints[0]
		} else {
			endpoint, err = dnsEngineEndpoint(operation.Endpoint)
			if err != nil {
				return nil, &dnsTaskError{Code: "INVALID_PAYLOAD", Message: fmt.Sprintf("operation %q: %v", operation.OperationID, err)}
			}
			resolverEndpoints = []dnsengine.Endpoint{endpoint}
		}
		retryEndpoint := endpoint
		if len(resolverEndpoints) > 1 {
			retryEndpoint = resolverEndpoints[1]
		}
		queryType, ok := dns.StringToType[string(operation.Question.Type)]
		if !ok {
			return nil, &dnsTaskError{Code: "UNSUPPORTED_RR_TYPE", Message: fmt.Sprintf("operation %q has unsupported DNS type %q", operation.OperationID, operation.Question.Type)}
		}
		observer, err := factory(time.Duration(request.Limits.AttemptTimeoutMS)*time.Millisecond, uint16(operation.Flags.EDNSUDPSize))
		if err != nil {
			return nil, &dnsTaskError{Code: "DNS_ENGINE_UNAVAILABLE", Message: fmt.Sprintf("operation %q: initialize DNS engine: %v", operation.OperationID, err)}
		}
		prepared[index] = preparedDNSOperation{
			index:         index,
			operation:     operation,
			endpoint:      endpoint,
			retryEndpoint: retryEndpoint,
			query: dnsengine.Query{
				Name:             operation.Question.Name,
				Type:             queryType,
				Class:            dns.ClassINET,
				Mode:             dnsengine.QueryMode(operation.Mode),
				RecursionDesired: operation.Flags.RecursionDesired,
				CheckingDisabled: operation.Flags.CheckingDisabled,
				DNSSECOK:         operation.Flags.DNSSECOK,
			},
			observer: observer,
		}
	}
	return prepared, nil
}

func planDNSSystemEndpoints(ctx context.Context, operations []dnsobs.Operation, planner dnsSystemEndpointPlanner) (map[int][]dnsengine.Endpoint, error) {
	hasSystem := false
	for _, operation := range operations {
		if operation.Endpoint.Kind == dnsobs.EndpointSystem {
			hasSystem = true
			break
		}
	}
	if !hasSystem {
		return nil, nil
	}
	if planner == nil {
		return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: "trusted system DNS endpoint planning is unavailable"}
	}
	endpoints, err := planner(ctx, operations)
	if err != nil {
		var taskErr *dnsTaskError
		if errors.As(err, &taskErr) {
			return nil, err
		}
		return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: "prepare trusted system DNS endpoints: " + err.Error()}
	}
	return endpoints, nil
}

func defaultDNSSystemEndpointPlanner(ctx context.Context, operations []dnsobs.Operation) (map[int][]dnsengine.Endpoint, error) {
	return planDNSSystemEndpointsFromDiscovery(ctx, operations, systemdns.Discover)
}

func planDNSSystemEndpointsFromDiscovery(ctx context.Context, operations []dnsobs.Operation, discover dnsSystemDiscoverer) (map[int][]dnsengine.Endpoint, error) {
	if discover == nil {
		return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: "native system DNS discovery is unavailable"}
	}
	result, err := discover(ctx)
	if err != nil {
		return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: "native system DNS discovery failed: " + err.Error()}
	}
	endpoints := make(map[int][]dnsengine.Endpoint)
	for index, operation := range operations {
		if operation.Endpoint.Kind != dnsobs.EndpointSystem {
			continue
		}
		rotation := dnsSystemRotation.Add(1) - 1
		targets, selectErr := result.SelectTrustedDialTargets(systemdns.Selection{Name: operation.Question.Name, Rotation: rotation})
		if selectErr != nil {
			return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: fmt.Sprintf("operation %q has no trusted system DNS route: %v", operation.OperationID, selectErr)}
		}
		if len(targets) == 0 {
			return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: fmt.Sprintf("operation %q has no trusted system DNS resolver", operation.OperationID)}
		}
		planned := make([]dnsengine.Endpoint, len(targets))
		for resolverIndex, target := range targets {
			endpoint, endpointErr := dnsengine.NewTrustedSystemEndpoint(target, dnsengine.Protocol(operation.Endpoint.Protocol))
			if endpointErr != nil {
				return nil, &dnsTaskError{Code: "SYSTEM_DNS_UNAVAILABLE", Message: fmt.Sprintf("operation %q trusted system resolver %d is unusable: %v", operation.OperationID, resolverIndex, endpointErr)}
			}
			planned[resolverIndex] = endpoint
		}
		endpoints[index] = planned
	}
	return endpoints, nil
}

func dnsEngineEndpoint(endpoint dnsobs.Endpoint) (dnsengine.Endpoint, error) {
	if endpoint.Kind == dnsobs.EndpointSystem {
		return dnsengine.Endpoint{}, errors.New("system endpoints require native resolver discovery")
	}
	protocol := dnsengine.Protocol(endpoint.Protocol)
	result := dnsengine.Endpoint{
		Protocol:   protocol,
		ConnectIP:  endpoint.ConnectIP,
		ServerName: endpoint.ServerName,
		Port:       uint16(endpoint.Port),
	}
	if endpoint.Protocol == dnsobs.ProtocolDoH {
		host := endpoint.HTTPAuthority
		if endpoint.Port != dnsobs.ProtocolDoH.DefaultPort() {
			host = net.JoinHostPort(host, strconv.Itoa(endpoint.Port))
		}
		path, err := url.Parse(endpoint.HTTPPath)
		if err != nil {
			return dnsengine.Endpoint{}, fmt.Errorf("parse DoH HTTP path: %w", err)
		}
		result.Address = (&url.URL{Scheme: "https", Host: host, Path: path.Path, RawPath: path.RawPath}).String()
		return result, nil
	}
	result.Address = endpoint.ConnectIP
	if result.Address == "" {
		return dnsengine.Endpoint{}, errors.New("wire endpoint requires a fixed connect_ip")
	}
	return result, nil
}

func executePreparedDNSOperation(ctx context.Context, roundID string, limits dnsobs.Limits, operation preparedDNSOperation, retryWait dnsRetryWaiter) (dnsobs.Observation, error) {
	started := time.Now()
	result, exchangeErr := operation.observer.Observe(ctx, operation.endpoint, operation.query)
	var terminalErr error
	if result == nil {
		return composeDNSExecutionFailure(roundID, operation.operation, started, nil, 1, fmt.Errorf("operation %q returned no DNS wire result", operation.operation.OperationID))
	}
	if exchangeErr != nil && ctx.Err() == nil && retryableDNSExchangeError(exchangeErr) {
		attemptsUsed := len(result.Attempts)
		if result.UDPToTCPFallback {
			if attemptsUsed < limits.MaxAttempts {
				if waitErr := waitForDNSRetry(ctx, retryWait); waitErr != nil {
					terminalErr = waitErr
				} else {
					retryEndpoint := operation.endpoint
					retryEndpoint.Protocol = dnsengine.ProtocolTCP
					retryResult, retryErr := operation.observer.Observe(ctx, retryEndpoint, operation.query)
					if retryResult == nil {
						return composeDNSExecutionFailure(roundID, operation.operation, started, result, len(result.Attempts), fmt.Errorf("operation %q TCP fallback retry returned no DNS wire result", operation.operation.OperationID))
					}
					result = mergeTCPFallbackRetry(result, retryResult, time.Since(started), retryErr)
					exchangeErr = retryErr
				}
			}
		} else if canRetryDNSExchange(operation.operation.Endpoint.Protocol, attemptsUsed, limits.MaxAttempts) {
			if waitErr := waitForDNSRetry(ctx, retryWait); waitErr != nil {
				terminalErr = waitErr
			} else {
				retryResult, retryErr := operation.observer.Observe(ctx, operation.retryEndpoint, operation.query)
				if retryResult == nil {
					return composeDNSExecutionFailure(roundID, operation.operation, started, result, len(result.Attempts), fmt.Errorf("operation %q retry returned no DNS wire result", operation.operation.OperationID))
				}
				result = mergeWholeDNSRetry(result, retryResult, time.Since(started))
				exchangeErr = retryErr
			}
		}
	}
	if result == nil {
		return composeDNSExecutionFailure(roundID, operation.operation, started, nil, 1, fmt.Errorf("operation %q retry returned no DNS wire result", operation.operation.OperationID))
	}
	finished := time.Now()
	result.StartedAt, result.Duration = composeDNSOperationTimeline(started, finished, finished.Sub(started))
	if len(result.Attempts) > limits.MaxAttempts || len(result.Attempts) > dnsobs.MaxAttempts {
		return composeDNSExecutionFailure(roundID, operation.operation, started, result, len(result.Attempts), fmt.Errorf("operation %q used %d physical attempts; limit is %d", operation.operation.OperationID, len(result.Attempts), limits.MaxAttempts))
	}
	observation, err := dnsengine.ToObservation(result, exchangeErr, dnsengine.ObservationEnvelope{
		RoundID:       roundID,
		OperationID:   operation.operation.OperationID,
		Question:      operation.operation.Question,
		Endpoint:      operation.operation.Endpoint,
		Comparison:    dnsobs.ComparisonUnknown,
		DNSSEC:        dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		TerminalError: terminalErr,
	})
	if err != nil {
		return composeDNSExecutionFailure(roundID, operation.operation, started, result, len(result.Attempts), fmt.Errorf("operation %q conversion failed: %w", operation.operation.OperationID, err))
	}
	return observation, nil
}

func composeDNSOperationTimeline(started time.Time, finished time.Time, elapsed time.Duration) (time.Time, time.Duration) {
	started = started.UTC()
	wallElapsed := finished.UTC().Sub(started)
	if wallElapsed > elapsed {
		elapsed = wallElapsed
	}
	if elapsed < 0 {
		elapsed = 0
	}
	return started, elapsed
}

func composeDNSExecutionFailure(roundID string, operation dnsobs.Operation, started time.Time, wireResult *dnsengine.Result, attempts int, cause error) (dnsobs.Observation, error) {
	if cause == nil {
		cause = errors.New("DNS operation failed after execution started")
	}
	_ = wireResult
	_ = attempts
	duration := time.Since(started)
	if duration < 0 {
		duration = 0
	}
	observation, err := dnsobs.NormalizeObservation(dnsobs.Observation{
		Schema:           dnsobs.SchemaV1,
		RoundID:          roundID,
		OperationID:      operation.OperationID,
		Question:         operation.Question,
		Endpoint:         operation.Endpoint,
		TransportStatus:  dnsobs.TransportNetworkError,
		AttemptCount:     0,
		Attempts:         []dnsobs.WireAttempt{},
		ResponseAttempt:  0,
		Protocol:         operation.Endpoint.Protocol,
		UDPToTCPFallback: false,
		StartedAt:        started.UTC(),
		ObservedAt:       started.Add(duration).UTC(),
		FinishedAt:       started.Add(duration).UTC(),
		DurationMS:       duration.Milliseconds(),
		Outcome:          dnsobs.DNSOutcomeNotObserved,
		Comparison:       dnsobs.ComparisonUnknown,
		DNSSEC:           dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		Error: &dnsobs.ObservationError{
			Code:      "INTERNAL_ERROR",
			Message:   "DNS operation failed after execution started",
			Retryable: false,
		},
	})
	if err != nil {
		return dnsobs.Observation{}, errors.Join(cause, fmt.Errorf("compose DNS execution failure: %w", err))
	}
	return observation, cause
}

func dnsExecutionFailureAttemptMetadata(operation dnsobs.Operation, result *dnsengine.Result, attempted int) (int, dnsobs.Protocol, bool) {
	attempts := max(1, attempted)
	protocol := operation.Endpoint.Protocol
	if result == nil || len(result.Attempts) == 0 {
		return attempts, protocol, false
	}
	attempts = len(result.Attempts)
	lastProtocol := dnsobs.Protocol(result.Attempts[attempts-1].Protocol)
	if validDNSFailureFallbackAttempts(result.Attempts) {
		return attempts, lastProtocol, true
	}
	return attempts, protocol, false
}

func validDNSFailureFallbackAttempts(attempts []dnsengine.Attempt) bool {
	if len(attempts) == 2 {
		return cleanDNSFallbackTrigger(attempts[0]) && attempts[1].Protocol == dnsengine.ProtocolTCP
	}
	if len(attempts) != 3 || attempts[0].Protocol != dnsengine.ProtocolUDP || attempts[2].Protocol != dnsengine.ProtocolTCP {
		return false
	}
	switch attempts[1].Protocol {
	case dnsengine.ProtocolUDP:
		return failedDNSRetryAttempt(attempts[0]) && cleanDNSFallbackTrigger(attempts[1])
	case dnsengine.ProtocolTCP:
		return cleanDNSFallbackTrigger(attempts[0]) && failedDNSRetryAttempt(attempts[1])
	default:
		return false
	}
}

func cleanDNSFallbackTrigger(attempt dnsengine.Attempt) bool {
	return attempt.Protocol == dnsengine.ProtocolUDP && attempt.Truncated && attempt.Error == ""
}

func failedDNSRetryAttempt(attempt dnsengine.Attempt) bool {
	return !attempt.Truncated && attempt.Error != ""
}

func waitForDNSRetry(ctx context.Context, wait dnsRetryWaiter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if wait == nil {
		return nil
	}
	if err := wait(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func waitDNSRetryJitter(ctx context.Context) error {
	timer := time.NewTimer(dnsRetryJitterDuration())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func dnsRetryJitterDuration() time.Duration {
	span := maxDNSRetryJitter - minDNSRetryJitter
	return minDNSRetryJitter + time.Duration(rand.Int64N(int64(span)+1))
}

func canRetryDNSExchange(protocol dnsobs.Protocol, attemptsUsed int, maxAttempts int) bool {
	remaining := maxAttempts - attemptsUsed
	if protocol == dnsobs.ProtocolUDP {
		// A retried UDP query must retain one physical-attempt slot for a
		// mandatory TCP fallback if the retry response sets TC.
		return remaining >= 2
	}
	return remaining >= 1
}

func retryableDNSExchangeError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, dnsengine.ErrInvalidEndpoint) || errors.Is(err, dnsengine.ErrInvalidQuery) || errors.Is(err, dnsengine.ErrECSDisabled) || errors.Is(err, dnsengine.ErrMalformedResponse) || errors.Is(err, dnsengine.ErrResponseMismatch) || errors.Is(err, dnsengine.ErrResponseTooLarge) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func mergeWholeDNSRetry(first *dnsengine.Result, retry *dnsengine.Result, duration time.Duration) *dnsengine.Result {
	if retry == nil {
		return first
	}
	merged := *retry
	if first != nil {
		merged.Attempts = append(append([]dnsengine.Attempt(nil), first.Attempts...), retry.Attempts...)
		merged.StartedAt = first.StartedAt
	}
	merged.Duration = duration
	return &merged
}

func mergeTCPFallbackRetry(first *dnsengine.Result, retry *dnsengine.Result, duration time.Duration, retryErr error) *dnsengine.Result {
	if first == nil {
		return retry
	}
	if retry != nil && (retryErr == nil || errors.Is(retryErr, dnsengine.ErrMalformedResponse) || errors.Is(retryErr, dnsengine.ErrResponseMismatch)) {
		merged := *retry
		merged.Attempts = append(append([]dnsengine.Attempt(nil), first.Attempts...), retry.Attempts...)
		merged.StartedAt = first.StartedAt
		merged.Duration = duration
		merged.UDPToTCPFallback = true
		// A malformed final TCP response keeps only evidence owned by that retry;
		// promotePendingTCPHeader decides whether its TC prefix is trustworthy.
		return &merged
	}
	merged := *first
	if retry != nil {
		merged.Attempts = append(append([]dnsengine.Attempt(nil), first.Attempts...), retry.Attempts...)
	}
	merged.Duration = duration
	return &merged
}

func cancelledDNSObservation(roundID string, operation dnsobs.Operation) (dnsobs.Observation, error) {
	cancelledAt := time.Now().UTC()
	return dnsobs.NormalizeObservation(dnsobs.Observation{
		Schema:          dnsobs.SchemaV1,
		RoundID:         roundID,
		OperationID:     operation.OperationID,
		Question:        operation.Question,
		Endpoint:        operation.Endpoint,
		TransportStatus: dnsobs.TransportCancelled,
		AttemptCount:    0,
		Attempts:        []dnsobs.WireAttempt{},
		ResponseAttempt: 0,
		Protocol:        operation.Endpoint.Protocol,
		StartedAt:       cancelledAt,
		ObservedAt:      cancelledAt,
		FinishedAt:      cancelledAt,
		Outcome:         dnsobs.DNSOutcomeNotObserved,
		Comparison:      dnsobs.ComparisonUnknown,
		DNSSEC:          dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate},
		Error: &dnsobs.ObservationError{
			Code:      "CANCELLED",
			Message:   "operation cancelled before its first wire attempt",
			Retryable: false,
		},
	})
}

func dnsTaskTypeIsCapability(taskType string) bool {
	return strings.EqualFold(strings.TrimSpace(taskType), dnsObserveCapability)
}
