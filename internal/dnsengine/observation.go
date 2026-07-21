package dnsengine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

// ObservationEnvelope supplies operation metadata that is intentionally not
// owned by the wire engine.
type ObservationEnvelope struct {
	RoundID     string
	OperationID string
	Question    dnsobs.Question
	Endpoint    dnsobs.Endpoint
	Comparison  dnsobs.Comparison
	DNSSEC      dnsobs.DNSSECResult
	// TerminalError overrides only the operation-level decision when cancellation
	// or deadline fires after the last retryable wire attempt completed.
	TerminalError error
}

// ToObservation is the bounded boundary between transport results and the
// public DNS observation contract. It never exposes the raw dns.Msg.
func ToObservation(result *Result, exchangeErr error, envelope ObservationEnvelope) (dnsobs.Observation, error) {
	if result == nil {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: result is nil")
	}
	if result.StartedAt.IsZero() {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: started_at is required")
	}
	if len(result.Attempts) > dnsobs.MaxAttempts {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: got %d attempts, limit %d", len(result.Attempts), dnsobs.MaxAttempts)
	}
	question, err := dnsobs.NormalizeQuestion(envelope.Question)
	if err != nil {
		return dnsobs.Observation{}, err
	}
	if err := resultQuestionMatches(result.Question, question); err != nil {
		return dnsobs.Observation{}, err
	}
	endpoint, err := dnsobs.NormalizeEndpoint(envelope.Endpoint)
	if err != nil {
		return dnsobs.Observation{}, err
	}
	if result.UDPToTCPFallback {
		if !validFallbackAttemptSequence(result.Attempts) {
			return dnsobs.Observation{}, fmt.Errorf("convert DNS result: invalid UDP to TCP fallback attempts")
		}
	} else {
		if len(result.Attempts) > 2 {
			return dnsobs.Observation{}, fmt.Errorf("convert DNS result: more than one retry without UDP to TCP fallback")
		}
		if len(result.Attempts) == 2 && result.Attempts[0].Error == "" {
			return dnsobs.Observation{}, fmt.Errorf("convert DNS result: non-fallback retry has no preceding transport error")
		}
		for _, attempt := range result.Attempts {
			if attempt.Protocol != result.Protocol {
				return dnsobs.Observation{}, fmt.Errorf("convert DNS result: non-fallback attempt protocol mismatch")
			}
		}
	}
	result = promotePendingTCPHeader(result, exchangeErr)

	protocol := result.Protocol
	lastPeerIP := ""
	duration := result.Duration
	if len(result.Attempts) != 0 {
		last := result.Attempts[len(result.Attempts)-1]
		protocol = last.Protocol
		lastPeerIP = last.PeerIP
	}
	if duration < 0 {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: negative duration")
	}
	if err := validateAttemptTimelines(result); err != nil {
		return dnsobs.Observation{}, err
	}

	wireTransport, malformed := classifyExchangeError(exchangeErr)
	if err := validateTerminalAttemptError(result, exchangeErr, malformed); err != nil {
		return dnsobs.Observation{}, err
	}
	terminalErr := exchangeErr
	transport := wireTransport
	if envelope.TerminalError != nil {
		if err := validateTerminalDecisionOverride(result, exchangeErr, envelope.TerminalError); err != nil {
			return dnsobs.Observation{}, err
		}
		terminalErr = envelope.TerminalError
		var terminalMalformed bool
		transport, terminalMalformed = classifyExchangeError(terminalErr)
		if terminalMalformed {
			return dnsobs.Observation{}, fmt.Errorf("convert DNS result: terminal decision override must be cancellation or deadline")
		}
	}
	malformedResponse := malformed
	retainedParsedUDP := exchangeErr != nil && !malformed && result.ResponseParsed && result.UDPToTCPFallback && result.ResponseTruncated && result.Flags.Truncated
	retainedHeader := exchangeErr != nil && result.ResponseHeaderValidated && result.Outcome == OutcomeTruncatedResponse && result.UDPToTCPFallback && result.ResponseTruncated && result.Flags.Truncated
	retainedUDP := retainedParsedUDP || (retainedHeader && !malformed)
	retainedFinalTCPHeader := retainedHeader && malformed
	retainedFallback := retainedUDP || retainedFinalTCPHeader
	if (result.ResponseParsed || result.ResponseHeaderValidated) && exchangeErr != nil && !retainedFallback {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: failed transport contains unqualified parsed response evidence")
	}
	if result.ResponseParsed && result.ResponseHeaderValidated {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: response cannot be both fully parsed and header-only")
	}
	if retainedFallback {
		malformed = false
	}
	if exchangeErr == nil && (!result.ResponseParsed || result.ResponseHeaderValidated) {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: successful exchange has no parsed response")
	}

	var evidenceAttempt *Attempt
	switch {
	case exchangeErr == nil:
		evidenceAttempt, err = successfulResponseAttempt(result)
	case retainedUDP:
		evidenceAttempt, err = retainedUDPResponseAttempt(result, exchangeErr)
	case retainedFinalTCPHeader:
		evidenceAttempt, err = finalMalformedResponseAttempt(result, exchangeErr, true)
	case malformedResponse && result.ResponseSize > 0:
		evidenceAttempt, err = finalMalformedResponseAttempt(result, exchangeErr, false)
	}
	if err != nil {
		return dnsobs.Observation{}, err
	}
	attempts, responseAttempt, err := publicWireAttempts(result, evidenceAttempt)
	if err != nil {
		return dnsobs.Observation{}, err
	}
	operationStartedAt := result.StartedAt.UTC()
	observedAt := operationStartedAt.Add(duration)
	if evidenceAttempt != nil && responseAttempt > 0 {
		observedAt = attempts[responseAttempt-1].FinishedAt
	}
	peerIP := lastPeerIP
	if evidenceAttempt != nil {
		peerIP = result.PeerIP
	}

	comparison := envelope.Comparison
	if comparison == "" {
		comparison = dnsobs.ComparisonUnknown
	}
	dnssec := envelope.DNSSEC
	if dnssec.Status == "" {
		dnssec.Status = dnsobs.DNSSECIndeterminate
	}
	responseSize := result.ResponseSize
	if evidenceAttempt == nil && len(result.Attempts) != 0 {
		responseSize = result.Attempts[len(result.Attempts)-1].ResponseSize
	}
	dropped := false
	if responseSize < 0 {
		responseSize = 0
		dropped = true
	}
	if responseSize > dnsobs.MaxObservationBytes {
		responseSize = dnsobs.MaxObservationBytes
		dropped = true
	}

	observation := dnsobs.Observation{
		Schema:            dnsobs.SchemaV1,
		RoundID:           envelope.RoundID,
		OperationID:       envelope.OperationID,
		Question:          question,
		Endpoint:          endpoint,
		TransportStatus:   transport,
		AttemptCount:      len(result.Attempts),
		Attempts:          attempts,
		ResponseAttempt:   responseAttempt,
		PeerIP:            peerIP,
		Protocol:          dnsobs.Protocol(protocol),
		UDPToTCPFallback:  result.UDPToTCPFallback,
		StartedAt:         operationStartedAt,
		ObservedAt:        observedAt.UTC(),
		FinishedAt:        operationStartedAt.Add(duration),
		DurationMS:        duration.Milliseconds(),
		Comparison:        comparison,
		DNSSEC:            dnssec,
		ResponseTruncated: result.ResponseTruncated,
		ResultTruncated:   result.ResultTruncated,
		ResponseSizeBytes: responseSize,
	}

	headerOnlyObservation := result.ResponseHeaderValidated
	if result.ResponseParsed && !headerOnlyObservation {
		dropped = populateObservationEvidence(&observation, result) || dropped
	} else if headerOnlyObservation {
		populateObservationHeaderEvidence(&observation, result)
		observation.DNSSEC = dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}
	} else if malformed {
		observation.Outcome = dnsobs.DNSOutcomeMalformed
		observation.DNSSEC = dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}
	} else {
		observation.Outcome = dnsobs.DNSOutcomeNotObserved
		observation.DNSSEC = dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}
	}
	if terminalErr != nil {
		observation.Error, dropped = observationError(terminalErr, transport, malformed && envelope.TerminalError == nil, dropped)
	}
	if dropped || observation.ResponseTruncated || observation.ResultTruncated || transport != dnsobs.TransportSuccess || observation.Outcome == dnsobs.DNSOutcomeMalformed {
		observation.ResultTruncated = observation.ResultTruncated || dropped
		observation.Comparison = dnsobs.ComparisonUnknown
		if observation.ResponseTruncated || observation.ResultTruncated {
			observation.DNSSEC = dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}
		}
	}

	normalized, fitDropped, err := fitObservation(observation)
	if err != nil {
		return dnsobs.Observation{}, err
	}
	if fitDropped && !normalized.ResultTruncated {
		return dnsobs.Observation{}, fmt.Errorf("convert DNS result: bounded conversion lost truncation marker")
	}
	return normalized, nil
}

func validFallbackAttemptSequence(attempts []Attempt) bool {
	if len(attempts) == 2 {
		return attempts[0].Protocol == ProtocolUDP && attempts[0].Truncated && attempts[0].Error == "" &&
			attempts[1].Protocol == ProtocolTCP
	}
	if len(attempts) != 3 || attempts[0].Protocol != ProtocolUDP || attempts[2].Protocol != ProtocolTCP {
		return false
	}
	switch attempts[1].Protocol {
	case ProtocolUDP:
		return !attempts[0].Truncated && attempts[0].Error != "" &&
			attempts[1].Truncated && attempts[1].Error == ""
	case ProtocolTCP:
		return attempts[0].Truncated && attempts[0].Error == "" &&
			!attempts[1].Truncated && attempts[1].Error != ""
	default:
		return false
	}
}

func promotePendingTCPHeader(result *Result, exchangeErr error) *Result {
	if result == nil || result.pendingTCPHeader == nil || !result.UDPToTCPFallback ||
		(!errors.Is(exchangeErr, ErrMalformedResponse) && !errors.Is(exchangeErr, ErrResponseMismatch)) {
		return result
	}
	header := result.pendingTCPHeader
	if len(result.Attempts) == 0 {
		return result
	}
	last := result.Attempts[len(result.Attempts)-1]
	if last.Protocol != ProtocolTCP || last.Error != "" || !last.Truncated || last.ResponseSize != header.ResponseSize ||
		last.PeerIP != header.PeerIP || !last.StartedAt.Equal(header.AttemptStartedAt) ||
		result.ResponseSize != header.ResponseSize || result.PeerIP != header.PeerIP {
		return result
	}
	promoted := *result
	promoted.Message = nil
	promoted.RCode = header.RCode
	promoted.ExtendedRCode = 0
	promoted.Flags = header.Flags
	promoted.EDNS = EDNS{}
	promoted.Outcome = OutcomeTruncatedResponse
	promoted.Sections = Sections{}
	promoted.AliasChain = AliasChain{}
	promoted.NegativeTTL = nil
	promoted.ResponseParsed = false
	promoted.ResponseHeaderValidated = true
	promoted.ResponseTruncated = true
	promoted.ResultTruncated = false
	return &promoted
}

func successfulResponseAttempt(result *Result) (*Attempt, error) {
	last, err := finalResponseAttempt(result)
	if err != nil {
		return nil, err
	}
	if last.Error != "" {
		return nil, fmt.Errorf("convert DNS result: successful response belongs to an attempt with an error")
	}
	if result.UDPToTCPFallback && last.Protocol != ProtocolTCP {
		return nil, fmt.Errorf("convert DNS result: successful fallback response does not belong to the final TCP attempt")
	}
	if err := validateResponseAttemptProvenance(result, last, true); err != nil {
		return nil, err
	}
	return last, nil
}

func retainedUDPResponseAttempt(result *Result, exchangeErr error) (*Attempt, error) {
	last, err := finalResponseAttempt(result)
	if err != nil {
		return nil, err
	}
	if last.Protocol != ProtocolTCP || last.Error == "" || last.Truncated || !attemptErrorMatches(last.Error, exchangeErr) {
		return nil, fmt.Errorf("convert DNS result: failed fallback does not end with a matching TCP error")
	}
	if err := validateAttemptTiming(result, last); err != nil {
		return nil, err
	}

	var owner *Attempt
	for index := range result.Attempts[:len(result.Attempts)-1] {
		attempt := &result.Attempts[index]
		if attempt.Protocol != ProtocolUDP || !attempt.Truncated || attempt.Error != "" {
			continue
		}
		if owner != nil {
			return nil, fmt.Errorf("convert DNS result: failed fallback has ambiguous UDP TC evidence")
		}
		owner = attempt
	}
	if owner == nil {
		return nil, fmt.Errorf("convert DNS result: failed fallback has no successful UDP TC evidence")
	}
	if err := validateResponseAttemptProvenance(result, owner, true); err != nil {
		return nil, err
	}
	return owner, nil
}

func finalMalformedResponseAttempt(result *Result, exchangeErr error, headerOnly bool) (*Attempt, error) {
	last, err := finalResponseAttempt(result)
	if err != nil {
		return nil, err
	}
	if result.UDPToTCPFallback && last.Protocol != ProtocolTCP {
		return nil, fmt.Errorf("convert DNS result: malformed fallback evidence does not belong to the final TCP attempt")
	}
	if last.Error != "" && !attemptErrorMatches(last.Error, exchangeErr) {
		return nil, fmt.Errorf("convert DNS result: malformed response attempt error does not match the exchange error")
	}
	if headerOnly {
		if last.Protocol != ProtocolTCP || last.Error != "" || !last.Truncated {
			return nil, fmt.Errorf("convert DNS result: header-only fallback evidence is not a final TCP TC response")
		}
		if result.pendingTCPHeader != nil {
			header := result.pendingTCPHeader
			if header.ResponseSize != last.ResponseSize || header.PeerIP != last.PeerIP || !header.AttemptStartedAt.Equal(last.StartedAt) {
				return nil, fmt.Errorf("convert DNS result: pending TCP header provenance does not match the final attempt")
			}
		}
	}
	if err := validateResponseAttemptProvenance(result, last, headerOnly); err != nil {
		return nil, err
	}
	return last, nil
}

func finalResponseAttempt(result *Result) (*Attempt, error) {
	if len(result.Attempts) == 0 {
		return nil, fmt.Errorf("convert DNS result: response evidence has no wire attempt")
	}
	return &result.Attempts[len(result.Attempts)-1], nil
}

func validateResponseAttemptProvenance(result *Result, attempt *Attempt, requireTrustedTC bool) error {
	if attempt.PeerIP != result.PeerIP || attempt.ResponseSize != result.ResponseSize {
		return fmt.Errorf("convert DNS result: response evidence does not match its owning wire attempt")
	}
	if requireTrustedTC && (attempt.Truncated != result.ResponseTruncated || attempt.Truncated != result.Flags.Truncated) {
		return fmt.Errorf("convert DNS result: trusted response TC state does not match its owning wire attempt")
	}
	return validateAttemptTiming(result, attempt)
}

func validateAttemptTiming(result *Result, attempt *Attempt) error {
	if attempt.StartedAt.IsZero() || attempt.Duration < 0 {
		return fmt.Errorf("convert DNS result: invalid response attempt timing")
	}
	completedAt := attempt.StartedAt.Add(attempt.Duration)
	decisionTime := result.StartedAt.Add(result.Duration)
	if attempt.StartedAt.Before(result.StartedAt) || completedAt.After(decisionTime) {
		return fmt.Errorf(
			"convert DNS result: response attempt timing is outside the operation interval: attempt=[%s,%s] operation=[%s,%s]",
			attempt.StartedAt.Format(time.RFC3339Nano),
			completedAt.Format(time.RFC3339Nano),
			result.StartedAt.Format(time.RFC3339Nano),
			decisionTime.Format(time.RFC3339Nano),
		)
	}
	return nil
}

func validateAttemptTimelines(result *Result) error {
	var previousCompletedAt time.Time
	for index := range result.Attempts {
		attempt := &result.Attempts[index]
		if err := validateAttemptTiming(result, attempt); err != nil {
			return err
		}
		if index != 0 && attempt.StartedAt.Before(previousCompletedAt) {
			return fmt.Errorf("convert DNS result: wire attempts overlap or are out of order")
		}
		previousCompletedAt = attempt.StartedAt.Add(attempt.Duration)
	}
	return nil
}

func validateTerminalAttemptError(result *Result, exchangeErr error, malformed bool) error {
	if exchangeErr == nil || len(result.Attempts) == 0 {
		return nil
	}
	last := result.Attempts[len(result.Attempts)-1]
	if malformed {
		if last.Error != "" && !attemptErrorMatches(last.Error, exchangeErr) {
			return fmt.Errorf("convert DNS result: final malformed attempt error does not match the exchange error")
		}
		return nil
	}
	if last.Error == "" || !attemptErrorMatches(last.Error, exchangeErr) {
		return fmt.Errorf("convert DNS result: failed exchange does not end with a matching attempt error")
	}
	if result.UDPToTCPFallback && last.Truncated {
		return fmt.Errorf("convert DNS result: failed TCP fallback attempt cannot own trusted TC evidence")
	}
	return nil
}

func validateTerminalDecisionOverride(result *Result, exchangeErr error, terminalErr error) error {
	if !errors.Is(terminalErr, context.Canceled) && !errors.Is(terminalErr, context.DeadlineExceeded) {
		return fmt.Errorf("convert DNS result: terminal decision override must be cancellation or deadline")
	}
	if exchangeErr == nil || len(result.Attempts) == 0 {
		return fmt.Errorf("convert DNS result: terminal decision override has no preceding failed wire attempt")
	}
	_, malformed := classifyExchangeError(exchangeErr)
	if malformed {
		return fmt.Errorf("convert DNS result: malformed response cannot be replaced by a retry-gap terminal decision")
	}
	status, attemptErr := publicAttemptTransport(result.Attempts[len(result.Attempts)-1])
	if status == dnsobs.TransportSuccess || attemptErr == nil || !attemptErr.Retryable {
		return fmt.Errorf("convert DNS result: terminal decision override requires a retryable final wire error")
	}
	last := result.Attempts[len(result.Attempts)-1]
	if result.StartedAt.Add(result.Duration).Before(last.StartedAt.Add(last.Duration)) {
		return fmt.Errorf("convert DNS result: terminal decision precedes the final wire attempt")
	}
	return nil
}

func publicWireAttempts(result *Result, evidenceAttempt *Attempt) ([]dnsobs.WireAttempt, int, error) {
	attempts := make([]dnsobs.WireAttempt, len(result.Attempts))
	responseAttempt := 0
	operationStartedAt := result.StartedAt.UTC()
	for index := range result.Attempts {
		source := result.Attempts[index]
		// Keep Engine timing on the monotonic clock, then project every public
		// timestamp from the operation's one UTC wall-clock base. Independent
		// wall-clock conversions can otherwise differ by a few microseconds.
		startedAt := operationStartedAt.Add(source.StartedAt.Sub(result.StartedAt))
		status, attemptErr := publicAttemptTransport(source)
		trustedTC := false
		if source.Truncated && status == dnsobs.TransportSuccess {
			if index+1 < len(result.Attempts) && source.Protocol == ProtocolUDP && result.Attempts[index+1].Protocol == ProtocolTCP {
				trustedTC = true
			}
			if evidenceAttempt == &result.Attempts[index] && result.ResponseTruncated && result.Flags.Truncated {
				trustedTC = true
			}
		}
		attempts[index] = dnsobs.WireAttempt{
			Protocol:          dnsobs.Protocol(source.Protocol),
			TransportStatus:   status,
			StartedAt:         startedAt,
			FinishedAt:        startedAt.Add(source.Duration),
			DurationMS:        source.Duration.Milliseconds(),
			PeerIP:            source.PeerIP,
			ResponseSizeBytes: source.ResponseSize,
			ResponseTruncated: trustedTC,
			Error:             attemptErr,
		}
		if evidenceAttempt == &result.Attempts[index] {
			responseAttempt = index + 1
		}
	}
	if evidenceAttempt != nil && responseAttempt == 0 {
		return nil, 0, fmt.Errorf("convert DNS result: response evidence owner is outside the attempt transcript")
	}
	return attempts, responseAttempt, nil
}

func publicAttemptTransport(attempt Attempt) (dnsobs.TransportStatus, *dnsobs.AttemptError) {
	if attempt.Error == "" {
		return dnsobs.TransportSuccess, nil
	}
	if attemptSemanticResponseError(attempt) {
		return dnsobs.TransportSuccess, nil
	}
	err := attempt.err
	text := strings.ToLower(strings.TrimSpace(attempt.Error))
	switch {
	case errors.Is(err, context.Canceled) || text == context.Canceled.Error() || strings.HasSuffix(text, ": "+context.Canceled.Error()):
		return dnsobs.TransportCancelled, &dnsobs.AttemptError{Code: "CANCELLED", Retryable: false}
	case errors.Is(err, context.DeadlineExceeded) || text == context.DeadlineExceeded.Error() || strings.HasSuffix(text, ": "+context.DeadlineExceeded.Error()):
		return dnsobs.TransportTimeout, &dnsobs.AttemptError{Code: "TIMEOUT", Retryable: true}
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(text, "connection refused"):
		return dnsobs.TransportRefused, &dnsobs.AttemptError{Code: "CONNECTION_REFUSED", Retryable: true}
	case errors.Is(err, ErrResponseTooLarge) || strings.Contains(text, strings.ToLower(ErrResponseTooLarge.Error())):
		return dnsobs.TransportNetworkError, &dnsobs.AttemptError{Code: "RESPONSE_TOO_LARGE", Retryable: false}
	default:
		return dnsobs.TransportNetworkError, &dnsobs.AttemptError{Code: "NETWORK_ERROR", Retryable: true}
	}
}

func attemptSemanticResponseError(attempt Attempt) bool {
	if attempt.ResponseSize <= 0 || attempt.PeerIP == "" {
		return false
	}
	if errors.Is(attempt.err, ErrMalformedResponse) || errors.Is(attempt.err, ErrResponseMismatch) {
		return true
	}
	text := strings.ToLower(strings.TrimSpace(attempt.Error))
	return strings.Contains(text, strings.ToLower(ErrMalformedResponse.Error())) || strings.Contains(text, strings.ToLower(ErrResponseMismatch.Error()))
}

func attemptErrorMatches(attemptError string, exchangeErr error) bool {
	if attemptError == "" || exchangeErr == nil {
		return false
	}
	exchangeText := exchangeErr.Error()
	return attemptError == exchangeText || strings.HasSuffix(exchangeText, ": "+attemptError) || strings.HasSuffix(attemptError, ": "+exchangeText)
}

func populateObservationHeaderEvidence(observation *dnsobs.Observation, result *Result) {
	rcode := result.RCode
	observation.RCode = &rcode
	observation.Flags = dnsobs.DNSFlags{
		Response:           result.Flags.Response,
		Authoritative:      result.Flags.Authoritative,
		Truncated:          result.Flags.Truncated,
		RecursionDesired:   result.Flags.RecursionDesired,
		RecursionAvailable: result.Flags.RecursionAvailable,
		ReservedZ:          result.Flags.ReservedZ,
		AuthenticData:      result.Flags.AuthenticData,
		CheckingDisabled:   result.Flags.CheckingDisabled,
	}
	observation.Outcome = dnsobs.DNSOutcomeTruncatedResponse
}

func resultQuestionMatches(question dns.Question, expected dnsobs.Question) error {
	normalized, err := normalizeWireQuestion(question)
	if err != nil {
		return fmt.Errorf("convert DNS result question: %w", err)
	}
	if normalized.Name != expected.Name || dnsobs.RRType(typeName(normalized.Qtype)) != expected.Type || normalized.Qclass != dns.ClassINET {
		return fmt.Errorf("convert DNS result: result question does not match operation question")
	}
	return nil
}

func classifyExchangeError(err error) (dnsobs.TransportStatus, bool) {
	if err == nil {
		return dnsobs.TransportSuccess, false
	}
	if errors.Is(err, context.Canceled) {
		return dnsobs.TransportCancelled, false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return dnsobs.TransportTimeout, false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return dnsobs.TransportRefused, false
	}
	if errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrResponseMismatch) {
		return dnsobs.TransportSuccess, true
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return dnsobs.TransportTimeout, false
	}
	return dnsobs.TransportNetworkError, false
}

func populateObservationEvidence(observation *dnsobs.Observation, result *Result) bool {
	rcode := result.RCode
	observation.RCode = &rcode
	if result.EDNS.Present {
		extendedRCode := result.ExtendedRCode
		observation.ExtendedRCode = &extendedRCode
	}
	observation.Flags = dnsobs.DNSFlags{
		Response:           result.Flags.Response,
		Authoritative:      result.Flags.Authoritative,
		Truncated:          result.Flags.Truncated,
		RecursionDesired:   result.Flags.RecursionDesired,
		RecursionAvailable: result.Flags.RecursionAvailable,
		ReservedZ:          result.Flags.ReservedZ,
		AuthenticData:      result.Flags.AuthenticData,
		CheckingDisabled:   result.Flags.CheckingDisabled,
	}
	observation.Outcome = convertOutcome(result.Outcome)
	observation.ResultTruncated = observation.ResultTruncated || result.AliasChain.Truncated

	dropped := false
	observation.EDNS, dropped = convertEDNS(result.EDNS)
	observation.Sections.Answer, dropped = convertRecordsForObservation(result.Sections.Answer, dropped)
	observation.Sections.Authority, dropped = convertRecordsForObservation(result.Sections.Authority, dropped)
	observation.Sections.Additional, dropped = convertRecordsForObservation(result.Sections.Additional, dropped)
	convertedAlias, aliasDropped := convertAliasChain(result.AliasChain, dropped)
	dropped = dropped || aliasDropped
	if result.ResultTruncated || dropped {
		observation.AliasChain = dnsobs.AliasChain{}
	} else {
		observation.AliasChain = convertedAlias
	}
	if result.NegativeTTL != nil {
		if observation.Outcome == dnsobs.DNSOutcomeNoData || observation.Outcome == dnsobs.DNSOutcomeNXDomain {
			value := *result.NegativeTTL
			observation.NegativeTTL = &value
		} else {
			dropped = true
		}
	}
	return dropped
}

func convertOutcome(outcome Outcome) dnsobs.DNSOutcome {
	switch outcome {
	case OutcomeAnswer:
		return dnsobs.DNSOutcomeAnswer
	case OutcomeNoData:
		return dnsobs.DNSOutcomeNoData
	case OutcomeNXDomain:
		return dnsobs.DNSOutcomeNXDomain
	case OutcomeServFail:
		return dnsobs.DNSOutcomeServFail
	case OutcomeRefused:
		return dnsobs.DNSOutcomeRefused
	case OutcomeReferral:
		return dnsobs.DNSOutcomeReferral
	case OutcomeMalformed:
		return dnsobs.DNSOutcomeMalformed
	case OutcomeTruncatedResponse:
		return dnsobs.DNSOutcomeTruncatedResponse
	case OutcomeOther:
		return dnsobs.DNSOutcomeRCodeError
	default:
		return ""
	}
}

func convertEDNS(source EDNS) (dnsobs.EDNS, bool) {
	if !source.Present {
		return dnsobs.EDNS{}, source.UDPSize != 0 || source.Version != 0 || source.Flags != 0 || source.DNSSECOK || source.ECS != nil || len(source.EDE) != 0 || source.NSIDHex != "" || len(source.Options) != 0
	}
	result := dnsobs.EDNS{Present: true, UDPSize: int(source.UDPSize), Version: source.Version, Flags: source.Flags, DNSSECOK: source.DNSSECOK}
	dropped := source.UDPSize < 512
	if dropped {
		return dnsobs.EDNS{}, true
	}
	if source.ECS != nil {
		address, err := netip.ParseAddr(strings.TrimSpace(source.ECS.Address))
		if err == nil && address.Zone() == "" {
			address = address.Unmap()
			bits := uint8(128)
			if address.Is4() {
				bits = 32
			}
			if source.ECS.SourcePrefix <= bits && source.ECS.ScopePrefix <= bits {
				result.ECS = &dnsobs.ClientSubnet{Address: address.String(), SourcePrefix: source.ECS.SourcePrefix, ScopePrefix: source.ECS.ScopePrefix}
			} else {
				dropped = true
			}
		} else {
			dropped = true
		}
	}
	for _, value := range source.EDE {
		if len(result.EDE) == dnsobs.MaxExtendedDNSErrors || !utf8.ValidString(value.Text) || len(value.Text) > dnsobs.MaxErrorMessageBytes {
			dropped = true
			continue
		}
		result.EDE = append(result.EDE, dnsobs.ExtendedDNSError{Code: value.Code, Text: value.Text})
	}
	if source.NSIDHex != "" {
		value := strings.ToLower(strings.TrimSpace(source.NSIDHex))
		decoded, err := hex.DecodeString(value)
		if err == nil && len(decoded) <= dnsobs.MaxRDataBytes {
			result.NSIDHex = value
		} else {
			dropped = true
		}
	}
	for _, value := range source.Options {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.DataBase64)
		if len(result.Options) == dnsobs.MaxEDNSOptions || err != nil || len(decoded) > dnsobs.MaxRDataBytes {
			dropped = true
			continue
		}
		result.Options = append(result.Options, dnsobs.EDNSOption{Code: value.Code, DataBase64: base64.StdEncoding.EncodeToString(decoded)})
	}
	return result, dropped
}

func convertRecordsForObservation(source []ResourceRecord, alreadyDropped bool) ([]dnsobs.ResourceRecord, bool) {
	type rrSetGroup struct {
		records []dnsobs.ResourceRecord
	}
	groups := make(map[observationRRSetKey]*rrSetGroup, len(source))
	orderedKeys := make([]observationRRSetKey, 0, len(source))
	dropped := alreadyDropped
	for _, record := range source {
		key, err := normalizeObservationRRSetKey(record.Owner, dnsobs.RRType(record.Type), dnsobs.DNSClass(record.Class))
		if err != nil {
			dropped = true
			continue
		}
		group := groups[key]
		if group == nil {
			orderedKeys = append(orderedKeys, key)
			group = &rrSetGroup{}
			groups[key] = group
		}
		group.records = append(group.records, dnsobs.ResourceRecord{
			Owner:            key.owner,
			Type:             key.rrType,
			Class:            key.class,
			TTL:              record.TTL,
			DisplayRData:     record.DisplayRData,
			CanonicalRData:   record.CanonicalRData,
			RRSetRecordCount: record.RRSetRecordCount,
		})
	}

	result := make([]dnsobs.ResourceRecord, 0, min(len(source), dnsobs.MaxSectionRecordLimit))
	limitClosed := false
	for _, key := range orderedKeys {
		records := groups[key].records
		valid := true
		expectedCount := records[0].RRSetRecordCount
		for _, record := range records {
			if record.RRSetRecordCount <= 0 || record.RRSetRecordCount > dnsobs.MaxSectionRecordLimit ||
				record.RRSetRecordCount != expectedCount || !validObservationRData(record) {
				valid = false
				break
			}
		}
		if expectedCount != len(records) {
			valid = false
		}
		if !valid {
			dropped = true
			continue
		}
		if limitClosed || len(result)+len(records) > dnsobs.MaxSectionRecordLimit {
			dropped = true
			limitClosed = true
			continue
		}
		result = append(result, records...)
	}
	return result, dropped
}

func validObservationRData(record dnsobs.ResourceRecord) bool {
	return utf8.ValidString(record.DisplayRData) && utf8.ValidString(record.CanonicalRData) &&
		record.DisplayRData != "" && record.CanonicalRData != "" &&
		len(record.DisplayRData) <= dnsobs.MaxRDataBytes && len(record.CanonicalRData) <= dnsobs.MaxRDataBytes
}

func convertAliasChain(source AliasChain, alreadyDropped bool) (dnsobs.AliasChain, bool) {
	dropped := alreadyDropped || len(source.Hops) > dnsobs.MaxAliasChainDepth
	limit := min(len(source.Hops), dnsobs.MaxAliasChainDepth)
	result := dnsobs.AliasChain{Loop: source.Loop, CrossZoneKnown: source.CrossZoneKnown, CrossZone: source.CrossZone, Truncated: source.Truncated || len(source.Hops) > limit}
	for _, hop := range source.Hops[:limit] {
		rrType := dnsobs.RRType(strings.ToUpper(strings.TrimSpace(hop.Type)))
		from, fromErr := dnsobs.NormalizeWireName(hop.From)
		to, toErr := dnsobs.NormalizeWireName(hop.To)
		if (rrType != dnsobs.RRTypeCNAME && rrType != dnsobs.RRTypeDNAME) || fromErr != nil || toErr != nil {
			return dnsobs.AliasChain{}, true
		}
		result.Hops = append(result.Hops, dnsobs.AliasHop{Type: rrType, From: from, To: to})
	}
	if source.TerminalName != "" {
		terminal, err := dnsobs.NormalizeWireName(source.TerminalName)
		if err != nil {
			return dnsobs.AliasChain{}, true
		}
		result.TerminalName = terminal
	}
	return result, dropped
}

func observationError(err error, transport dnsobs.TransportStatus, malformed bool, alreadyDropped bool) (*dnsobs.ObservationError, bool) {
	code := "NETWORK_ERROR"
	retryable := true
	switch {
	case malformed || errors.Is(err, ErrMalformedResponse) || errors.Is(err, ErrResponseMismatch):
		code, retryable = "MALFORMED_DNS", false
	case errors.Is(err, context.Canceled):
		code, retryable = "CANCELLED", false
	case errors.Is(err, context.DeadlineExceeded):
		code = "TIMEOUT"
	case errors.Is(err, syscall.ECONNREFUSED) || transport == dnsobs.TransportRefused:
		code = "CONNECTION_REFUSED"
	case errors.Is(err, ErrResponseTooLarge):
		code, retryable = "RESPONSE_TOO_LARGE", false
	}
	message, clipped := boundedUTF8(err.Error(), dnsobs.MaxErrorMessageBytes)
	if message == "" {
		message = strings.ToLower(strings.ReplaceAll(code, "_", " "))
	}
	return &dnsobs.ObservationError{Code: code, Message: message, Retryable: retryable}, alreadyDropped || clipped
}

func boundedUTF8(value string, limit int) (string, bool) {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "\uFFFD"))
	if len(value) <= limit {
		return value, false
	}
	end := limit
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return strings.TrimSpace(value[:end]), true
}

func fitObservation(observation dnsobs.Observation) (dnsobs.Observation, bool, error) {
	return FitObservationToBytes(observation, dnsobs.MaxObservationBytes)
}

// FitObservationToBytes deterministically removes optional evidence and whole
// RRsets until the normalized observation fits the requested encoded size.
func FitObservationToBytes(observation dnsobs.Observation, limit int) (dnsobs.Observation, bool, error) {
	if limit < 1 || limit > dnsobs.MaxObservationBytes {
		return dnsobs.Observation{}, false, fmt.Errorf("DNS observation byte limit must be from 1 to %d", dnsobs.MaxObservationBytes)
	}
	normalized, tooLarge, err := normalizeObservationWithinLimit(observation, limit)
	if err != nil {
		return dnsobs.Observation{}, false, err
	}
	if !tooLarge {
		return normalized, false, nil
	}
	if normalized.Schema != "" {
		// A custom byte limit can reject an otherwise valid observation. Continue
		// cropping from its canonical form so one semantic RRset stays atomic.
		observation = normalized
	}

	dropped := true
	observation.ResultTruncated = true
	observation.Comparison = dnsobs.ComparisonUnknown
	observation.DNSSEC = dnsobs.DNSSECResult{Status: dnsobs.DNSSECIndeterminate}
	dropOptional := []func() bool{
		func() bool {
			if len(observation.EDNS.Options) == 0 {
				return false
			}
			observation.EDNS.Options = nil
			return true
		},
		func() bool {
			if observation.EDNS.NSIDHex == "" {
				return false
			}
			observation.EDNS.NSIDHex = ""
			return true
		},
		func() bool {
			if len(observation.EDNS.EDE) == 0 {
				return false
			}
			observation.EDNS.EDE = nil
			return true
		},
		func() bool {
			if observation.EDNS.ECS == nil {
				return false
			}
			observation.EDNS.ECS = nil
			return true
		},
		func() bool {
			alias := observation.AliasChain
			if len(alias.Hops) == 0 && !alias.Loop && !alias.CrossZoneKnown && !alias.CrossZone && !alias.Truncated && alias.TerminalName == "" {
				return false
			}
			observation.AliasChain = dnsobs.AliasChain{}
			return true
		},
	}
	for _, drop := range dropOptional {
		if !drop() {
			continue
		}
		normalized, tooLarge, err = normalizeObservationWithinLimit(observation, limit)
		if err != nil {
			return dnsobs.Observation{}, dropped, err
		}
		if !tooLarge {
			return normalized, dropped, nil
		}
	}

	sections := []*[]dnsobs.ResourceRecord{
		&observation.Sections.Additional,
		&observation.Sections.Authority,
		&observation.Sections.Answer,
	}
	for _, section := range sections {
		original := *section
		*section = nil
		zero, zeroTooLarge, zeroErr := normalizeObservationWithinLimit(observation, limit)
		if zeroErr != nil {
			return dnsobs.Observation{}, dropped, zeroErr
		}
		if zeroTooLarge {
			continue
		}

		groupKeys, keyErr := orderedRRSetKeys(original)
		if keyErr != nil {
			return dnsobs.Observation{}, dropped, keyErr
		}
		best := 0
		bestObservation := zero
		for low, high := 1, len(groupKeys); low <= high; {
			middle := low + (high-low)/2
			retained, retainErr := retainRRSetPrefix(original, groupKeys, middle)
			if retainErr != nil {
				return dnsobs.Observation{}, dropped, retainErr
			}
			*section = retained
			candidate, candidateTooLarge, candidateErr := normalizeObservationWithinLimit(observation, limit)
			if candidateErr != nil {
				return dnsobs.Observation{}, dropped, candidateErr
			}
			if !candidateTooLarge {
				best = middle
				bestObservation = candidate
				low = middle + 1
				continue
			}
			high = middle - 1
		}
		retained, retainErr := retainRRSetPrefix(original, groupKeys, best)
		if retainErr != nil {
			return dnsobs.Observation{}, dropped, retainErr
		}
		*section = retained
		return bestObservation, dropped, nil
	}
	return dnsobs.Observation{}, dropped, fmt.Errorf("bounded DNS observation still exceeds %d bytes after evidence removal", limit)
}

func normalizeObservationWithinLimit(observation dnsobs.Observation, limit int) (dnsobs.Observation, bool, error) {
	normalized, err := dnsobs.NormalizeObservation(observation)
	if err != nil {
		if observationTooLarge(err) {
			return dnsobs.Observation{}, true, nil
		}
		return dnsobs.Observation{}, false, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return dnsobs.Observation{}, false, fmt.Errorf("encode bounded DNS observation: %w", err)
	}
	return normalized, len(raw) > limit, nil
}

type observationRRSetKey struct {
	owner  string
	rrType dnsobs.RRType
	class  dnsobs.DNSClass
}

func orderedRRSetKeys(records []dnsobs.ResourceRecord) ([]observationRRSetKey, error) {
	keys := make([]observationRRSetKey, 0, len(records))
	seen := make(map[observationRRSetKey]struct{}, len(records))
	for _, record := range records {
		key, err := observationRRSetKeyForRecord(record)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys, nil
}

func retainRRSetPrefix(records []dnsobs.ResourceRecord, orderedKeys []observationRRSetKey, count int) ([]dnsobs.ResourceRecord, error) {
	if count <= 0 {
		return nil, nil
	}
	keep := make(map[observationRRSetKey]struct{}, count)
	for _, key := range orderedKeys[:min(count, len(orderedKeys))] {
		keep[key] = struct{}{}
	}
	result := make([]dnsobs.ResourceRecord, 0, len(records))
	for _, record := range records {
		key, err := observationRRSetKeyForRecord(record)
		if err != nil {
			return nil, err
		}
		if _, ok := keep[key]; ok {
			result = append(result, record)
		}
	}
	return result, nil
}

func observationRRSetKeyForRecord(record dnsobs.ResourceRecord) (observationRRSetKey, error) {
	return normalizeObservationRRSetKey(record.Owner, record.Type, record.Class)
}

func normalizeObservationRRSetKey(owner string, rrType dnsobs.RRType, class dnsobs.DNSClass) (observationRRSetKey, error) {
	normalizedOwner, err := dnsobs.NormalizeWireName(owner)
	if err != nil {
		return observationRRSetKey{}, fmt.Errorf("normalize observation RRset owner: %w", err)
	}
	normalizedType, err := dnsobs.ParseResponseRRType(string(rrType))
	if err != nil {
		return observationRRSetKey{}, fmt.Errorf("normalize observation RRset type: %w", err)
	}
	normalizedClass := dnsobs.DNSClass(strings.ToUpper(strings.TrimSpace(string(class))))
	if normalizedClass != dnsobs.DNSClassIN {
		return observationRRSetKey{}, fmt.Errorf("normalize observation RRset class: only IN class is supported")
	}
	return observationRRSetKey{owner: normalizedOwner, rrType: normalizedType, class: normalizedClass}, nil
}

func observationTooLarge(err error) bool {
	var validationError *dnsobs.ValidationError
	return errors.As(err, &validationError) && validationError.Code == "OBSERVATION_TOO_LARGE"
}
