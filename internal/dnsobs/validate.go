package dnsobs

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
var errorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func ValidateSchema(schema string) error {
	if schema != SchemaV1 {
		return invalid("schema", "UNSUPPORTED_SCHEMA", fmt.Sprintf("schema must be %q", SchemaV1))
	}
	return nil
}

func ParseRRType(value string) (RRType, error) {
	normalized := RRType(strings.ToUpper(strings.TrimSpace(value)))
	if !normalized.SupportedQuery() {
		return "", fmt.Errorf("unsupported DNS query type %q", value)
	}
	return normalized, nil
}

func ParseResponseRRType(value string) (RRType, error) {
	normalized := RRType(strings.ToUpper(strings.TrimSpace(value)))
	if normalized.SupportedQuery() {
		return normalized, nil
	}
	switch normalized {
	case RRTypeDNAME, RRTypeRRSIG, RRTypeNSEC, RRTypeNSEC3, RRTypeNSEC3PARAM:
		return normalized, nil
	case RRTypeOPT:
		return "", fmt.Errorf("OPT must be represented by the EDNS field, not a resource record")
	case "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY":
		return "", fmt.Errorf("meta or transfer type %q is not allowed", normalized)
	}
	text := string(normalized)
	if !strings.HasPrefix(text, "TYPE") {
		return "", fmt.Errorf("unsupported DNS response type %q", value)
	}
	code, err := strconv.Atoi(strings.TrimPrefix(text, "TYPE"))
	if err != nil || code < 1 || code > 65535 || code >= 249 && code <= 255 {
		return "", fmt.Errorf("invalid RFC 3597 DNS response type %q", value)
	}
	if known, ok := responseRRTypeByCode[code]; ok {
		if known == RRTypeOPT {
			return "", fmt.Errorf("OPT must be represented by the EDNS field, not a resource record")
		}
		return known, nil
	}
	return RRType(fmt.Sprintf("TYPE%d", code)), nil
}

var responseRRTypeByCode = map[int]RRType{
	1: RRTypeA, 2: RRTypeNS, 5: RRTypeCNAME, 6: RRTypeSOA, 12: RRTypePTR,
	15: RRTypeMX, 16: RRTypeTXT, 28: RRTypeAAAA, 33: RRTypeSRV,
	39: RRTypeDNAME, 41: RRTypeOPT, 43: RRTypeDS, 46: RRTypeRRSIG,
	47: RRTypeNSEC, 48: RRTypeDNSKEY, 50: RRTypeNSEC3, 51: RRTypeNSEC3PARAM,
	52: RRTypeTLSA, 64: RRTypeSVCB, 65: RRTypeHTTPS, 257: RRTypeCAA,
}

func NormalizeQuestion(question Question) (Question, error) {
	rrType, err := ParseRRType(string(question.Type))
	if err != nil {
		return Question{}, invalid("question.type", "UNSUPPORTED_RR_TYPE", err.Error())
	}
	class := DNSClass(strings.ToUpper(strings.TrimSpace(string(question.Class))))
	if class == "" {
		class = DNSClassIN
	}
	if !class.Valid() {
		return Question{}, invalid("question.class", "UNSUPPORTED_DNS_CLASS", "only IN class is supported")
	}
	name, err := NormalizeQuestionName(question.Name, rrType)
	if err != nil {
		return Question{}, invalid("question.name", "INVALID_QNAME", err.Error())
	}
	return Question{Name: name, Type: rrType, Class: class}, nil
}

func NormalizeEndpoint(endpoint Endpoint) (Endpoint, error) {
	result := endpoint
	result.Kind = EndpointKind(strings.ToLower(strings.TrimSpace(string(endpoint.Kind))))
	if result.Kind == "resolver" {
		result.Kind = EndpointCatalog
	}
	if !result.Kind.Valid() {
		return Endpoint{}, invalid("endpoint.kind", "UNSUPPORTED_ENDPOINT_KIND", "endpoint kind is unsupported")
	}
	result.Protocol = Protocol(strings.ToLower(strings.TrimSpace(string(endpoint.Protocol))))
	if !result.Protocol.Valid() {
		return Endpoint{}, invalid("endpoint.protocol", "UNSUPPORTED_DNS_PROTOCOL", "endpoint protocol is unsupported")
	}
	if result.Port == 0 {
		result.Port = result.Protocol.DefaultPort()
	}
	if result.Port < 1 || result.Port > 65535 {
		return Endpoint{}, invalid("endpoint.port", "INVALID_ENDPOINT_PORT", "endpoint port must be from 1 to 65535")
	}
	if result.Kind == EndpointSystem && result.Port != 53 {
		return Endpoint{}, invalid("endpoint.port", "INVALID_SYSTEM_DNS_PORT", "system DNS endpoint port must be 53; the native resolver snapshot supplies the actual dial port")
	}

	result.ConnectIP = strings.TrimSpace(endpoint.ConnectIP)
	result.ServerName = strings.TrimSpace(endpoint.ServerName)
	result.HTTPAuthority = strings.TrimSpace(endpoint.HTTPAuthority)
	result.HTTPPath = endpoint.HTTPPath
	if result.Kind == EndpointSystem || result.Kind == EndpointRootHints {
		if result.ConnectIP != "" || result.ServerName != "" || result.HTTPAuthority != "" {
			return Endpoint{}, invalid("endpoint", "INVALID_ENDPOINT_IDENTITY", "system and root-hints endpoints discover their own peer identity")
		}
		if result.Protocol != ProtocolUDP && result.Protocol != ProtocolTCP {
			return Endpoint{}, invalid("endpoint.protocol", "UNSUPPORTED_DNS_PROTOCOL", "system and root-hints endpoints require UDP or TCP")
		}
	} else {
		addr, err := netip.ParseAddr(result.ConnectIP)
		if err != nil || !addr.IsValid() || addr.Zone() != "" {
			return Endpoint{}, invalid("endpoint.connect_ip", "INVALID_CONNECT_IP", "connect_ip must be a bare IPv4 or IPv6 address")
		}
		if !IsPublicDNSAddress(addr) {
			return Endpoint{}, invalid("endpoint.connect_ip", "NON_PUBLIC_CONNECT_IP", "connect_ip must be a public unicast address")
		}
		result.ConnectIP = addr.Unmap().String()
		if result.ServerName != "" {
			if _, err := netip.ParseAddr(strings.TrimSuffix(result.ServerName, ".")); err == nil {
				return Endpoint{}, invalid("endpoint.server_name", "INVALID_SERVER_NAME", "server_name must be a DNS host name, not an IP address")
			}
			serverName, err := NormalizeFQDN(result.ServerName)
			if err != nil || serverName == "." {
				return Endpoint{}, invalid("endpoint.server_name", "INVALID_SERVER_NAME", "server_name must be a valid DNS host name")
			}
			result.ServerName = strings.TrimSuffix(serverName, ".")
		}
		if (result.Protocol == ProtocolDoT || result.Protocol == ProtocolDoH || result.Protocol == ProtocolDoQ) && result.ServerName == "" {
			return Endpoint{}, invalid("endpoint.server_name", "SERVER_NAME_REQUIRED", "encrypted DNS protocols require a separate TLS server name")
		}
	}

	if result.Protocol == ProtocolDoH {
		if result.HTTPAuthority == "" {
			result.HTTPAuthority = result.ServerName
		} else {
			if strings.ContainsAny(result.HTTPAuthority, ":/[]@?#") {
				return Endpoint{}, invalid("endpoint.http_authority", "INVALID_HTTP_AUTHORITY", "http_authority must be a DNS host name without a scheme or port")
			}
			if _, err := netip.ParseAddr(strings.TrimSuffix(result.HTTPAuthority, ".")); err == nil {
				return Endpoint{}, invalid("endpoint.http_authority", "INVALID_HTTP_AUTHORITY", "http_authority must be a DNS host name, not an IP address")
			}
			authority, err := NormalizeFQDN(result.HTTPAuthority)
			if err != nil || authority == "." {
				return Endpoint{}, invalid("endpoint.http_authority", "INVALID_HTTP_AUTHORITY", "http_authority must be a valid IDNA DNS host name")
			}
			result.HTTPAuthority = strings.TrimSuffix(authority, ".")
		}
		if result.HTTPPath == "" {
			result.HTTPPath = "/dns-query"
		}
		httpPath, err := NormalizeDoHPath(result.HTTPPath)
		if err != nil {
			return Endpoint{}, invalid("endpoint.http_path", "INVALID_DOH_PATH", err.Error())
		}
		result.HTTPPath = httpPath
	} else {
		if result.HTTPAuthority != "" {
			return Endpoint{}, invalid("endpoint.http_authority", "UNEXPECTED_HTTP_AUTHORITY", "http_authority is only valid for DoH")
		}
		if result.HTTPPath != "" {
			return Endpoint{}, invalid("endpoint.http_path", "UNEXPECTED_HTTP_PATH", "http_path is only valid for DoH")
		}
	}
	return result, nil
}

// NormalizeDoHPath validates and canonicalizes a URI path without accepting
// any scheme, authority, query, fragment, whitespace, control, or backslash.
func NormalizeDoHPath(value string) (string, error) {
	if len(value) == 0 || len(value) > 1024 {
		return "", fmt.Errorf("DoH path must contain from 1 to 1024 bytes")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("DoH path is not a valid escaped URI path")
	}
	if parsed.IsAbs() || parsed.Scheme != "" || parsed.Opaque != "" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("DoH path must not contain a scheme, authority, query, or fragment")
	}
	if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "", fmt.Errorf("DoH path must be a single absolute path")
	}
	if !utf8.ValidString(parsed.Path) {
		return "", fmt.Errorf("DoH path must decode to valid UTF-8")
	}
	for _, r := range parsed.Path {
		if r == '\\' || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("DoH path must not contain control characters, spaces, or backslashes")
		}
	}
	normalized := parsed.EscapedPath()
	if len(normalized) == 0 || len(normalized) > 1024 {
		return "", fmt.Errorf("escaped DoH path must contain from 1 to 1024 bytes")
	}
	return normalized, nil
}

func NormalizeLimits(limits Limits) (Limits, error) {
	result := limits
	if result.Parallel == 0 {
		result.Parallel = DefaultParallel
	}
	if result.AttemptTimeoutMS == 0 {
		result.AttemptTimeoutMS = DefaultAttemptTimeoutMS
	}
	if result.MaxAttempts == 0 {
		result.MaxAttempts = DefaultMaxAttempts
	}
	if result.Parallel < 1 || result.Parallel > MaxParallel {
		return Limits{}, invalid("limits.parallel", "INVALID_PARALLEL_LIMIT", fmt.Sprintf("parallel must be from 1 to %d", MaxParallel))
	}
	if result.AttemptTimeoutMS < MinAttemptTimeoutMS || result.AttemptTimeoutMS > MaxAttemptTimeoutMS {
		return Limits{}, invalid("limits.attempt_timeout_ms", "INVALID_ATTEMPT_TIMEOUT", fmt.Sprintf("attempt timeout must be from %d to %d milliseconds", MinAttemptTimeoutMS, MaxAttemptTimeoutMS))
	}
	if result.MaxAttempts < 1 || result.MaxAttempts > MaxAttempts {
		return Limits{}, invalid("limits.max_attempts", "INVALID_ATTEMPT_LIMIT", fmt.Sprintf("max attempts must be from 1 to %d", MaxAttempts))
	}
	return result, nil
}

func NormalizeRequest(request Request) (Request, error) {
	if err := ValidateSchema(request.Schema); err != nil {
		return Request{}, err
	}
	roundID, err := normalizeIdentifier("round_id", request.RoundID)
	if err != nil {
		return Request{}, err
	}
	if len(request.Operations) == 0 || len(request.Operations) > MaxOperations {
		return Request{}, invalid("operations", "INVALID_OPERATION_COUNT", fmt.Sprintf("operations must contain from 1 to %d items", MaxOperations))
	}
	limits, err := NormalizeLimits(request.Limits)
	if err != nil {
		return Request{}, err
	}
	result := Request{Schema: SchemaV1, RoundID: roundID, Limits: limits, Operations: make([]Operation, len(request.Operations))}
	seen := make(map[string]struct{}, len(request.Operations))
	for i, operation := range request.Operations {
		operationID, err := normalizeIdentifier(fmt.Sprintf("operations[%d].operation_id", i), operation.OperationID)
		if err != nil {
			return Request{}, err
		}
		if _, duplicate := seen[operationID]; duplicate {
			return Request{}, invalid(fmt.Sprintf("operations[%d].operation_id", i), "DUPLICATE_OPERATION_ID", "operation_id must be unique within a round")
		}
		seen[operationID] = struct{}{}
		mode := Mode(strings.ToLower(strings.TrimSpace(string(operation.Mode))))
		if !mode.Valid() {
			return Request{}, invalid(fmt.Sprintf("operations[%d].mode", i), "UNSUPPORTED_DNS_MODE", "DNS operation mode is unsupported")
		}
		question, err := NormalizeQuestion(operation.Question)
		if err != nil {
			return Request{}, err
		}
		endpoint, err := NormalizeEndpoint(operation.Endpoint)
		if err != nil {
			return Request{}, err
		}
		if err := validateModeEndpoint(mode, endpoint.Kind); err != nil {
			return Request{}, invalid(fmt.Sprintf("operations[%d].endpoint.kind", i), "ENDPOINT_MODE_MISMATCH", err.Error())
		}
		if endpoint.Protocol == ProtocolUDP && limits.MaxAttempts < 2 {
			return Request{}, invalid(fmt.Sprintf("operations[%d].endpoint.protocol", i), "UDP_FALLBACK_ATTEMPT_REQUIRED", "UDP operations require at least two physical attempts so TC fallback can always run")
		}
		flags := operation.Flags
		if flags.EDNSUDPSize == 0 {
			flags.EDNSUDPSize = DefaultEDNSUDPSize
		}
		if flags.EDNSUDPSize < 512 || flags.EDNSUDPSize > 4096 {
			return Request{}, invalid(fmt.Sprintf("operations[%d].flags.edns_udp_size", i), "INVALID_EDNS_UDP_SIZE", "EDNS UDP size must be from 512 to 4096")
		}
		if mode != ModeRecursive && flags.RecursionDesired {
			return Request{}, invalid(fmt.Sprintf("operations[%d].flags.rd", i), "INVALID_RECURSION_FLAG", "iterative and authoritative operations must not set RD")
		}
		result.Operations[i] = Operation{OperationID: operationID, Mode: mode, Question: question, Endpoint: endpoint, Flags: flags}
	}
	return result, nil
}

func (r Request) Validate() error {
	_, err := NormalizeRequest(r)
	return err
}

func NormalizeBatchResultForRequest(request Request, batch BatchResult) (BatchResult, error) {
	normalizedRequest, err := NormalizeRequest(request)
	if err != nil {
		return BatchResult{}, err
	}
	if err := ValidateSchema(batch.Schema); err != nil {
		return BatchResult{}, err
	}
	roundID, err := normalizeIdentifier("round_id", batch.RoundID)
	if err != nil {
		return BatchResult{}, err
	}
	if roundID != normalizedRequest.RoundID {
		return BatchResult{}, invalid("round_id", "ROUND_ID_MISMATCH", "batch result round_id must match the request")
	}
	if len(batch.Observations) > MaxOperations {
		return BatchResult{}, invalid("observations", "OBSERVATION_COUNT_LIMIT", fmt.Sprintf("batch result is limited to %d observations", MaxOperations))
	}

	operationIndexes := make(map[string]int, len(normalizedRequest.Operations))
	for i := range normalizedRequest.Operations {
		operationIndexes[normalizedRequest.Operations[i].OperationID] = i
	}
	result := BatchResult{
		Schema:       SchemaV1,
		RoundID:      roundID,
		Observations: make([]Observation, len(normalizedRequest.Operations)),
	}
	seen := make([]bool, len(normalizedRequest.Operations))
	for sourceIndex := range batch.Observations {
		observation, err := NormalizeObservation(batch.Observations[sourceIndex])
		if err != nil {
			return BatchResult{}, prefixValidationError(fmt.Sprintf("observations[%d]", sourceIndex), err)
		}
		if observation.RoundID != roundID {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].round_id", sourceIndex), "OBSERVATION_ROUND_MISMATCH", "observation round_id must match the batch result")
		}
		requestIndex, ok := operationIndexes[observation.OperationID]
		if !ok {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].operation_id", sourceIndex), "UNKNOWN_OPERATION_ID", "observation does not belong to a request operation")
		}
		if seen[requestIndex] {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].operation_id", sourceIndex), "DUPLICATE_OBSERVATION", "request operation has more than one observation")
		}
		operation := normalizedRequest.Operations[requestIndex]
		if observation.Question != operation.Question {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].question", sourceIndex), "QUESTION_MISMATCH", "observation question must match its request operation")
		}
		if observation.Endpoint != operation.Endpoint {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].endpoint", sourceIndex), "ENDPOINT_MISMATCH", "observation endpoint must match its request operation")
		}
		if observation.AttemptCount > normalizedRequest.Limits.MaxAttempts {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].attempt_count", sourceIndex), "ATTEMPT_LIMIT_EXCEEDED", "observation attempt_count exceeds the request max_attempts limit")
		}
		if needed := RetryGapAdditionalAttempts(observation); observation.AttemptCount+needed > normalizedRequest.Limits.MaxAttempts {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].attempts", sourceIndex), "RETRY_GAP_BUDGET_EXCEEDED", "retry-gap termination requires enough frozen attempt budget for the pending physical retry")
		}
		if observation.Outcome == DNSOutcomeReferral && operation.Mode != ModeIterative {
			return BatchResult{}, invalid(fmt.Sprintf("observations[%d].dns_outcome", sourceIndex), "REFERRAL_MODE_MISMATCH", "referral is only valid for an iterative parent-zone operation")
		}
		seen[requestIndex] = true
		result.Observations[requestIndex] = observation
	}
	for requestIndex, observed := range seen {
		if !observed {
			return BatchResult{}, invalid("observations", "MISSING_OBSERVATION", fmt.Sprintf("request operation %q has no observation", normalizedRequest.Operations[requestIndex].OperationID))
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return BatchResult{}, fmt.Errorf("encode DNS batch result: %w", err)
	}
	if len(raw) > MaxTaskResultBytes {
		return BatchResult{}, invalid("batch_result", "TASK_RESULT_TOO_LARGE", fmt.Sprintf("encoded batch result exceeds %d bytes", MaxTaskResultBytes))
	}
	return result, nil
}

func prefixValidationError(prefix string, err error) error {
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	field := prefix
	if validationErr.Field != "" {
		field += "." + validationErr.Field
	}
	return invalid(field, validationErr.Code, validationErr.Message)
}

func NormalizeObservation(observation Observation) (Observation, error) {
	if err := ValidateSchema(observation.Schema); err != nil {
		return Observation{}, err
	}
	roundID, err := normalizeIdentifier("round_id", observation.RoundID)
	if err != nil {
		return Observation{}, err
	}
	operationID, err := normalizeIdentifier("operation_id", observation.OperationID)
	if err != nil {
		return Observation{}, err
	}
	question, err := NormalizeQuestion(observation.Question)
	if err != nil {
		return Observation{}, err
	}
	endpoint, err := NormalizeEndpoint(observation.Endpoint)
	if err != nil {
		return Observation{}, err
	}
	result := cloneObservation(observation)
	result.Schema = SchemaV1
	result.RoundID = roundID
	result.OperationID = operationID
	result.Question = question
	result.Endpoint = endpoint
	result.TransportStatus = TransportStatus(strings.ToLower(strings.TrimSpace(string(observation.TransportStatus))))
	if !result.TransportStatus.Valid() {
		return Observation{}, invalid("transport_status", "INVALID_TRANSPORT_STATUS", "transport status is unsupported")
	}
	result.Protocol = Protocol(strings.ToLower(strings.TrimSpace(string(observation.Protocol))))
	if !result.Protocol.Valid() {
		return Observation{}, invalid("protocol", "UNSUPPORTED_DNS_PROTOCOL", "observation protocol is unsupported")
	}
	if result.StartedAt.IsZero() {
		return Observation{}, invalid("started_at", "MISSING_STARTED_AT", "started_at is required")
	}
	if result.ObservedAt.IsZero() {
		return Observation{}, invalid("observed_at", "MISSING_OBSERVED_AT", "observed_at is required")
	}
	if result.FinishedAt.IsZero() {
		return Observation{}, invalid("finished_at", "MISSING_FINISHED_AT", "finished_at is required")
	}
	result.StartedAt = result.StartedAt.UTC()
	result.ObservedAt = result.ObservedAt.UTC()
	result.FinishedAt = result.FinishedAt.UTC()
	if result.DurationMS < 0 {
		return Observation{}, invalid("duration_ms", "INVALID_DURATION", "duration must not be negative")
	}
	if result.ObservedAt.Before(result.StartedAt) || result.ObservedAt.After(result.FinishedAt) {
		return Observation{}, invalid("observed_at", "OBSERVATION_TIME_OUTSIDE_OPERATION", "observed_at must fall within the operation interval")
	}
	if result.FinishedAt.Before(result.StartedAt) {
		return Observation{}, invalid("finished_at", "INVALID_OPERATION_INTERVAL", "finished_at must not precede started_at")
	}
	if elapsed := result.FinishedAt.Sub(result.StartedAt).Milliseconds(); result.DurationMS != elapsed {
		return Observation{}, invalid("duration_ms", "DURATION_INTERVAL_MISMATCH", "duration_ms must equal the millisecond-truncated operation interval")
	}
	if err := normalizeWireAttempts(&result); err != nil {
		return Observation{}, err
	}
	if result.ResponseSizeBytes < 0 || result.ResponseSizeBytes > MaxObservationBytes {
		return Observation{}, invalid("response_size_bytes", "INVALID_RESPONSE_SIZE", fmt.Sprintf("response size must be from 0 to %d bytes", MaxObservationBytes))
	}
	if result.Comparison == "" {
		result.Comparison = ComparisonUnknown
	}
	result.Comparison = Comparison(strings.ToLower(strings.TrimSpace(string(result.Comparison))))
	if !result.Comparison.Valid() {
		return Observation{}, invalid("comparison", "INVALID_COMPARISON", "comparison status is unsupported")
	}
	if err := normalizeObservationResponse(&result); err != nil {
		return Observation{}, err
	}
	if err := normalizeEDNS(&result.EDNS); err != nil {
		return Observation{}, err
	}
	if result.ExtendedRCode != nil && !result.EDNS.Present {
		return Observation{}, invalid("extended_rcode", "EXTENDED_RCODE_WITHOUT_EDNS", "extended rcode requires an EDNS OPT response")
	}
	if result.DNSSEC.Status == "" {
		result.DNSSEC.Status = DNSSECIndeterminate
	}
	result.DNSSEC.Status = DNSSECStatus(strings.ToLower(strings.TrimSpace(string(result.DNSSEC.Status))))
	if !result.DNSSEC.Status.Valid() {
		return Observation{}, invalid("dnssec.status", "INVALID_DNSSEC_STATUS", "DNSSEC status is unsupported")
	}
	if result.DNSSEC.Status == DNSSECIndeterminate && result.DNSSEC.LocallyValidated {
		return Observation{}, invalid("dnssec.locally_validated", "INDETERMINATE_LOCALLY_VALIDATED", "indeterminate status cannot claim completed local validation")
	}
	if result.DNSSEC.Status != DNSSECIndeterminate && !result.DNSSEC.LocallyValidated {
		return Observation{}, invalid("dnssec.locally_validated", "UNVERIFIED_DNSSEC_STATUS", "secure, insecure, and bogus statuses require local chain validation")
	}
	if err := normalizeCode("dnssec.reason_code", &result.DNSSEC.ReasonCode, false); err != nil {
		return Observation{}, err
	}
	if result.DNSSEC.Status == DNSSECBogus && result.DNSSEC.ReasonCode == "" {
		return Observation{}, invalid("dnssec.reason_code", "BOGUS_REASON_REQUIRED", "bogus status requires a local validation reason code")
	}
	if observationIncomplete(result) && (result.DNSSEC.Status != DNSSECIndeterminate || result.DNSSEC.LocallyValidated) {
		return Observation{}, invalid("dnssec", "TRUNCATED_DNSSEC_INDETERMINATE", "cropped and wire-truncated observations require indeterminate DNSSEC status")
	}
	switch result.DNSSEC.Status {
	case DNSSECSecure, DNSSECInsecure:
		if result.Outcome != DNSOutcomeAnswer && result.Outcome != DNSOutcomeNoData && result.Outcome != DNSOutcomeNXDomain {
			return Observation{}, invalid("dnssec", "DNSSEC_OUTCOME_MISMATCH", "secure and insecure statuses require an answer, NODATA, or NXDOMAIN outcome")
		}
	case DNSSECBogus:
		if result.Outcome != DNSOutcomeServFail {
			return Observation{}, invalid("dnssec", "DNSSEC_OUTCOME_MISMATCH", "bogus status requires the locally attributable SERVFAIL path")
		}
	}
	if result.Comparison != ComparisonUnknown && !observationComparable(result) {
		return Observation{}, invalid("comparison", "OBSERVATION_NOT_COMPARABLE", "only complete, locally secure or insecure answer, NODATA, and NXDOMAIN observations are comparable")
	}
	if result.ResponseTruncated != result.Flags.Truncated {
		return Observation{}, invalid("response_truncated", "INCONSISTENT_RESPONSE_TRUNCATION", "response_truncated must exactly match the retained DNS TC flag")
	}
	if err := normalizeSections(&result.Sections); err != nil {
		return Observation{}, err
	}
	if err := normalizeAliasChain(result.Question, result.Sections, &result.AliasChain, observationIncomplete(result)); err != nil {
		return Observation{}, err
	}
	if result.AliasChain.Truncated && !result.ResultTruncated {
		return Observation{}, invalid("alias_chain.truncated", "ALIAS_TRUNCATION_NOT_DECLARED", "a truncated alias chain requires result_truncated=true")
	}
	if result.NegativeTTL != nil && result.Outcome != DNSOutcomeNoData && result.Outcome != DNSOutcomeNXDomain {
		return Observation{}, invalid("negative_ttl", "UNEXPECTED_NEGATIVE_TTL", "negative TTL is only valid for NODATA or NXDOMAIN")
	}
	if err := normalizeObservationError(&result); err != nil {
		return Observation{}, err
	}
	if err := validateObservationAttemptContract(&result); err != nil {
		return Observation{}, err
	}
	if result.AttemptCount == 0 {
		if err := validateZeroAttemptObservation(&result); err != nil {
			return Observation{}, err
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return Observation{}, fmt.Errorf("encode DNS observation: %w", err)
	}
	if len(raw) > MaxObservationBytes {
		return Observation{}, invalid("observation", "OBSERVATION_TOO_LARGE", fmt.Sprintf("encoded observation exceeds %d bytes", MaxObservationBytes))
	}
	return result, nil
}

func observationComparable(result Observation) bool {
	if result.TransportStatus != TransportSuccess || observationIncomplete(result) {
		return false
	}
	switch result.Outcome {
	case DNSOutcomeAnswer, DNSOutcomeNoData, DNSOutcomeNXDomain:
	default:
		return false
	}
	return result.DNSSEC.LocallyValidated && (result.DNSSEC.Status == DNSSECSecure || result.DNSSEC.Status == DNSSECInsecure)
}

func observationIncomplete(result Observation) bool {
	return result.ResponseTruncated || result.ResultTruncated
}

func normalizeWireAttempts(result *Observation) error {
	if result.Attempts == nil {
		return invalid("attempts", "MISSING_ATTEMPT_TRANSCRIPT", "attempts must be an explicit JSON array")
	}
	if result.AttemptCount != len(result.Attempts) || len(result.Attempts) > MaxAttempts {
		return invalid("attempt_count", "INVALID_ATTEMPT_COUNT", fmt.Sprintf("attempt_count must equal the attempts array length and contain at most %d attempts", MaxAttempts))
	}
	if result.ResponseAttempt < 0 || result.ResponseAttempt > len(result.Attempts) {
		return invalid("response_attempt", "INVALID_RESPONSE_ATTEMPT", "response_attempt must be zero or a 1-based attempts index")
	}
	if len(result.Attempts) == 0 {
		return nil
	}

	var previousFinished time.Time
	for index := range result.Attempts {
		attempt := &result.Attempts[index]
		field := fmt.Sprintf("attempts[%d]", index)
		attempt.Protocol = Protocol(strings.ToLower(strings.TrimSpace(string(attempt.Protocol))))
		if !attempt.Protocol.Valid() {
			return invalid(field+".protocol", "UNSUPPORTED_DNS_PROTOCOL", "attempt protocol is unsupported")
		}
		attempt.TransportStatus = TransportStatus(strings.ToLower(strings.TrimSpace(string(attempt.TransportStatus))))
		if !attempt.TransportStatus.Valid() {
			return invalid(field+".transport_status", "INVALID_TRANSPORT_STATUS", "attempt transport status is unsupported")
		}
		if attempt.StartedAt.IsZero() || attempt.FinishedAt.IsZero() {
			return invalid(field, "MISSING_ATTEMPT_TIME", "attempt started_at and finished_at are required")
		}
		attempt.StartedAt = attempt.StartedAt.UTC()
		attempt.FinishedAt = attempt.FinishedAt.UTC()
		if attempt.FinishedAt.Before(attempt.StartedAt) || attempt.StartedAt.Before(result.StartedAt) || attempt.FinishedAt.After(result.FinishedAt) {
			return invalid(field, "ATTEMPT_TIME_OUTSIDE_OPERATION", "attempt interval must be contained by the operation interval")
		}
		if index != 0 && attempt.StartedAt.Before(previousFinished) {
			return invalid(field+".started_at", "OVERLAPPING_ATTEMPTS", "wire attempts must be ordered and non-overlapping")
		}
		previousFinished = attempt.FinishedAt
		if attempt.DurationMS < 0 || attempt.DurationMS != attempt.FinishedAt.Sub(attempt.StartedAt).Milliseconds() {
			return invalid(field+".duration_ms", "ATTEMPT_DURATION_MISMATCH", "attempt duration_ms must equal its millisecond-truncated interval")
		}
		if attempt.ResponseSizeBytes < 0 || attempt.ResponseSizeBytes > MaxObservationBytes {
			return invalid(field+".response_size_bytes", "INVALID_RESPONSE_SIZE", fmt.Sprintf("attempt response size must be from 0 to %d bytes", MaxObservationBytes))
		}
		attempt.PeerIP = strings.TrimSpace(attempt.PeerIP)
		if attempt.PeerIP != "" {
			addr, err := netip.ParseAddr(attempt.PeerIP)
			if err != nil || addr.Zone() != "" {
				return invalid(field+".peer_ip", "INVALID_PEER_IP", "attempt peer_ip must be a bare IPv4 or IPv6 address")
			}
			attempt.PeerIP = addr.Unmap().String()
			if result.Endpoint.Kind != EndpointSystem && result.Endpoint.Kind != EndpointRootHints && attempt.PeerIP != result.Endpoint.ConnectIP {
				return invalid(field+".peer_ip", "PEER_CONNECT_IP_MISMATCH", "attempt peer_ip must match the endpoint connect_ip")
			}
		}
		if err := normalizeAttemptError(field, attempt); err != nil {
			return err
		}
		if attempt.ResponseTruncated && (attempt.TransportStatus != TransportSuccess || attempt.ResponseSizeBytes < 12) {
			return invalid(field+".response_truncated", "UNTRUSTED_ATTEMPT_TRUNCATION", "TC evidence requires a successful response containing at least a DNS header")
		}
	}

	if result.UDPToTCPFallback {
		if result.Endpoint.Protocol != ProtocolUDP || result.Protocol != ProtocolTCP || len(result.Attempts) < 2 {
			return invalid("udp_to_tcp_fallback", "INVALID_UDP_TCP_FALLBACK", "fallback requires a UDP endpoint, final TCP protocol, and two or three attempts")
		}
	} else {
		if result.Protocol != result.Endpoint.Protocol {
			return invalid("protocol", "ENDPOINT_PROTOCOL_MISMATCH", "observation protocol must match the endpoint unless UDP to TCP fallback occurred")
		}
		if len(result.Attempts) > 2 {
			return invalid("attempt_count", "INVALID_RETRY_SEQUENCE", "an observation without fallback may contain at most one retry")
		}
	}
	if result.Protocol != result.Attempts[len(result.Attempts)-1].Protocol {
		return invalid("protocol", "FINAL_ATTEMPT_PROTOCOL_MISMATCH", "observation protocol must match the final physical attempt")
	}

	transitionedToTCP := false
	for index := 0; index+1 < len(result.Attempts); index++ {
		current, next := result.Attempts[index], result.Attempts[index+1]
		switch {
		case current.Protocol == next.Protocol:
			if current.TransportStatus == TransportSuccess || current.Error == nil || !current.Error.Retryable {
				return invalid(fmt.Sprintf("attempts[%d]", index), "INVALID_RETRY_TRIGGER", "a same-protocol retry requires a retryable failed attempt")
			}
		case current.Protocol == ProtocolUDP && next.Protocol == ProtocolTCP:
			if transitionedToTCP || current.TransportStatus != TransportSuccess || !current.ResponseTruncated {
				return invalid(fmt.Sprintf("attempts[%d]", index), "INVALID_FALLBACK_TRIGGER", "UDP to TCP fallback requires one successful trusted UDP TC response")
			}
			transitionedToTCP = true
		default:
			return invalid(fmt.Sprintf("attempts[%d].protocol", index+1), "INVALID_ATTEMPT_SEQUENCE", "attempt protocols do not form a supported physical sequence")
		}
	}
	if transitionedToTCP != result.UDPToTCPFallback {
		return invalid("udp_to_tcp_fallback", "FALLBACK_SEQUENCE_MISMATCH", "udp_to_tcp_fallback must exactly describe the attempt protocol transition")
	}
	last := result.Attempts[len(result.Attempts)-1]
	if !result.UDPToTCPFallback && last.Protocol == ProtocolUDP && last.TransportStatus == TransportSuccess && last.ResponseTruncated {
		return invalid(fmt.Sprintf("attempts[%d].response_truncated", len(result.Attempts)-1), "UDP_TC_WITHOUT_FALLBACK", "a successful UDP TC response must be followed by TCP fallback")
	}
	return nil
}

func normalizeAttemptError(field string, attempt *WireAttempt) error {
	if attempt.TransportStatus == TransportSuccess {
		if attempt.Error != nil {
			return invalid(field+".error", "SUCCESSFUL_ATTEMPT_WITH_ERROR", "successful attempts must not contain an attempt error")
		}
		if attempt.PeerIP == "" || attempt.ResponseSizeBytes == 0 {
			return invalid(field, "SUCCESSFUL_ATTEMPT_WITHOUT_RESPONSE", "successful attempts require response peer and size metadata")
		}
		return nil
	}
	if attempt.Error == nil {
		return invalid(field+".error", "MISSING_ATTEMPT_ERROR", "failed attempts require a structured attempt error")
	}
	if err := normalizeCode(field+".error.code", &attempt.Error.Code, true); err != nil {
		return err
	}
	valid := false
	switch attempt.TransportStatus {
	case TransportTimeout:
		valid = attempt.Error.Code == "TIMEOUT" && attempt.Error.Retryable
	case TransportRefused:
		valid = attempt.Error.Code == "CONNECTION_REFUSED" && attempt.Error.Retryable
	case TransportCancelled:
		valid = attempt.Error.Code == "CANCELLED" && !attempt.Error.Retryable
	case TransportNetworkError:
		valid = attempt.Error.Code == "NETWORK_ERROR" && attempt.Error.Retryable || attempt.Error.Code == "RESPONSE_TOO_LARGE" && !attempt.Error.Retryable
	}
	if !valid {
		return invalid(field+".error", "ATTEMPT_STATUS_ERROR_MISMATCH", "attempt status, error code, and retryability do not match")
	}
	if attempt.ResponseTruncated {
		return invalid(field+".response_truncated", "FAILED_ATTEMPT_WITH_TRUNCATION", "failed attempts cannot claim trusted TC evidence")
	}
	return nil
}

func validateZeroAttemptObservation(result *Observation) error {
	if result.Attempts == nil || len(result.Attempts) != 0 || result.ResponseAttempt != 0 {
		return invalid("attempts", "INVALID_ZERO_ATTEMPT_TRANSCRIPT", "zero attempts require an explicit empty attempts array and response_attempt=0")
	}
	if result.Protocol != result.Endpoint.Protocol || result.UDPToTCPFallback {
		return invalid("protocol", "INVALID_ZERO_ATTEMPT_PROTOCOL", "zero attempts require the endpoint protocol and no fallback")
	}
	if result.PeerIP != "" || result.ResponseSizeBytes != 0 || result.ResponseTruncated || result.ResultTruncated || hasParsedDNSResponseData(result) {
		return invalid("observation", "ZERO_ATTEMPT_WITH_EVIDENCE", "zero attempts cannot contain transport or DNS response evidence")
	}
	if !result.ObservedAt.Equal(result.FinishedAt) {
		return invalid("observed_at", "INVALID_ZERO_ATTEMPT_TIMELINE", "zero attempts require observed_at=finished_at")
	}
	if result.DNSSEC.Status != DNSSECIndeterminate || result.DNSSEC.LocallyValidated || result.Comparison != ComparisonUnknown || result.Outcome != DNSOutcomeNotObserved {
		return invalid("observation", "INVALID_ZERO_ATTEMPT_RESULT", "zero attempts require a not-observed, incomparable, indeterminate result")
	}
	if result.TransportStatus == TransportNetworkError {
		if result.Error == nil || result.Error.Code != "INTERNAL_ERROR" || result.Error.Retryable {
			return invalid("error", "INVALID_ZERO_ATTEMPT_INTERNAL_ERROR", "zero-attempt network_error requires a non-retryable INTERNAL_ERROR")
		}
		return nil
	}
	return validateUnstartedCancellation(result)
}

func validateUnstartedCancellation(result *Observation) error {
	if result.TransportStatus != TransportCancelled || result.Outcome != DNSOutcomeNotObserved {
		return invalid("attempt_count", "INVALID_UNSTARTED_CANCELLATION", "zero attempts require a cancelled, not-observed operation")
	}
	if result.DurationMS != 0 {
		return invalid("observation", "UNSTARTED_CANCELLATION_WITH_EVIDENCE", "an operation cancelled before its first attempt cannot contain transport or DNS response evidence")
	}
	if !result.StartedAt.Equal(result.ObservedAt) || !result.ObservedAt.Equal(result.FinishedAt) {
		return invalid("observation", "INVALID_UNSTARTED_CANCELLATION_TIMELINE", "an unstarted cancellation requires started_at, observed_at, and finished_at to be identical")
	}
	if result.DNSSEC.Status != DNSSECIndeterminate || result.DNSSEC.LocallyValidated {
		return invalid("dnssec", "UNSTARTED_DNSSEC_INDETERMINATE", "an operation cancelled before its first attempt requires indeterminate DNSSEC status")
	}
	if result.Error == nil || result.Error.Code != "CANCELLED" || result.Error.Retryable {
		return invalid("error", "INVALID_UNSTARTED_CANCELLATION_ERROR", "an operation cancelled before its first attempt requires a non-retryable CANCELLED error")
	}
	return nil
}

func (o Observation) Validate() error {
	_, err := NormalizeObservation(o)
	return err
}

func normalizeObservationResponse(result *Observation) error {
	result.PeerIP = strings.TrimSpace(result.PeerIP)
	if result.PeerIP != "" {
		addr, err := netip.ParseAddr(result.PeerIP)
		if err != nil || addr.Zone() != "" {
			return invalid("peer_ip", "INVALID_PEER_IP", "peer_ip must be a bare IPv4 or IPv6 address")
		}
		result.PeerIP = addr.Unmap().String()
		if result.Endpoint.Kind != EndpointSystem && result.Endpoint.Kind != EndpointRootHints && result.PeerIP != result.Endpoint.ConnectIP {
			return invalid("peer_ip", "PEER_CONNECT_IP_MISMATCH", "peer_ip must match the endpoint connect_ip")
		}
	}
	result.Outcome = DNSOutcome(strings.ToLower(strings.TrimSpace(string(result.Outcome))))
	retainedTruncatedUDP := isRetainedTruncatedUDP(result)
	if result.TransportStatus == TransportSuccess {
		if result.PeerIP == "" {
			return invalid("peer_ip", "MISSING_PEER_IP", "successful transport must include peer_ip")
		}
		if !result.Outcome.Valid() {
			return invalid("dns_outcome", "INVALID_DNS_OUTCOME", "successful transport must include a supported DNS outcome")
		}
		if result.Outcome == DNSOutcomeNotObserved {
			return invalid("dns_outcome", "UNEXPECTED_NOT_OBSERVED", "successful transport must include an observed DNS outcome")
		}
		if result.Outcome == DNSOutcomeMalformed {
			if hasParsedDNSResponseData(result) {
				return invalid("dns_outcome", "MALFORMED_WITH_PARSED_RESPONSE", "malformed is reserved for responses that could not be reliably parsed")
			}
		} else {
			if result.RCode == nil {
				return invalid("rcode", "MISSING_RCODE", "a parsed DNS response must include rcode")
			}
			if !result.Flags.Response {
				return invalid("flags.qr", "NOT_A_DNS_RESPONSE", "a parsed DNS response must set QR")
			}
		}
	} else {
		if !retainedTruncatedUDP {
			if result.Outcome != DNSOutcomeNotObserved {
				return invalid("dns_outcome", "DNS_NOT_OBSERVED_REQUIRED", "failed transport without validated DNS evidence must use not_observed")
			}
			if hasParsedDNSResponseData(result) {
				return invalid("dns_outcome", "UNEXPECTED_DNS_RESPONSE", "not_observed must not contain parsed DNS response data")
			}
		}
		if retainedTruncatedUDP && result.Comparison != ComparisonUnknown {
			return invalid("comparison", "FALLBACK_FAILURE_NOT_COMPARABLE", "failed TCP fallback evidence must use unknown comparison")
		}
	}
	if result.Outcome == DNSOutcomeTruncatedResponse {
		if !retainedTruncatedUDP {
			return invalid("dns_outcome", "INVALID_TRUNCATED_RESPONSE", "truncated_response requires validated UDP TC header evidence followed by TCP fallback")
		}
		if result.ResponseSizeBytes < 12 {
			return invalid("response_size_bytes", "INVALID_TRUNCATED_RESPONSE_SIZE", "truncated_response must include a DNS header")
		}
		if result.ExtendedRCode != nil || hasResponseBodyData(result) {
			return invalid("dns_outcome", "TRUNCATED_RESPONSE_WITH_BODY", "truncated_response may contain header flags and base rcode only")
		}
	}
	if result.RCode != nil && *result.RCode > 15 {
		return invalid("rcode", "INVALID_RCODE", "header rcode must be from 0 to 15")
	}
	if result.ExtendedRCode != nil && result.RCode == nil {
		return invalid("extended_rcode", "ORPHAN_EXTENDED_RCODE", "extended rcode requires a header rcode")
	}
	if result.RCode != nil {
		fullRCode, _ := result.FullRCode()
		switch result.Outcome {
		case DNSOutcomeNXDomain:
			if fullRCode != 3 {
				return invalid("dns_outcome", "RCODE_OUTCOME_MISMATCH", "NXDOMAIN outcome requires rcode 3")
			}
		case DNSOutcomeServFail:
			if fullRCode != 2 {
				return invalid("dns_outcome", "RCODE_OUTCOME_MISMATCH", "SERVFAIL outcome requires rcode 2")
			}
		case DNSOutcomeRefused:
			if fullRCode != 5 {
				return invalid("dns_outcome", "RCODE_OUTCOME_MISMATCH", "REFUSED outcome requires rcode 5")
			}
		case DNSOutcomeRCodeError:
			if fullRCode == 0 || fullRCode == 2 || fullRCode == 3 || fullRCode == 5 {
				return invalid("dns_outcome", "RCODE_OUTCOME_MISMATCH", "rcode_error requires a nonzero RCODE without a dedicated outcome")
			}
		case DNSOutcomeAnswer, DNSOutcomeNoData, DNSOutcomeReferral:
			if fullRCode != 0 {
				return invalid("dns_outcome", "RCODE_OUTCOME_MISMATCH", "answer, NODATA, and referral outcomes require NOERROR")
			}
		}
	}
	return nil
}

func isRetainedTruncatedUDP(result *Observation) bool {
	return result.UDPToTCPFallback &&
		result.Endpoint.Protocol == ProtocolUDP &&
		result.Protocol == ProtocolTCP &&
		result.AttemptCount >= 2 &&
		result.AttemptCount <= MaxAttempts &&
		result.ResponseTruncated &&
		result.Flags.Truncated &&
		result.Flags.Response &&
		result.RCode != nil &&
		result.Outcome.Valid() &&
		result.Outcome != DNSOutcomeMalformed &&
		result.Outcome != DNSOutcomeNotObserved
}

func hasResponseBodyData(result *Observation) bool {
	alias := result.AliasChain
	return result.EDNS.Present || result.EDNS.UDPSize != 0 || result.EDNS.Version != 0 || result.EDNS.Flags != 0 || result.EDNS.DNSSECOK || result.EDNS.ECS != nil || len(result.EDNS.EDE) != 0 || result.EDNS.NSIDHex != "" || len(result.EDNS.Options) != 0 ||
		result.Sections.RecordCount() != 0 ||
		len(alias.Hops) != 0 || alias.Loop || alias.CrossZoneKnown || alias.CrossZone || alias.Truncated || alias.TerminalName != "" ||
		result.NegativeTTL != nil
}

func hasParsedDNSResponseData(result *Observation) bool {
	flags := result.Flags
	alias := result.AliasChain
	return result.RCode != nil ||
		result.ExtendedRCode != nil ||
		flags.Response || flags.Authoritative || flags.Truncated || flags.RecursionDesired || flags.RecursionAvailable || flags.ReservedZ || flags.AuthenticData || flags.CheckingDisabled ||
		result.EDNS.Present || result.EDNS.UDPSize != 0 || result.EDNS.Version != 0 || result.EDNS.Flags != 0 || result.EDNS.DNSSECOK || result.EDNS.ECS != nil || len(result.EDNS.EDE) != 0 || result.EDNS.NSIDHex != "" || len(result.EDNS.Options) != 0 ||
		result.Sections.RecordCount() != 0 ||
		len(alias.Hops) != 0 || alias.Loop || alias.CrossZoneKnown || alias.CrossZone || alias.Truncated || alias.TerminalName != "" ||
		result.NegativeTTL != nil
}

func normalizeSections(sections *Sections) error {
	if len(sections.Answer) > MaxSectionRecordLimit || len(sections.Authority) > MaxSectionRecordLimit || len(sections.Additional) > MaxSectionRecordLimit {
		return invalid("sections", "SECTION_RECORD_LIMIT", fmt.Sprintf("each DNS section is limited to %d records", MaxSectionRecordLimit))
	}
	all := [][]ResourceRecord{sections.Answer, sections.Authority, sections.Additional}
	names := []string{"answer", "authority", "additional"}
	for sectionIndex := range all {
		for recordIndex := range all[sectionIndex] {
			record := &all[sectionIndex][recordIndex]
			if !utf8.ValidString(record.DisplayRData) || !utf8.ValidString(record.CanonicalRData) {
				return invalid(fmt.Sprintf("sections.%s[%d]", names[sectionIndex], recordIndex), "INVALID_RDATA_ENCODING", "RDATA must be valid UTF-8")
			}
			if record.DisplayRData == "" || record.CanonicalRData == "" {
				return invalid(fmt.Sprintf("sections.%s[%d]", names[sectionIndex], recordIndex), "MISSING_RDATA", "display and canonical RDATA are required")
			}
			if len(record.DisplayRData) > MaxRDataBytes || len(record.CanonicalRData) > MaxRDataBytes {
				return invalid(fmt.Sprintf("sections.%s[%d]", names[sectionIndex], recordIndex), "RDATA_TOO_LARGE", fmt.Sprintf("RDATA is limited to %d bytes", MaxRDataBytes))
			}
			derivedDisplay, err := DisplayRDataForCanonicalRData(record.Owner, record.Type, record.Class, record.CanonicalRData)
			if err != nil {
				return invalid(fmt.Sprintf("sections.%s[%d].canonical_rdata", names[sectionIndex], recordIndex), "INVALID_CANONICAL_RDATA", err.Error())
			}
			if record.DisplayRData != derivedDisplay {
				return invalid(fmt.Sprintf("sections.%s[%d].display_rdata", names[sectionIndex], recordIndex), "DISPLAY_RDATA_MISMATCH", "display RDATA must exactly match the canonical typed RR representation")
			}
		}
	}
	sections.Answer = all[0]
	sections.Authority = all[1]
	sections.Additional = all[2]
	if err := ApplyRRSetFingerprints(sections); err != nil {
		var validationError *ValidationError
		if errors.As(err, &validationError) {
			return err
		}
		return invalid("sections", "INVALID_RRSET", err.Error())
	}
	return nil
}

func normalizeAliasChain(question Question, sections Sections, chain *AliasChain, observationTruncated bool) error {
	if len(chain.Hops) > MaxAliasChainDepth {
		return invalid("alias_chain.hops", "ALIAS_CHAIN_LIMIT", fmt.Sprintf("alias chain is limited to %d hops", MaxAliasChainDepth))
	}
	if chain.CrossZone && !chain.CrossZoneKnown {
		return invalid("alias_chain.cross_zone", "UNKNOWN_CROSS_ZONE", "cross_zone=true requires cross_zone_known=true")
	}
	for i := range chain.Hops {
		hop := &chain.Hops[i]
		hop.Type = RRType(strings.ToUpper(strings.TrimSpace(string(hop.Type))))
		if hop.Type != RRTypeCNAME && hop.Type != RRTypeDNAME {
			return invalid(fmt.Sprintf("alias_chain.hops[%d].type", i), "INVALID_ALIAS_TYPE", "alias hop type must be CNAME or DNAME")
		}
		from, err := NormalizeWireName(hop.From)
		if err != nil {
			return invalid(fmt.Sprintf("alias_chain.hops[%d].from", i), "INVALID_ALIAS_NAME", err.Error())
		}
		to, err := NormalizeWireName(hop.To)
		if err != nil {
			return invalid(fmt.Sprintf("alias_chain.hops[%d].to", i), "INVALID_ALIAS_NAME", err.Error())
		}
		hop.From = from
		hop.To = to
	}
	if chain.TerminalName != "" {
		terminal, err := NormalizeWireName(chain.TerminalName)
		if err != nil {
			return invalid("alias_chain.terminal_name", "INVALID_ALIAS_NAME", err.Error())
		}
		chain.TerminalName = terminal
	}
	expected, err := aliasChainFromAnswer(question, sections.Answer)
	if err != nil {
		return err
	}
	if len(chain.Hops) == 0 && observationTruncated {
		if chain.Loop || chain.CrossZoneKnown || chain.CrossZone || chain.Truncated || chain.TerminalName != "" {
			return invalid("alias_chain", "INCOMPLETE_ALIAS_CHAIN", "a cropped alias chain must be omitted as an empty value")
		}
		return nil
	}
	if len(chain.Hops) != len(expected.Hops) {
		return invalid("alias_chain.hops", "ALIAS_EVIDENCE_MISMATCH", "alias hops must be completely derived from the answer section")
	}
	for i := range chain.Hops {
		if chain.Hops[i] != expected.Hops[i] {
			return invalid(fmt.Sprintf("alias_chain.hops[%d]", i), "ALIAS_EVIDENCE_MISMATCH", "alias hop does not match the CNAME or DNAME answer evidence")
		}
	}
	if chain.Loop != expected.Loop || chain.Truncated != expected.Truncated || chain.TerminalName != expected.TerminalName {
		return invalid("alias_chain", "ALIAS_CHAIN_INCONSISTENT", "alias loop, truncation, and terminal name must match the derived answer chain")
	}
	if len(chain.Hops) == 0 && (chain.CrossZoneKnown || chain.CrossZone) {
		return invalid("alias_chain.cross_zone_known", "CROSS_ZONE_WITHOUT_ALIAS", "cross-zone evidence requires at least one alias hop")
	}
	return nil
}

type aliasAnswerIndex struct {
	cnames map[string]string
	dnames map[string]string
}

func aliasChainFromAnswer(question Question, answers []ResourceRecord) (AliasChain, error) {
	index, err := buildAliasAnswerIndex(answers)
	if err != nil {
		return AliasChain{}, err
	}
	for owner, target := range index.cnames {
		dnameOwner, dnameTarget, ok := closestDNAME(owner, index.dnames)
		if !ok {
			continue
		}
		synthesized, ok := synthesizeDNAMEAlias(owner, dnameOwner, dnameTarget)
		if !ok || synthesized != target {
			return AliasChain{}, invalid("sections.answer", "CONFLICTING_ALIAS_EVIDENCE", "a synthesized CNAME conflicts with its closest DNAME answer")
		}
	}

	current := question.Name
	visited := map[string]bool{current: true}
	chain := AliasChain{}
	for range MaxAliasChainDepth {
		hop, ok := nextAnswerAliasHop(current, index)
		if !ok {
			if len(chain.Hops) != 0 {
				chain.TerminalName = current
			}
			return chain, nil
		}
		chain.Hops = append(chain.Hops, hop)
		if visited[hop.To] {
			chain.Loop = true
			chain.TerminalName = hop.To
			return chain, nil
		}
		visited[hop.To] = true
		current = hop.To
	}
	if _, ok := nextAnswerAliasHop(current, index); ok {
		chain.Truncated = true
	}
	chain.TerminalName = current
	return chain, nil
}

func buildAliasAnswerIndex(answers []ResourceRecord) (aliasAnswerIndex, error) {
	result := aliasAnswerIndex{cnames: make(map[string]string), dnames: make(map[string]string)}
	for i := range answers {
		record := answers[i]
		if record.Type != RRTypeCNAME && record.Type != RRTypeDNAME {
			continue
		}
		target, err := aliasRecordTarget(record)
		if err != nil {
			return aliasAnswerIndex{}, invalid(fmt.Sprintf("sections.answer[%d]", i), "INVALID_ALIAS_RDATA", err.Error())
		}
		targets := result.cnames
		if record.Type == RRTypeDNAME {
			targets = result.dnames
		}
		if previous, exists := targets[record.Owner]; exists && previous != target {
			return aliasAnswerIndex{}, invalid(fmt.Sprintf("sections.answer[%d]", i), "CONFLICTING_ALIAS_EVIDENCE", "an alias owner cannot have multiple targets")
		}
		targets[record.Owner] = target
	}
	return result, nil
}

func aliasRecordTarget(record ResourceRecord) (string, error) {
	displayTarget, err := NormalizeWireName(record.DisplayRData)
	if err != nil {
		return "", fmt.Errorf("display RDATA is not a canonical alias target")
	}
	fields := strings.Fields(record.CanonicalRData)
	if len(fields) != 3 || fields[0] != `\#` {
		return "", fmt.Errorf("canonical alias RDATA must use RFC 3597 wire form")
	}
	wantLength, err := strconv.Atoi(fields[1])
	if err != nil || wantLength < 1 || wantLength > MaxRDataBytes {
		return "", fmt.Errorf("canonical alias RDATA has an invalid wire length")
	}
	wire, err := hex.DecodeString(fields[2])
	if err != nil || len(wire) != wantLength {
		return "", fmt.Errorf("canonical alias RDATA does not match its wire length")
	}
	if aliasRDATAUsesCompression(wire) {
		return "", fmt.Errorf("canonical alias RDATA must not contain compression pointers")
	}
	name, offset, err := dns.UnpackDomainName(wire, 0)
	if err != nil || offset != len(wire) {
		return "", fmt.Errorf("canonical alias RDATA is not one complete domain name")
	}
	canonicalTarget, err := NormalizeWireName(name)
	if err != nil {
		return "", fmt.Errorf("canonical alias RDATA contains an invalid domain name")
	}
	if canonicalTarget != displayTarget {
		return "", fmt.Errorf("display and canonical alias RDATA targets disagree")
	}
	return canonicalTarget, nil
}

func aliasRDATAUsesCompression(wire []byte) bool {
	for offset := 0; offset < len(wire); {
		length := wire[offset]
		if length&0xc0 == 0xc0 {
			return true
		}
		if length&0xc0 != 0 || length == 0 {
			return false
		}
		offset += 1 + int(length)
	}
	return false
}

func nextAnswerAliasHop(current string, index aliasAnswerIndex) (AliasHop, bool) {
	if owner, target, ok := closestDNAME(current, index.dnames); ok {
		if synthesized, valid := synthesizeDNAMEAlias(current, owner, target); valid {
			return AliasHop{Type: RRTypeDNAME, From: current, To: synthesized}, true
		}
	}
	if target, ok := index.cnames[current]; ok {
		return AliasHop{Type: RRTypeCNAME, From: current, To: target}, true
	}
	return AliasHop{}, false
}

func closestDNAME(current string, dnames map[string]string) (string, string, bool) {
	bestOwner := ""
	bestTarget := ""
	for owner, target := range dnames {
		if owner == current || !dns.IsSubDomain(owner, current) || len(owner) <= len(bestOwner) {
			continue
		}
		bestOwner = owner
		bestTarget = target
	}
	return bestOwner, bestTarget, bestOwner != ""
}

func synthesizeDNAMEAlias(current string, owner string, target string) (string, bool) {
	if current == owner || !dns.IsSubDomain(owner, current) {
		return "", false
	}
	prefix := strings.TrimSuffix(current, owner)
	if target == "." {
		normalized, err := NormalizeWireName(prefix)
		return normalized, err == nil
	}
	normalized, err := NormalizeWireName(prefix + target)
	return normalized, err == nil
}

func normalizeEDNS(edns *EDNS) error {
	if !edns.Present {
		if edns.UDPSize != 0 || edns.Version != 0 || edns.Flags != 0 || edns.DNSSECOK || edns.ECS != nil || len(edns.EDE) != 0 || edns.NSIDHex != "" || len(edns.Options) != 0 {
			return invalid("edns", "INCONSISTENT_EDNS", "EDNS data requires present=true")
		}
		return nil
	}
	if edns.UDPSize < 512 || edns.UDPSize > 65535 {
		return invalid("edns.udp_size", "INVALID_EDNS_UDP_SIZE", "EDNS UDP size must be from 512 to 65535")
	}
	if edns.DNSSECOK != (edns.Flags&0x8000 != 0) {
		return invalid("edns.flags", "INCONSISTENT_EDNS_DO", "DNSSEC OK must match the DO bit in EDNS flags")
	}
	if len(edns.EDE) > MaxExtendedDNSErrors || len(edns.Options) > MaxEDNSOptions {
		return invalid("edns", "EDNS_OPTION_LIMIT", "EDNS option count exceeds the contract limit")
	}
	if edns.ECS != nil {
		addr, err := netip.ParseAddr(strings.TrimSpace(edns.ECS.Address))
		if err != nil || addr.Zone() != "" {
			return invalid("edns.ecs.address", "INVALID_ECS_ADDRESS", "ECS address must be IPv4 or IPv6")
		}
		addr = addr.Unmap()
		bits := uint8(128)
		if addr.Is4() {
			bits = 32
		}
		if edns.ECS.SourcePrefix > bits || edns.ECS.ScopePrefix > bits {
			return invalid("edns.ecs", "INVALID_ECS_PREFIX", "ECS prefix exceeds its address family")
		}
		edns.ECS.Address = netip.PrefixFrom(addr, int(edns.ECS.SourcePrefix)).Masked().Addr().String()
	}
	if edns.NSIDHex != "" {
		edns.NSIDHex = strings.ToLower(strings.TrimSpace(edns.NSIDHex))
		decoded, err := hex.DecodeString(edns.NSIDHex)
		if err != nil || len(decoded) > MaxRDataBytes {
			return invalid("edns.nsid_hex", "INVALID_NSID", "NSID must be bounded hexadecimal data")
		}
	}
	for i := range edns.EDE {
		if !utf8.ValidString(edns.EDE[i].Text) || len(edns.EDE[i].Text) > MaxErrorMessageBytes {
			return invalid(fmt.Sprintf("edns.ede[%d].text", i), "INVALID_EDE_TEXT", "EDE text must be valid bounded UTF-8")
		}
	}
	for i := range edns.Options {
		decoded, err := base64.StdEncoding.Strict().DecodeString(edns.Options[i].DataBase64)
		if err != nil || len(decoded) > MaxRDataBytes {
			return invalid(fmt.Sprintf("edns.options[%d].data_base64", i), "INVALID_EDNS_OPTION", "EDNS option data must be bounded canonical base64")
		}
	}
	return nil
}

func normalizeObservationError(observation *Observation) error {
	transport := observation.TransportStatus
	outcome := observation.Outcome
	observationError := observation.Error
	requiresError := transport != TransportSuccess || outcome == DNSOutcomeMalformed || outcome == DNSOutcomeTruncatedResponse
	if observationError == nil {
		if requiresError {
			return invalid("error", "MISSING_STRUCTURED_ERROR", "failed or malformed observations require a structured error")
		}
		return nil
	}
	if err := normalizeCode("error.code", &observationError.Code, true); err != nil {
		return err
	}
	if transport == TransportSuccess {
		if outcome != DNSOutcomeMalformed && outcome != DNSOutcomeTruncatedResponse {
			return invalid("error", "UNEXPECTED_STRUCTURED_ERROR", "successful parsed DNS observations must not contain an error")
		}
		if observationError.Code != "MALFORMED_DNS" || observationError.Retryable {
			return invalid("error.retryable", "RETRYABLE_MALFORMED_RESPONSE", "a received but unclassifiable DNS response is not a retryable transport error")
		}
	}
	if transport == TransportCancelled && (observationError.Code != "CANCELLED" || observationError.Retryable) {
		return invalid("error", "INVALID_CANCELLED_ERROR", "cancelled transport requires a non-retryable CANCELLED error")
	}
	if transport == TransportTimeout && (observationError.Code != "TIMEOUT" || !observationError.Retryable) {
		return invalid("error", "INVALID_TIMEOUT_ERROR", "timeout transport requires a retryable TIMEOUT error")
	}
	if transport == TransportRefused && (observationError.Code != "CONNECTION_REFUSED" || !observationError.Retryable) {
		return invalid("error", "INVALID_REFUSED_ERROR", "refused transport requires a retryable CONNECTION_REFUSED error")
	}
	if transport == TransportNetworkError {
		valid := observationError.Code == "NETWORK_ERROR" && observationError.Retryable ||
			observationError.Code == "RESPONSE_TOO_LARGE" && !observationError.Retryable ||
			observation.AttemptCount == 0 && observationError.Code == "INTERNAL_ERROR" && !observationError.Retryable
		if !valid {
			return invalid("error", "INVALID_NETWORK_ERROR", "network_error requires NETWORK_ERROR, RESPONSE_TOO_LARGE, or the zero-attempt INTERNAL_ERROR contract")
		}
	}
	observationError.Message = strings.TrimSpace(observationError.Message)
	if observationError.Message == "" || !utf8.ValidString(observationError.Message) || len(observationError.Message) > MaxErrorMessageBytes {
		return invalid("error.message", "INVALID_ERROR_MESSAGE", fmt.Sprintf("error message must contain from 1 to %d bytes of UTF-8", MaxErrorMessageBytes))
	}
	return nil
}

func validateObservationAttemptContract(result *Observation) error {
	if len(result.Attempts) == 0 {
		return nil
	}
	lastIndex := len(result.Attempts) - 1
	last := result.Attempts[lastIndex]
	if last.TransportStatus == TransportSuccess {
		if result.TransportStatus != TransportSuccess {
			return invalid("transport_status", "FINAL_ATTEMPT_STATUS_MISMATCH", "a successful final attempt requires successful top-level transport")
		}
	} else if result.TransportStatus != last.TransportStatus {
		gapTermination := last.Error != nil && last.Error.Retryable &&
			(result.TransportStatus == TransportCancelled || result.TransportStatus == TransportTimeout) &&
			!result.FinishedAt.Before(last.FinishedAt)
		if !gapTermination || !validRetryGapShape(*result) {
			return invalid("transport_status", "FINAL_ATTEMPT_STATUS_MISMATCH", "top-level transport must match the final attempt except cancellation or deadline in a retry gap")
		}
	} else if result.Error == nil || last.Error == nil || result.Error.Code != last.Error.Code || result.Error.Retryable != last.Error.Retryable {
		return invalid("error", "FINAL_ATTEMPT_ERROR_MISMATCH", "top-level transport error must match the final physical attempt")
	}

	if result.ResponseAttempt == 0 {
		if result.Outcome != DNSOutcomeNotObserved {
			return invalid("response_attempt", "MISSING_RESPONSE_OWNER", "an observed DNS response requires a 1-based response_attempt owner")
		}
		if result.PeerIP != last.PeerIP || result.ResponseSizeBytes != last.ResponseSizeBytes || result.ResponseTruncated || !result.ObservedAt.Equal(result.FinishedAt) {
			return invalid("response_attempt", "UNOWNED_RESPONSE_METADATA", "without a response owner, top-level peer and size must match the final attempt and observed_at must equal finished_at")
		}
		return nil
	}

	ownerIndex := result.ResponseAttempt - 1
	owner := result.Attempts[ownerIndex]
	if owner.TransportStatus != TransportSuccess {
		return invalid("response_attempt", "FAILED_RESPONSE_OWNER", "response_attempt must identify a successful wire response")
	}
	if result.Outcome == DNSOutcomeNotObserved {
		return invalid("response_attempt", "UNEXPECTED_RESPONSE_OWNER", "not_observed cannot claim a response owner")
	}
	if result.PeerIP != owner.PeerIP || result.ResponseSizeBytes != owner.ResponseSizeBytes || result.ResponseTruncated != owner.ResponseTruncated || !result.ObservedAt.Equal(owner.FinishedAt) {
		return invalid("response_attempt", "RESPONSE_OWNER_METADATA_MISMATCH", "top-level response peer, size, TC, and observed_at must match response_attempt")
	}

	expectedOwner := lastIndex
	if last.TransportStatus != TransportSuccess {
		expectedOwner = -1
		for index := 0; index < lastIndex; index++ {
			attempt := result.Attempts[index]
			if attempt.Protocol == ProtocolUDP && attempt.TransportStatus == TransportSuccess && attempt.ResponseTruncated {
				if expectedOwner != -1 {
					return invalid("response_attempt", "AMBIGUOUS_FALLBACK_RESPONSE", "failed fallback contains more than one UDP TC response owner")
				}
				expectedOwner = index
			}
		}
	}
	if expectedOwner < 0 || ownerIndex != expectedOwner {
		return invalid("response_attempt", "WRONG_RESPONSE_OWNER", "response_attempt does not identify the response permitted by the physical attempt sequence")
	}
	return nil
}

func validRetryGapShape(result Observation) bool {
	if result.UDPToTCPFallback {
		return len(result.Attempts) == 2 &&
			result.Attempts[0].Protocol == ProtocolUDP && result.Attempts[0].TransportStatus == TransportSuccess && result.Attempts[0].ResponseTruncated &&
			result.Attempts[1].Protocol == ProtocolTCP && result.Attempts[1].TransportStatus != TransportSuccess
	}
	return len(result.Attempts) == 1 && result.Attempts[0].Protocol == result.Endpoint.Protocol && result.Attempts[0].TransportStatus != TransportSuccess
}

// RetryGapAdditionalAttempts returns the physical slots that must still have
// been available when cancellation or deadline terminated retry scheduling.
func RetryGapAdditionalAttempts(observation Observation) int {
	if len(observation.Attempts) == 0 {
		return 0
	}
	last := observation.Attempts[len(observation.Attempts)-1]
	if observation.TransportStatus == last.TransportStatus || !validRetryGapShape(observation) {
		return 0
	}
	if observation.UDPToTCPFallback {
		return 1
	}
	if last.Protocol == ProtocolUDP {
		// The pending UDP retry also needs one reserved slot for mandatory TC
		// fallback.
		return 2
	}
	return 1
}

func normalizeIdentifier(field string, value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > MaxIdentifierBytes || !identifierPattern.MatchString(value) {
		return "", invalid(field, "INVALID_IDENTIFIER", fmt.Sprintf("identifier must contain from 1 to %d safe ASCII bytes", MaxIdentifierBytes))
	}
	return value, nil
}

func normalizeCode(field string, value *string, required bool) error {
	*value = strings.ToUpper(strings.TrimSpace(*value))
	if *value == "" && !required {
		return nil
	}
	if len(*value) > 64 || !errorCodePattern.MatchString(*value) {
		return invalid(field, "INVALID_ERROR_CODE", "code must use 1 to 64 uppercase ASCII letters, digits, or underscores")
	}
	return nil
}

func validateModeEndpoint(mode Mode, kind EndpointKind) error {
	switch mode {
	case ModeRecursive:
		if kind != EndpointSystem && kind != EndpointCatalog && kind != EndpointPublicAnycast {
			return fmt.Errorf("recursive mode requires a system, catalog, or public-anycast endpoint")
		}
	case ModeIterative:
		if kind != EndpointRootHints {
			return fmt.Errorf("iterative mode requires a root-hints endpoint")
		}
	case ModeAuthoritative:
		if kind != EndpointParentAuthority && kind != EndpointChildAuthority {
			return fmt.Errorf("authoritative mode requires a parent-authority or child-authority endpoint")
		}
	}
	return nil
}

var nonPublicDNSPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// Product safety policy: reject the globally reachable well-known NAT64
	// prefix because it can encode private or reserved IPv4 destinations.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

// These IANA special-purpose addresses are globally reachable exceptions
// nested inside broader protocol-assignment blocks that remain denied.
var publicDNSAddressExceptions = [...]netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"),
	netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

func IsPublicDNSAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range publicDNSAddressExceptions {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range nonPublicDNSPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func cloneObservation(observation Observation) Observation {
	result := observation
	if observation.Attempts != nil {
		result.Attempts = append([]WireAttempt{}, observation.Attempts...)
		for index := range result.Attempts {
			if observation.Attempts[index].Error != nil {
				value := *observation.Attempts[index].Error
				result.Attempts[index].Error = &value
			}
		}
	}
	if observation.RCode != nil {
		value := *observation.RCode
		result.RCode = &value
	}
	if observation.ExtendedRCode != nil {
		value := *observation.ExtendedRCode
		result.ExtendedRCode = &value
	}
	if observation.NegativeTTL != nil {
		value := *observation.NegativeTTL
		result.NegativeTTL = &value
	}
	if observation.Error != nil {
		value := *observation.Error
		result.Error = &value
	}
	if observation.EDNS.ECS != nil {
		value := *observation.EDNS.ECS
		result.EDNS.ECS = &value
	}
	result.EDNS.EDE = append([]ExtendedDNSError(nil), observation.EDNS.EDE...)
	result.EDNS.Options = append([]EDNSOption(nil), observation.EDNS.Options...)
	result.Sections.Answer = append([]ResourceRecord(nil), observation.Sections.Answer...)
	result.Sections.Authority = append([]ResourceRecord(nil), observation.Sections.Authority...)
	result.Sections.Additional = append([]ResourceRecord(nil), observation.Sections.Additional...)
	result.AliasChain.Hops = append([]AliasHop(nil), observation.AliasChain.Hops...)
	return result
}
