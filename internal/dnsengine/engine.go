package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func New(config Config) (*Engine, error) {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	udpSize := config.UDPSize
	if udpSize == 0 {
		udpSize = DefaultUDPSize
	}
	if udpSize < 512 || udpSize > 4096 {
		return nil, fmt.Errorf("UDP size must be between 512 and 4096 bytes")
	}
	maxResponseBytes := config.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = DefaultMaxResponseBytes
	}
	if maxResponseBytes < 12 || maxResponseBytes > 65535 {
		return nil, fmt.Errorf("max response bytes must be between 12 and 65535")
	}
	maxRecordsPerSection := config.MaxRecordsPerSection
	if maxRecordsPerSection == 0 {
		maxRecordsPerSection = DefaultMaxRecordsPerSection
	}
	if maxRecordsPerSection < 1 || maxRecordsPerSection > MaxRecordsPerSection {
		return nil, fmt.Errorf("max records per section must be between 1 and %d", MaxRecordsPerSection)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
		if tlsConfig.InsecureSkipVerify {
			return nil, fmt.Errorf("TLS certificate verification cannot be disabled")
		}
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS12 {
			return nil, fmt.Errorf("TLS maximum version must permit TLS 1.2 or newer")
		}
	}
	quicConfig := &quic.Config{HandshakeIdleTimeout: timeout}
	if config.QUICConfig != nil {
		quicConfig = config.QUICConfig.Clone()
		if quicConfig.HandshakeIdleTimeout <= 0 || quicConfig.HandshakeIdleTimeout > timeout {
			quicConfig.HandshakeIdleTimeout = timeout
		}
	}
	dialer := net.Dialer{}
	if config.Dialer != nil {
		dialer = *config.Dialer
	}
	idGenerator := config.IDGenerator
	if idGenerator == nil {
		idGenerator = secureMessageID
	}
	return &Engine{
		timeout:               timeout,
		udpSize:               udpSize,
		maxResponseBytes:      maxResponseBytes,
		maxRecordsPerSection:  maxRecordsPerSection,
		allowECS:              config.AllowECS,
		allowPrivateConnectIP: config.AllowPrivateConnectIP,
		tlsConfig:             tlsConfig,
		quicConfig:            quicConfig,
		dialer:                dialer,
		idGenerator:           idGenerator,
	}, nil
}

func (e *Engine) Observe(ctx context.Context, endpoint Endpoint, query Query) (*Result, error) {
	if e == nil {
		return nil, errors.New("DNS engine is nil")
	}
	resolved, err := resolveEndpoint(endpoint, e.allowPrivateConnectIP)
	if err != nil {
		return nil, err
	}
	message, err := e.buildQuery(query, resolved.protocol)
	if err != nil {
		return nil, err
	}
	mode := query.Mode
	if mode == "" {
		mode = QueryModeRecursive
	}
	return e.exchangePrepared(ctx, resolved, message, mode == QueryModeIterative)
}

func (e *Engine) ExchangeMessage(ctx context.Context, endpoint Endpoint, message *dns.Msg) (*Result, error) {
	if e == nil {
		return nil, errors.New("DNS engine is nil")
	}
	resolved, err := resolveEndpoint(endpoint, e.allowPrivateConnectIP)
	if err != nil {
		return nil, err
	}
	prepared, err := e.prepareMessage(message, resolved.protocol)
	if err != nil {
		return nil, err
	}
	return e.exchangePrepared(ctx, resolved, prepared, false)
}

func (e *Engine) exchangePrepared(parent context.Context, endpoint resolvedEndpoint, query *dns.Msg, allowReferral bool) (*Result, error) {
	started := time.Now()
	result := &Result{
		Question:      query.Question[0],
		Protocol:      endpoint.protocol,
		StartedAt:     started,
		allowReferral: allowReferral,
	}
	wire, err := query.Pack()
	if err != nil {
		return result, fmt.Errorf("%w: pack query: %v", ErrInvalidQuery, err)
	}
	if len(wire) > 65535 {
		return result, fmt.Errorf("%w: packed query is too large", ErrInvalidQuery)
	}

	responseWire, attempt, err := e.exchangeAttempt(parent, endpoint, endpoint.protocol, wire)
	result.Attempts = append(result.Attempts, attempt)
	result.PeerIP = attempt.PeerIP
	result.ResponseSize = attempt.ResponseSize
	result.ResponseTruncated = false
	if err != nil {
		result.Duration = time.Since(started)
		return result, err
	}
	udpTruncated := endpoint.protocol == ProtocolUDP && wireHasTC(responseWire)
	response, unpackErr := unpackResponse(responseWire)
	if udpTruncated {
		// TC can cut a message at any byte. Prefix validation is therefore the
		// trust boundary for deciding whether this packet belongs to the query.
		if err := validateTruncatedResponsePrefix(query, responseWire); err != nil {
			result.Outcome = OutcomeMalformed
			result.ResponseSize = len(responseWire)
			result.Duration = time.Since(started)
			return result, err
		}
		if unpackErr == nil && validateResponse(query, response) == nil {
			if err := e.composeResult(result, response); err != nil {
				// A validated UDP TC header still mandates TCP fallback. If its
				// body cannot be represented, retain only the trusted prefix.
				populateTruncatedResponsePrefix(result, responseWire)
			}
		} else {
			populateTruncatedResponsePrefix(result, responseWire)
		}
		result.ResponseSize = len(responseWire)
		result.ResponseTruncated = true
		fallbackEndpoint := endpoint
		fallbackEndpoint.protocol = ProtocolTCP
		responseWire, attempt, err = e.exchangeAttempt(parent, fallbackEndpoint, ProtocolTCP, wire)
		result.Attempts = append(result.Attempts, attempt)
		result.UDPToTCPFallback = true
		if err != nil {
			if errors.Is(err, ErrMalformedResponse) {
				result.PeerIP = attempt.PeerIP
				result.ResponseSize = attempt.ResponseSize
				clearMalformedFallbackEvidence(result)
			}
			result.Duration = time.Since(started)
			return result, err
		}
		response, unpackErr = unpackResponse(responseWire)
		if unpackErr == nil {
			unpackErr = validateResponse(query, response)
		}
		if unpackErr != nil {
			// The final transport did receive bytes. Attribute its peer and size to
			// the TCP attempt. DNS evidence must also come from TCP; retaining the
			// earlier UDP header here would mix provenance under protocol=tcp.
			result.PeerIP = attempt.PeerIP
			result.ResponseSize = len(responseWire)
			if wireHasTC(responseWire) && validateTruncatedResponsePrefix(query, responseWire) == nil {
				populateTruncatedResponsePrefix(result, responseWire)
			} else {
				clearMalformedFallbackEvidence(result)
			}
			result.Duration = time.Since(started)
			return result, unpackErr
		}
		completed := *result
		if err := e.composeResult(&completed, response); err != nil {
			result.PeerIP = attempt.PeerIP
			result.ResponseSize = len(responseWire)
			if wireHasTC(responseWire) && validateTruncatedResponsePrefix(query, responseWire) == nil {
				populateTruncatedResponsePrefix(result, responseWire)
			} else {
				clearMalformedFallbackEvidence(result)
			}
			result.Duration = time.Since(started)
			return result, err
		}
		completed.PeerIP = attempt.PeerIP
		completed.ResponseSize = len(responseWire)
		completed.Duration = time.Since(started)
		return &completed, nil
	}
	if unpackErr == nil {
		unpackErr = validateResponse(query, response)
	}
	if unpackErr != nil {
		if endpoint.protocol == ProtocolTCP && wireHasTC(responseWire) && validateTruncatedResponsePrefix(query, responseWire) == nil {
			retainPendingTCPHeader(result, responseWire, attempt)
		}
		result.Outcome = OutcomeMalformed
		result.ResponseSize = len(responseWire)
		result.Duration = time.Since(started)
		return result, unpackErr
	}

	result.Duration = time.Since(started)
	if err := e.composeResult(result, response); err != nil {
		if endpoint.protocol == ProtocolTCP && wireHasTC(responseWire) && validateTruncatedResponsePrefix(query, responseWire) == nil {
			clearMalformedFallbackEvidence(result)
			retainPendingTCPHeader(result, responseWire, attempt)
		}
		return result, err
	}
	return result, nil
}

func (e *Engine) exchangeAttempt(parent context.Context, endpoint resolvedEndpoint, protocol Protocol, query []byte) ([]byte, Attempt, error) {
	ctx, cancel := context.WithTimeout(parent, e.timeout)
	defer cancel()
	attemptStarted := time.Now()
	attempt := Attempt{Protocol: protocol, StartedAt: attemptStarted}
	wire, peerIP, err := e.exchangeWire(ctx, endpoint, protocol, query)
	attempt.Duration = time.Since(attemptStarted)
	attempt.PeerIP = peerIP
	attempt.ResponseSize = len(wire)
	attempt.Truncated = wireHasTC(wire)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				err = context.DeadlineExceeded
			}
		}
		attempt.Error = err.Error()
		attempt.err = err
		return wire, attempt, protocolError(protocol, "exchange", err)
	}
	if len(wire) > e.maxResponseBytes {
		err = fmt.Errorf("%w: got %d bytes, limit %d", ErrResponseTooLarge, len(wire), e.maxResponseBytes)
		attempt.Error = err.Error()
		attempt.err = err
		return wire, attempt, err
	}
	return wire, attempt, nil
}
