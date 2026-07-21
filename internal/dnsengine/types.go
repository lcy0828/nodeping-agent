// Package dnsengine provides bounded, validated DNS wire exchanges.
//
// It deliberately stops at the wire-observation boundary. Iterative resolution
// and local DNSSEC validation are separate capabilities and are not implied by
// a successful exchange.
package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"nodeping/internal/systemdns"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	DefaultTimeout                     = 5 * time.Second
	DefaultUDPSize              uint16 = 1232
	DefaultMaxResponseBytes            = 65535
	DefaultMaxRecordsPerSection        = 64
	MaxRecordsPerSection               = 128
	MaxEDNSOptions                     = 64
	MaxExtendedDNSErrors               = 32
)

var (
	ErrInvalidEndpoint   = errors.New("invalid DNS endpoint")
	ErrInvalidQuery      = errors.New("invalid DNS query")
	ErrECSDisabled       = errors.New("EDNS Client Subnet is disabled")
	ErrResponseMismatch  = errors.New("DNS response does not match query")
	ErrResponseTooLarge  = errors.New("DNS response exceeds size limit")
	ErrMalformedResponse = errors.New("malformed DNS response")
)

type Protocol string

const (
	ProtocolUDP Protocol = "udp"
	ProtocolTCP Protocol = "tcp"
	ProtocolDoT Protocol = "dot"
	ProtocolDoH Protocol = "doh"
	ProtocolDoQ Protocol = "doq"
)

type QueryMode string

const (
	QueryModeRecursive     QueryMode = "recursive"
	QueryModeIterative     QueryMode = "iterative"
	QueryModeAuthoritative QueryMode = "authoritative"
)

func (m QueryMode) valid() bool {
	switch m {
	case QueryModeRecursive, QueryModeIterative, QueryModeAuthoritative:
		return true
	default:
		return false
	}
}

// Endpoint separates the resolver's logical identity from its dial target.
// Address is a hostname/IP (or an HTTPS URL for DoH), ConnectIP pins the network
// connection whenever Address is a hostname, and ServerName overrides TLS SNI.
type Endpoint struct {
	Protocol   Protocol `json:"protocol"`
	Address    string   `json:"address"`
	ConnectIP  string   `json:"connect_ip,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	Port       uint16   `json:"port,omitempty"`

	trustedSystem *systemdns.DialTarget
}

type Query struct {
	Name              string
	Type              uint16
	Class             uint16
	Mode              QueryMode
	RecursionDesired  bool
	CheckingDisabled  bool
	DNSSECOK          bool
	AuthenticatedData bool
}

type Config struct {
	Timeout              time.Duration
	UDPSize              uint16
	MaxResponseBytes     int
	MaxRecordsPerSection int
	AllowECS             bool
	// AllowPrivateConnectIP is only for controlled integration tests or trusted
	// private deployments. Production callers must leave it false.
	AllowPrivateConnectIP bool
	TLSConfig             *tls.Config
	QUICConfig            *quic.Config
	Dialer                *net.Dialer
	IDGenerator           func() (uint16, error)
}

type Engine struct {
	timeout               time.Duration
	udpSize               uint16
	maxResponseBytes      int
	maxRecordsPerSection  int
	allowECS              bool
	allowPrivateConnectIP bool
	tlsConfig             *tls.Config
	quicConfig            *quic.Config
	dialer                net.Dialer
	idGenerator           func() (uint16, error)
	resultComposer        func(*Result, *dns.Msg) error
}

type Attempt struct {
	Protocol     Protocol      `json:"protocol"`
	StartedAt    time.Time     `json:"started_at"`
	Duration     time.Duration `json:"duration"`
	PeerIP       string        `json:"peer_ip,omitempty"`
	ResponseSize int           `json:"response_size_bytes,omitempty"`
	Truncated    bool          `json:"truncated,omitempty"`
	Error        string        `json:"error,omitempty"`
	err          error
}

type Flags struct {
	Response           bool `json:"qr"`
	Authoritative      bool `json:"aa"`
	AuthenticData      bool `json:"ad"`
	CheckingDisabled   bool `json:"cd"`
	RecursionAvailable bool `json:"ra"`
	RecursionDesired   bool `json:"rd"`
	Truncated          bool `json:"tc"`
	ReservedZ          bool `json:"z"`
}

type EDNSOption struct {
	Code       uint16 `json:"code"`
	DataBase64 string `json:"data_base64"`
}

type ClientSubnet struct {
	Address      string `json:"address"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
}

type ExtendedDNSError struct {
	Code uint16 `json:"code"`
	Text string `json:"text,omitempty"`
}

type EDNS struct {
	Present  bool               `json:"present"`
	UDPSize  uint16             `json:"udp_size,omitempty"`
	Version  uint8              `json:"version,omitempty"`
	Flags    uint16             `json:"flags,omitempty"`
	DNSSECOK bool               `json:"dnssec_ok,omitempty"`
	ECS      *ClientSubnet      `json:"ecs,omitempty"`
	EDE      []ExtendedDNSError `json:"ede,omitempty"`
	NSIDHex  string             `json:"nsid_hex,omitempty"`
	Options  []EDNSOption       `json:"options,omitempty"`
}

type ResourceRecord struct {
	Owner            string `json:"owner"`
	Type             string `json:"type"`
	Class            string `json:"class"`
	TTL              uint32 `json:"ttl"`
	DisplayRData     string `json:"display_rdata"`
	CanonicalRData   string `json:"canonical_rdata"`
	RRSetRecordCount int    `json:"rrset_record_count"`
}

type Sections struct {
	Answer     []ResourceRecord `json:"answer"`
	Authority  []ResourceRecord `json:"authority"`
	Additional []ResourceRecord `json:"additional"`
}

type AliasChain struct {
	Hops           []AliasHop `json:"hops"`
	Loop           bool       `json:"loop"`
	CrossZoneKnown bool       `json:"cross_zone_known"`
	CrossZone      bool       `json:"cross_zone"`
	Truncated      bool       `json:"truncated"`
	TerminalName   string     `json:"terminal_name,omitempty"`
}

type AliasHop struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

type Outcome string

const (
	OutcomeAnswer            Outcome = "answer"
	OutcomeNoData            Outcome = "nodata"
	OutcomeNXDomain          Outcome = "nxdomain"
	OutcomeServFail          Outcome = "servfail"
	OutcomeRefused           Outcome = "refused"
	OutcomeReferral          Outcome = "referral"
	OutcomeMalformed         Outcome = "malformed"
	OutcomeTruncatedResponse Outcome = "truncated_response"
	OutcomeOther             Outcome = "rcode_error"
)

type Result struct {
	Question         dns.Question  `json:"question"`
	Protocol         Protocol      `json:"protocol"`
	PeerIP           string        `json:"peer_ip,omitempty"`
	StartedAt        time.Time     `json:"started_at"`
	Duration         time.Duration `json:"duration"`
	Attempts         []Attempt     `json:"attempts"`
	UDPToTCPFallback bool          `json:"udp_to_tcp_fallback"`
	RCode            uint8         `json:"rcode"`
	ExtendedRCode    uint8         `json:"extended_rcode"`
	Flags            Flags         `json:"flags"`
	EDNS             EDNS          `json:"edns"`
	Outcome          Outcome       `json:"outcome"`
	Sections         Sections      `json:"sections"`
	AliasChain       AliasChain    `json:"alias_chain"`
	NegativeTTL      *uint32       `json:"negative_ttl,omitempty"`
	ResponseSize     int           `json:"response_size_bytes"`
	ResponseParsed   bool          `json:"response_parsed"`
	// ResponseHeaderValidated marks a TC response whose header and question were
	// verified even though its RR sections could not be parsed completely.
	ResponseHeaderValidated bool     `json:"response_header_validated"`
	ResponseTruncated       bool     `json:"response_truncated"`
	ResultTruncated         bool     `json:"result_truncated"`
	Message                 *dns.Msg `json:"-"`
	allowReferral           bool
	pendingTCPHeader        *truncatedResponseHeader
}

// truncatedResponseHeader is retained internally when a direct TCP exchange
// receives a validated header/question/TC prefix but cannot parse the whole
// message. It is only promoted to public response evidence after the Agent
// proves that this TCP exchange is the final attempt of an earlier UDP
// fallback operation.
type truncatedResponseHeader struct {
	RCode            uint8
	Flags            Flags
	PeerIP           string
	ResponseSize     int
	AttemptStartedAt time.Time
}

func (r Result) FullRCode() uint16 {
	return uint16(r.ExtendedRCode)<<4 | uint16(r.RCode&0x0f)
}

type Capabilities struct {
	WireProtocols         []Protocol
	IterativeResolution   bool
	LocalDNSSECValidation bool
}

func (e *Engine) Capabilities() Capabilities {
	return Capabilities{
		WireProtocols:         []Protocol{ProtocolUDP, ProtocolTCP, ProtocolDoT, ProtocolDoH, ProtocolDoQ},
		IterativeResolution:   false,
		LocalDNSSECValidation: false,
	}
}

// Messenger is the narrow boundary needed by future iterative and DNSSEC
// implementations.
type Messenger interface {
	ExchangeMessage(context.Context, Endpoint, *dns.Msg) (*Result, error)
}

type IterativeRequest struct {
	Question  dns.Question
	RootHints []Endpoint
	MaxDepth  int
}

type IterativeResult struct {
	Final *Result
	Trace []*Result
}

type IterativeResolver interface {
	ResolveIteratively(context.Context, IterativeRequest) (*IterativeResult, error)
}

type DNSSECStatus string

const (
	DNSSECSecure        DNSSECStatus = "secure"
	DNSSECInsecure      DNSSECStatus = "insecure"
	DNSSECBogus         DNSSECStatus = "bogus"
	DNSSECIndeterminate DNSSECStatus = "indeterminate"
)

type DNSSECValidationRequest struct {
	Question     dns.Question
	Response     *dns.Msg
	Trace        []*Result
	TrustAnchors []dns.RR
	Now          time.Time
}

type DNSSECValidation struct {
	Status DNSSECStatus
	Reason string
}

type DNSSECValidator interface {
	ValidateDNSSEC(context.Context, DNSSECValidationRequest) (DNSSECValidation, error)
}

func (p Protocol) valid() bool {
	switch p {
	case ProtocolUDP, ProtocolTCP, ProtocolDoT, ProtocolDoH, ProtocolDoQ:
		return true
	default:
		return false
	}
}

func (p Protocol) defaultPort() uint16 {
	switch p {
	case ProtocolDoT, ProtocolDoQ:
		return 853
	case ProtocolDoH:
		return 443
	default:
		return 53
	}
}

func protocolError(protocol Protocol, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("DNS %s %s: %w", protocol, operation, err)
}
