package dnsobs

import "time"

const (
	SchemaV1                  = "dns-observation/v1"
	AgentCapabilityObserveV1  = "dns_observe_v1"
	EventKindDNSObservation   = "dns_observation"
	DefaultEDNSUDPSize        = 1232
	DefaultParallel           = 4
	MaxParallel               = 16
	DefaultAttemptTimeoutMS   = 2000
	MinAttemptTimeoutMS       = 100
	MaxAttemptTimeoutMS       = 10000
	DefaultMaxAttempts        = 3
	MaxAttempts               = 3
	MaxOperations             = 128
	DefaultSectionRecordLimit = 64
	MaxSectionRecordLimit     = 128
	MaxAliasChainDepth        = 32
	MaxObservationBytes       = 64 << 10
	MaxTaskResultBytes        = 2 << 20
	MaxEventBytes             = 256 << 10
	RRSetFingerprintAlgorithm = "sha256"
	RRSetFingerprintVersion   = "dns-observation/rrset/v1"
	MaxIdentifierBytes        = 128
	MaxErrorMessageBytes      = 512
	MaxRDataBytes             = 16 << 10
	MaxEDNSOptions            = 64
	MaxExtendedDNSErrors      = 32
)

type Mode string

const (
	ModeRecursive     Mode = "recursive"
	ModeIterative     Mode = "iterative"
	ModeAuthoritative Mode = "authoritative"
)

func (m Mode) Valid() bool {
	switch m {
	case ModeRecursive, ModeIterative, ModeAuthoritative:
		return true
	default:
		return false
	}
}

type EndpointKind string

const (
	EndpointSystem          EndpointKind = "system"
	EndpointCatalog         EndpointKind = "catalog"
	EndpointPublicAnycast   EndpointKind = "public_anycast"
	EndpointParentAuthority EndpointKind = "parent_authority"
	EndpointChildAuthority  EndpointKind = "child_authority"
	EndpointRootHints       EndpointKind = "root_hints"
)

func (k EndpointKind) Valid() bool {
	switch k {
	case EndpointSystem, EndpointCatalog, EndpointPublicAnycast, EndpointParentAuthority, EndpointChildAuthority, EndpointRootHints:
		return true
	default:
		return false
	}
}

type Protocol string

const (
	ProtocolUDP Protocol = "udp"
	ProtocolTCP Protocol = "tcp"
	ProtocolDoT Protocol = "dot"
	ProtocolDoH Protocol = "doh"
	ProtocolDoQ Protocol = "doq"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolUDP, ProtocolTCP, ProtocolDoT, ProtocolDoH, ProtocolDoQ:
		return true
	default:
		return false
	}
}

func (p Protocol) DefaultPort() int {
	switch p {
	case ProtocolDoT, ProtocolDoQ:
		return 853
	case ProtocolDoH:
		return 443
	default:
		return 53
	}
}

type DNSClass string

const DNSClassIN DNSClass = "IN"

func (c DNSClass) Valid() bool {
	return c == DNSClassIN
}

type RRType string

const (
	RRTypeA          RRType = "A"
	RRTypeAAAA       RRType = "AAAA"
	RRTypeCNAME      RRType = "CNAME"
	RRTypeMX         RRType = "MX"
	RRTypeTXT        RRType = "TXT"
	RRTypeNS         RRType = "NS"
	RRTypeSOA        RRType = "SOA"
	RRTypeCAA        RRType = "CAA"
	RRTypeSRV        RRType = "SRV"
	RRTypePTR        RRType = "PTR"
	RRTypeDS         RRType = "DS"
	RRTypeDNSKEY     RRType = "DNSKEY"
	RRTypeTLSA       RRType = "TLSA"
	RRTypeSVCB       RRType = "SVCB"
	RRTypeHTTPS      RRType = "HTTPS"
	RRTypeDNAME      RRType = "DNAME"
	RRTypeRRSIG      RRType = "RRSIG"
	RRTypeNSEC       RRType = "NSEC"
	RRTypeNSEC3      RRType = "NSEC3"
	RRTypeNSEC3PARAM RRType = "NSEC3PARAM"
	RRTypeOPT        RRType = "OPT"
)

var supportedQueryTypes = [...]RRType{
	RRTypeA,
	RRTypeAAAA,
	RRTypeCNAME,
	RRTypeMX,
	RRTypeTXT,
	RRTypeNS,
	RRTypeSOA,
	RRTypeCAA,
	RRTypeSRV,
	RRTypePTR,
	RRTypeDS,
	RRTypeDNSKEY,
	RRTypeTLSA,
	RRTypeSVCB,
	RRTypeHTTPS,
}

func (t RRType) SupportedQuery() bool {
	for _, supported := range supportedQueryTypes {
		if t == supported {
			return true
		}
	}
	return false
}

func SupportedQueryTypes() []RRType {
	result := make([]RRType, len(supportedQueryTypes))
	copy(result, supportedQueryTypes[:])
	return result
}

type TransportStatus string

const (
	TransportSuccess      TransportStatus = "success"
	TransportTimeout      TransportStatus = "timeout"
	TransportRefused      TransportStatus = "refused"
	TransportNetworkError TransportStatus = "network_error"
	TransportCancelled    TransportStatus = "cancelled"
)

func (s TransportStatus) Valid() bool {
	switch s {
	case TransportSuccess, TransportTimeout, TransportRefused, TransportNetworkError, TransportCancelled:
		return true
	default:
		return false
	}
}

type DNSOutcome string

const (
	DNSOutcomeAnswer            DNSOutcome = "answer"
	DNSOutcomeNoData            DNSOutcome = "nodata"
	DNSOutcomeNXDomain          DNSOutcome = "nxdomain"
	DNSOutcomeServFail          DNSOutcome = "servfail"
	DNSOutcomeRefused           DNSOutcome = "refused"
	DNSOutcomeReferral          DNSOutcome = "referral"
	DNSOutcomeRCodeError        DNSOutcome = "rcode_error"
	DNSOutcomeMalformed         DNSOutcome = "malformed"
	DNSOutcomeNotObserved       DNSOutcome = "not_observed"
	DNSOutcomeTruncatedResponse DNSOutcome = "truncated_response"
)

func (o DNSOutcome) Valid() bool {
	switch o {
	case DNSOutcomeAnswer, DNSOutcomeNoData, DNSOutcomeNXDomain, DNSOutcomeServFail, DNSOutcomeRefused, DNSOutcomeReferral, DNSOutcomeRCodeError, DNSOutcomeMalformed, DNSOutcomeNotObserved, DNSOutcomeTruncatedResponse:
		return true
	default:
		return false
	}
}

type Comparison string

const (
	ComparisonMatchExpected Comparison = "match_expected"
	ComparisonMatchPrevious Comparison = "match_previous"
	ComparisonMixed         Comparison = "mixed"
	ComparisonDivergent     Comparison = "divergent"
	ComparisonUnknown       Comparison = "unknown"
)

func (c Comparison) Valid() bool {
	switch c {
	case ComparisonMatchExpected, ComparisonMatchPrevious, ComparisonMixed, ComparisonDivergent, ComparisonUnknown:
		return true
	default:
		return false
	}
}

type DNSSECStatus string

const (
	DNSSECSecure        DNSSECStatus = "secure"
	DNSSECInsecure      DNSSECStatus = "insecure"
	DNSSECBogus         DNSSECStatus = "bogus"
	DNSSECIndeterminate DNSSECStatus = "indeterminate"
)

func (s DNSSECStatus) Valid() bool {
	switch s {
	case DNSSECSecure, DNSSECInsecure, DNSSECBogus, DNSSECIndeterminate:
		return true
	default:
		return false
	}
}

type NSState string

const (
	NSStateRegistrarPending          NSState = "registrar_pending"
	NSStateAuthoritativeInconsistent NSState = "authoritative_inconsistent"
	NSStateLameDelegation            NSState = "lame_delegation"
	NSStatePropagating               NSState = "propagating"
	NSStateSampleFullySynced         NSState = "sample_fully_synced"
	NSStateIncomplete                NSState = "incomplete"
)

func (s NSState) Valid() bool {
	switch s {
	case NSStateRegistrarPending, NSStateAuthoritativeInconsistent, NSStateLameDelegation, NSStatePropagating, NSStateSampleFullySynced, NSStateIncomplete:
		return true
	default:
		return false
	}
}

type Request struct {
	Schema     string      `json:"schema"`
	RoundID    string      `json:"round_id"`
	Operations []Operation `json:"operations"`
	Limits     Limits      `json:"limits"`
}

type BatchResult struct {
	Schema       string        `json:"schema"`
	RoundID      string        `json:"round_id"`
	Observations []Observation `json:"observations"`
}

type Operation struct {
	OperationID string     `json:"operation_id"`
	Mode        Mode       `json:"mode"`
	Question    Question   `json:"question"`
	Endpoint    Endpoint   `json:"endpoint"`
	Flags       QueryFlags `json:"flags"`
}

type Question struct {
	Name  string   `json:"name"`
	Type  RRType   `json:"type"`
	Class DNSClass `json:"class"`
}

type Endpoint struct {
	Kind          EndpointKind `json:"kind"`
	Protocol      Protocol     `json:"protocol"`
	ConnectIP     string       `json:"connect_ip"`
	ServerName    string       `json:"server_name"`
	HTTPAuthority string       `json:"http_authority,omitempty"`
	Port          int          `json:"port"`
	HTTPPath      string       `json:"http_path,omitempty"`
}

type QueryFlags struct {
	RecursionDesired bool `json:"rd"`
	CheckingDisabled bool `json:"cd"`
	DNSSECOK         bool `json:"do"`
	EDNSUDPSize      int  `json:"edns_udp_size"`
}

type Limits struct {
	Parallel         int `json:"parallel"`
	AttemptTimeoutMS int `json:"attempt_timeout_ms"`
	MaxAttempts      int `json:"max_attempts"`
}

type Observation struct {
	Schema            string            `json:"schema"`
	RoundID           string            `json:"round_id"`
	OperationID       string            `json:"operation_id"`
	Question          Question          `json:"question"`
	Endpoint          Endpoint          `json:"endpoint"`
	TransportStatus   TransportStatus   `json:"transport_status"`
	AttemptCount      int               `json:"attempt_count"`
	Attempts          []WireAttempt     `json:"attempts"`
	ResponseAttempt   int               `json:"response_attempt"`
	PeerIP            string            `json:"peer_ip,omitempty"`
	Protocol          Protocol          `json:"protocol"`
	UDPToTCPFallback  bool              `json:"udp_to_tcp_fallback"`
	StartedAt         time.Time         `json:"started_at"`
	ObservedAt        time.Time         `json:"observed_at"`
	FinishedAt        time.Time         `json:"finished_at"`
	DurationMS        int64             `json:"duration_ms"`
	RCode             *uint8            `json:"rcode,omitempty"`
	ExtendedRCode     *uint8            `json:"extended_rcode,omitempty"`
	Flags             DNSFlags          `json:"flags"`
	EDNS              EDNS              `json:"edns"`
	Outcome           DNSOutcome        `json:"dns_outcome"`
	Comparison        Comparison        `json:"comparison,omitempty"`
	DNSSEC            DNSSECResult      `json:"dnssec"`
	Sections          Sections          `json:"sections"`
	AliasChain        AliasChain        `json:"alias_chain"`
	NegativeTTL       *uint32           `json:"negative_ttl,omitempty"`
	ResponseTruncated bool              `json:"response_truncated"`
	ResultTruncated   bool              `json:"result_truncated"`
	ResponseSizeBytes int               `json:"response_size_bytes,omitempty"`
	Error             *ObservationError `json:"error,omitempty"`
}

// WireAttempt is the bounded, public transport transcript for one physical DNS
// exchange. It deliberately excludes raw error messages and DNS packet bytes.
type WireAttempt struct {
	Protocol          Protocol        `json:"protocol"`
	TransportStatus   TransportStatus `json:"transport_status"`
	StartedAt         time.Time       `json:"started_at"`
	FinishedAt        time.Time       `json:"finished_at"`
	DurationMS        int64           `json:"duration_ms"`
	PeerIP            string          `json:"peer_ip,omitempty"`
	ResponseSizeBytes int             `json:"response_size_bytes"`
	ResponseTruncated bool            `json:"response_truncated"`
	Error             *AttemptError   `json:"error,omitempty"`
}

// AttemptError is intentionally message-free so an observation cannot expose
// per-attempt network or platform details.
type AttemptError struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

func (o Observation) FullRCode() (uint16, bool) {
	if o.RCode == nil {
		return 0, false
	}
	extended := uint16(0)
	if o.ExtendedRCode != nil {
		extended = uint16(*o.ExtendedRCode)
	}
	return extended<<4 | uint16(*o.RCode&0x0f), true
}

type DNSFlags struct {
	Response           bool `json:"qr"`
	Authoritative      bool `json:"aa"`
	Truncated          bool `json:"tc"`
	RecursionDesired   bool `json:"rd"`
	RecursionAvailable bool `json:"ra"`
	ReservedZ          bool `json:"z"`
	AuthenticData      bool `json:"ad"`
	CheckingDisabled   bool `json:"cd"`
}

type EDNS struct {
	Present  bool               `json:"present"`
	UDPSize  int                `json:"udp_size,omitempty"`
	Version  uint8              `json:"version,omitempty"`
	Flags    uint16             `json:"flags,omitempty"`
	DNSSECOK bool               `json:"do"`
	ECS      *ClientSubnet      `json:"ecs,omitempty"`
	EDE      []ExtendedDNSError `json:"ede,omitempty"`
	NSIDHex  string             `json:"nsid_hex,omitempty"`
	Options  []EDNSOption       `json:"options,omitempty"`
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

type EDNSOption struct {
	Code       uint16 `json:"code"`
	DataBase64 string `json:"data_base64"`
}

type DNSSECResult struct {
	Status           DNSSECStatus `json:"status"`
	LocallyValidated bool         `json:"locally_validated"`
	ReasonCode       string       `json:"reason_code,omitempty"`
}

type Sections struct {
	Answer     []ResourceRecord `json:"answer"`
	Authority  []ResourceRecord `json:"authority"`
	Additional []ResourceRecord `json:"additional"`
}

func (s Sections) RecordCount() int {
	return len(s.Answer) + len(s.Authority) + len(s.Additional)
}

type ResourceRecord struct {
	Owner            string   `json:"owner"`
	Type             RRType   `json:"type"`
	Class            DNSClass `json:"class"`
	TTL              uint32   `json:"ttl"`
	DisplayRData     string   `json:"display_rdata"`
	CanonicalRData   string   `json:"canonical_rdata"`
	RRSetRecordCount int      `json:"rrset_record_count"`
	RRSetFingerprint string   `json:"rrset_fingerprint,omitempty"`
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
	Type RRType `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

type ObservationError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
