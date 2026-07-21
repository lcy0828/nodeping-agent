package dnstapcollector

import "time"

const ContentType = "protobuf:dnstap.Dnstap"

type CollectionStatus string

const (
	CollectionComplete         CollectionStatus = "complete"
	CollectionCancelled        CollectionStatus = "cancelled"
	CollectionDeadlineExceeded CollectionStatus = "deadline_exceeded"
	CollectionLimitExceeded    CollectionStatus = "limit_exceeded"
	CollectionProtocolError    CollectionStatus = "protocol_error"
	CollectionIOError          CollectionStatus = "io_error"
)

type ErrorCode string

const (
	ErrorHandshakeFailed    ErrorCode = "HANDSHAKE_FAILED"
	ErrorContentType        ErrorCode = "CONTENT_TYPE_MISMATCH"
	ErrorUnexpectedEOF      ErrorCode = "UNEXPECTED_EOF"
	ErrorInvalidControlFlow ErrorCode = "INVALID_CONTROL_FLOW"
	ErrorFrameTooLarge      ErrorCode = "FRAME_TOO_LARGE"
	ErrorEventLimit         ErrorCode = "EVENT_LIMIT_EXCEEDED"
	ErrorByteLimit          ErrorCode = "BYTE_LIMIT_EXCEEDED"
	ErrorOutstandingLimit   ErrorCode = "OUTSTANDING_QUERY_LIMIT_EXCEEDED"
	ErrorInvalidDNSTap      ErrorCode = "INVALID_DNSTAP_EVENT"
	ErrorReadFailed         ErrorCode = "READ_FAILED"
	ErrorCancelled          ErrorCode = "CANCELLED"
	ErrorDeadlineExceeded   ErrorCode = "DEADLINE_EXCEEDED"
)

type CollectionError struct {
	Code    ErrorCode
	Message string
}

type EventKind string

const (
	EventResolverQuery    EventKind = "resolver_query"
	EventResolverResponse EventKind = "resolver_response"
)

type SocketFamily string

const (
	FamilyIPv4 SocketFamily = "ipv4"
	FamilyIPv6 SocketFamily = "ipv6"
)

type SocketProtocol string

const (
	ProtocolUDP SocketProtocol = "udp"
	ProtocolTCP SocketProtocol = "tcp"
)

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type Event struct {
	Sequence     uint64
	Kind         EventKind
	Family       SocketFamily
	Protocol     SocketProtocol
	LocalIP      string
	LocalPort    uint16
	UpstreamIP   string
	UpstreamPort uint16
	QueryTime    time.Time
	ResponseTime time.Time
	QueryZone    string
	DNSID        uint16
	Question     Question
	QueryWire    []byte
	ResponseWire []byte
	FrameBytes   int
}

type PairStatus string

const (
	PairMatched        PairStatus = "matched"
	PairNoResponse     PairStatus = "no_response"
	PairOrphanResponse PairStatus = "orphan_response"
	PairAmbiguous      PairStatus = "ambiguous"
)

type PairingIntegrity string

const (
	PairingExact        PairingIntegrity = "exact"
	PairingHasOrphans   PairingIntegrity = "has_orphans"
	PairingHasAmbiguity PairingIntegrity = "has_ambiguity"
)

type Exchange struct {
	Status                  PairStatus
	QuerySequence           uint64
	ResponseSequence        uint64
	CandidateQuerySequences []uint64
	StartedAt               time.Time
	FinishedAt              time.Time
	Duration                time.Duration
}

type PairingSummary struct {
	Integrity       PairingIntegrity
	Matched         int
	NoResponse      int
	OrphanResponses int
	Ambiguous       int
}

type Result struct {
	Status     CollectionStatus
	Complete   bool
	StartedAt  time.Time
	FinishedAt time.Time
	FrameCount int
	FrameBytes int64
	Events     []Event
	Exchanges  []Exchange
	Pairing    PairingSummary
	Error      *CollectionError
}
