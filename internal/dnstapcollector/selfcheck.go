package dnstapcollector

import (
	"context"
	"net"
	"net/netip"
	"time"

	dnstappb "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

const (
	SelfCheckReady            = "ready"
	SelfCheckListenerFailed   = "listener_failed"
	SelfCheckAcceptFailed     = "accept_failed"
	SelfCheckProducerFailed   = "producer_failed"
	SelfCheckCollectionFailed = "collection_failed"
	SelfCheckEvidenceMismatch = "evidence_mismatch"
	SelfCheckDeadlineExceeded = "deadline_exceeded"
	selfCheckTimeout          = 3 * time.Second
)

type SelfCheckResult struct {
	Ready      bool
	ReasonCode string
}

func SelfCheck(ctx context.Context, baseDir string) SelfCheckResult {
	if ctx == nil {
		return SelfCheckResult{ReasonCode: SelfCheckCollectionFailed}
	}
	checkCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	listener, err := OpenListener(baseDir)
	if err != nil {
		return SelfCheckResult{ReasonCode: SelfCheckListenerFailed}
	}
	defer listener.Close()

	accepted := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept(checkCtx)
		accepted <- acceptResult{connection: connection, err: acceptErr}
	}()
	producer, err := (&net.Dialer{}).DialContext(checkCtx, listener.Network(), listener.Endpoint())
	if err != nil {
		return selfCheckFailure(checkCtx, SelfCheckProducerFailed)
	}
	defer producer.Close()
	accept := <-accepted
	if accept.err != nil {
		return selfCheckFailure(checkCtx, SelfCheckAcceptFailed)
	}
	defer accept.connection.Close()

	collected := make(chan Result, 1)
	go func() {
		collected <- NewDefault().Collect(checkCtx, accept.connection)
	}()
	writer, err := framestream.NewWriter(producer, &framestream.WriterOptions{
		ContentTypes: [][]byte{[]byte(ContentType)}, Bidirectional: true,
		Timeout: DefaultLimits().HandshakeTimeout,
	})
	if err != nil {
		return selfCheckFailure(checkCtx, SelfCheckProducerFailed)
	}
	queryFrame, responseFrame, err := selfCheckFrames(time.Now().UTC())
	if err == nil {
		_, err = writer.WriteFrame(queryFrame)
	}
	if err == nil {
		_, err = writer.WriteFrame(responseFrame)
	}
	if err == nil {
		err = writer.Flush()
	}
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return selfCheckFailure(checkCtx, SelfCheckProducerFailed)
	}
	result := <-collected
	if !result.Complete || result.Status != CollectionComplete {
		return selfCheckFailure(checkCtx, SelfCheckCollectionFailed)
	}
	if len(result.Events) != 2 || len(result.Exchanges) != 1 ||
		result.Exchanges[0].Status != PairMatched || result.Pairing.Integrity != PairingExact {
		return SelfCheckResult{ReasonCode: SelfCheckEvidenceMismatch}
	}
	return SelfCheckResult{Ready: true, ReasonCode: SelfCheckReady}
}

type acceptResult struct {
	connection net.Conn
	err        error
}

func selfCheckFailure(ctx context.Context, reason string) SelfCheckResult {
	if ctx.Err() != nil {
		return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
	}
	return SelfCheckResult{ReasonCode: reason}
}

func selfCheckFrames(queryTime time.Time) ([]byte, []byte, error) {
	query := new(dns.Msg)
	query.SetQuestion("collector-self-check.nodeping.invalid.", dns.TypeA)
	query.Id = 0x4e50
	query.RecursionDesired = false
	queryWire, err := query.Pack()
	if err != nil {
		return nil, nil, err
	}
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	responseWire, err := response.Pack()
	if err != nil {
		return nil, nil, err
	}
	zone := make([]byte, 255)
	zoneLength, err := dns.PackDomainName("invalid.", zone, 0, nil, false)
	if err != nil {
		return nil, nil, err
	}
	querySeconds := uint64(queryTime.Unix())
	queryNanoseconds := uint32(queryTime.Nanosecond())
	responseTime := queryTime.Add(time.Millisecond)
	responseSeconds := uint64(responseTime.Unix())
	responseNanoseconds := uint32(responseTime.Nanosecond())
	base := dnstappb.Message{
		SocketFamily:    dnstappb.SocketFamily_INET.Enum(),
		SocketProtocol:  dnstappb.SocketProtocol_UDP.Enum(),
		QueryAddress:    netip.MustParseAddr("0.0.0.0").AsSlice(),
		ResponseAddress: netip.MustParseAddr("192.0.2.53").AsSlice(),
		QueryPort:       proto.Uint32(53000), ResponsePort: proto.Uint32(53),
		QueryTimeSec: &querySeconds, QueryTimeNsec: &queryNanoseconds,
		QueryZone: zone[:zoneLength],
	}
	queryMessage := proto.Clone(&base).(*dnstappb.Message)
	queryMessage.Type = dnstappb.Message_RESOLVER_QUERY.Enum()
	queryMessage.QueryMessage = queryWire
	responseMessage := proto.Clone(&base).(*dnstappb.Message)
	responseMessage.Type = dnstappb.Message_RESOLVER_RESPONSE.Enum()
	responseMessage.QueryMessage = queryWire
	responseMessage.ResponseTimeSec = &responseSeconds
	responseMessage.ResponseTimeNsec = &responseNanoseconds
	responseMessage.ResponseMessage = responseWire
	queryFrame, err := proto.Marshal(&dnstappb.Dnstap{Type: dnstappb.Dnstap_MESSAGE.Enum(), Message: queryMessage})
	if err != nil {
		return nil, nil, err
	}
	responseFrame, err := proto.Marshal(&dnstappb.Dnstap{Type: dnstappb.Dnstap_MESSAGE.Enum(), Message: responseMessage})
	if err != nil {
		return nil, nil, err
	}
	return queryFrame, responseFrame, nil
}
