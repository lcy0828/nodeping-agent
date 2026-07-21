package dnsengine

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type SelfCheckReason string

const (
	SelfCheckReady            SelfCheckReason = "ready"
	SelfCheckListenerFailed   SelfCheckReason = "listener_failed"
	SelfCheckEngineFailed     SelfCheckReason = "engine_init_failed"
	SelfCheckExchangeFailed   SelfCheckReason = "exchange_failed"
	SelfCheckEvidenceMismatch SelfCheckReason = "evidence_mismatch"
	SelfCheckDeadlineExceeded SelfCheckReason = "deadline_exceeded"
)

type SelfCheckResult struct {
	Ready      bool
	ReasonCode SelfCheckReason
}

// SelfCheck exercises the production UDP-to-TCP observation path against a
// private local fixture. It never depends on public DNS or external network
// availability.
func SelfCheck(ctx context.Context) SelfCheckResult {
	if ctx == nil {
		return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
	}
	if err := ctx.Err(); err != nil {
		return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
	}

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return SelfCheckResult{ReasonCode: SelfCheckListenerFailed}
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConnection, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return SelfCheckResult{ReasonCode: SelfCheckListenerFailed}
	}
	defer udpConnection.Close()

	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		if strings.HasPrefix(writer.LocalAddr().Network(), "udp") {
			response.Truncated = true
			_ = writer.WriteMsg(response)
			return
		}
		if len(request.Question) == 1 && request.Question[0].Name == selfCheckName && request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: selfCheckName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			}}
		}
		_ = writer.WriteMsg(response)
	})
	udpServer := &dns.Server{PacketConn: udpConnection, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	serverErrors := make(chan error, 2)
	go func() { serverErrors <- udpServer.ActivateAndServe() }()
	go func() { serverErrors <- tcpServer.ActivateAndServe() }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = udpServer.ShutdownContext(shutdownCtx)
		_ = tcpServer.ShutdownContext(shutdownCtx)
	}()

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
	}
	timeout := min(remaining, time.Second)
	engine, err := New(Config{Timeout: timeout, AllowPrivateConnectIP: true})
	if err != nil {
		return SelfCheckResult{ReasonCode: SelfCheckEngineFailed}
	}
	result, exchangeErr := engine.Observe(ctx, Endpoint{
		Protocol: ProtocolUDP, Address: "fixture.nodeping.invalid", ConnectIP: "127.0.0.1", Port: uint16(port),
	}, Query{Name: selfCheckName, Type: dns.TypeA, RecursionDesired: true, DNSSECOK: true})
	if exchangeErr != nil {
		if errors.Is(exchangeErr, context.Canceled) || errors.Is(exchangeErr, context.DeadlineExceeded) || ctx.Err() != nil {
			return SelfCheckResult{ReasonCode: SelfCheckDeadlineExceeded}
		}
		select {
		case serverErr := <-serverErrors:
			if serverErr != nil {
				return SelfCheckResult{ReasonCode: SelfCheckExchangeFailed}
			}
		default:
		}
		return SelfCheckResult{ReasonCode: SelfCheckExchangeFailed}
	}
	if !validSelfCheckResult(result) {
		return SelfCheckResult{ReasonCode: SelfCheckEvidenceMismatch}
	}
	return SelfCheckResult{Ready: true, ReasonCode: SelfCheckReady}
}

const selfCheckName = "fixture.nodeping.invalid."

func validSelfCheckResult(result *Result) bool {
	if result == nil || !result.ResponseParsed || result.ResponseHeaderValidated || !result.UDPToTCPFallback ||
		result.Outcome != OutcomeAnswer || len(result.Attempts) != 2 ||
		result.Attempts[0].Protocol != ProtocolUDP || !result.Attempts[0].Truncated ||
		result.Attempts[1].Protocol != ProtocolTCP || len(result.Sections.Answer) != 1 {
		return false
	}
	record := result.Sections.Answer[0]
	return record.Owner == selfCheckName && record.Type == "A" && record.Class == "IN" && record.DisplayRData == "192.0.2.1"
}
