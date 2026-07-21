package dnsengine

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"reflect"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

func (e *Engine) buildQuery(query Query, protocol Protocol) (*dns.Msg, error) {
	if query.Type == 0 {
		return nil, fmt.Errorf("%w: type is required", ErrInvalidQuery)
	}
	if query.AuthenticatedData {
		return nil, fmt.Errorf("%w: AD is not a supported query flag", ErrInvalidQuery)
	}
	mode := query.Mode
	if mode == "" {
		mode = QueryModeRecursive
	}
	if !mode.valid() {
		return nil, fmt.Errorf("%w: unsupported query mode %q", ErrInvalidQuery, query.Mode)
	}
	if mode != QueryModeRecursive && query.RecursionDesired {
		return nil, fmt.Errorf("%w: iterative and authoritative query modes must not set RD", ErrInvalidQuery)
	}
	class := query.Class
	if class == 0 {
		class = dns.ClassINET
	}
	question, err := normalizeWireQuestion(dns.Question{Name: query.Name, Qtype: query.Type, Qclass: class})
	if err != nil {
		return nil, err
	}
	id := uint16(0)
	if protocol != ProtocolDoQ {
		var err error
		id, err = e.idGenerator()
		if err != nil {
			return nil, fmt.Errorf("generate DNS message ID: %w", err)
		}
	}
	message := new(dns.Msg)
	message.Id = id
	message.Opcode = dns.OpcodeQuery
	message.RecursionDesired = query.RecursionDesired
	message.CheckingDisabled = query.CheckingDisabled
	message.Question = []dns.Question{question}
	message.SetEdns0(e.udpSize, query.DNSSECOK)
	return message, nil
}

func (e *Engine) prepareMessage(message *dns.Msg, protocol Protocol) (*dns.Msg, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: message is nil", ErrInvalidQuery)
	}
	if err := validateQuerySections(message); err != nil {
		return nil, err
	}
	query := message.Copy()
	if query.Response || query.Opcode != dns.OpcodeQuery {
		return nil, fmt.Errorf("%w: only standard queries are supported", ErrInvalidQuery)
	}
	if query.Authoritative || query.Truncated || query.RecursionAvailable || query.Zero || query.AuthenticatedData || query.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%w: unsupported query header flags", ErrInvalidQuery)
	}
	if len(query.Question) != 1 {
		return nil, fmt.Errorf("%w: exactly one question is required", ErrInvalidQuery)
	}
	question, err := normalizeWireQuestion(query.Question[0])
	if err != nil {
		return nil, err
	}
	query.Question[0] = question
	if len(query.Answer) != 0 || len(query.Ns) != 0 {
		return nil, fmt.Errorf("%w: query answer and authority sections must be empty", ErrInvalidQuery)
	}

	var opt *dns.OPT
	for _, rr := range query.Extra {
		if rr == nil || rr.Header().Rrtype != dns.TypeOPT {
			return nil, fmt.Errorf("%w: query additional section may only contain OPT", ErrInvalidQuery)
		}
		if opt != nil {
			return nil, fmt.Errorf("%w: multiple OPT records", ErrInvalidQuery)
		}
		var ok bool
		opt, ok = rr.(*dns.OPT)
		if !ok {
			return nil, fmt.Errorf("%w: invalid OPT record", ErrInvalidQuery)
		}
		if dns.Fqdn(opt.Hdr.Name) != "." || opt.Version() != 0 || opt.ExtendedRcode() != 0 {
			return nil, fmt.Errorf("%w: invalid query OPT header", ErrInvalidQuery)
		}
		if opt.Co() || opt.Z() != 0 {
			return nil, fmt.Errorf("%w: unsupported query OPT flags", ErrInvalidQuery)
		}
		if len(opt.Option) > MaxEDNSOptions {
			return nil, fmt.Errorf("%w: too many EDNS options", ErrInvalidQuery)
		}
		for _, option := range opt.Option {
			if option == nil {
				return nil, fmt.Errorf("%w: nil EDNS option", ErrInvalidQuery)
			}
			if option.Option() == dns.EDNS0SUBNET && !e.allowECS {
				return nil, ErrECSDisabled
			}
		}
	}
	if opt == nil {
		query.SetEdns0(e.udpSize, false)
	} else {
		opt.SetUDPSize(e.udpSize)
	}
	if protocol == ProtocolDoQ {
		query.Id = 0
	} else {
		id, err := e.idGenerator()
		if err != nil {
			return nil, fmt.Errorf("generate DNS message ID: %w", err)
		}
		query.Id = id
	}
	return query, nil
}

func validateQuerySections(message *dns.Msg) error {
	if len(message.Answer) != 0 || len(message.Ns) != 0 {
		return fmt.Errorf("%w: query answer and authority sections must be empty", ErrInvalidQuery)
	}
	if len(message.Extra) > 1 {
		return fmt.Errorf("%w: multiple OPT records", ErrInvalidQuery)
	}
	for _, rr := range message.Extra {
		if nilInterface(rr) {
			return fmt.Errorf("%w: nil additional record", ErrInvalidQuery)
		}
		opt, ok := rr.(*dns.OPT)
		if !ok || opt == nil {
			return fmt.Errorf("%w: query additional section may only contain OPT", ErrInvalidQuery)
		}
		for _, option := range opt.Option {
			if nilInterface(option) {
				return fmt.Errorf("%w: nil EDNS option", ErrInvalidQuery)
			}
		}
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func normalizeWireQuestion(question dns.Question) (dns.Question, error) {
	if question.Qtype == 0 {
		return dns.Question{}, fmt.Errorf("%w: question type is required", ErrInvalidQuery)
	}
	if question.Qclass != dns.ClassINET {
		return dns.Question{}, fmt.Errorf("%w: only IN class is supported", ErrInvalidQuery)
	}
	normalized, err := dnsobs.NormalizeQuestion(dnsobs.Question{
		Name:  question.Name,
		Type:  dnsobs.RRType(typeName(question.Qtype)),
		Class: dnsobs.DNSClassIN,
	})
	if err != nil {
		return dns.Question{}, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	question.Name = normalized.Name
	return question, nil
}

func secureMessageID() (uint16, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value[:]), nil
}
