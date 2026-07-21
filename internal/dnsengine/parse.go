package dnsengine

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"nodeping/internal/dnsobs"

	"github.com/miekg/dns"
)

func unpackResponse(wire []byte) (*dns.Msg, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("%w: response is %d bytes", ErrMalformedResponse, len(wire))
	}
	if err := validateDNSWireConsumption(wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	message := new(dns.Msg)
	if err := message.Unpack(wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	return message, nil
}

func validateDNSWireConsumption(wire []byte) error {
	counts := [...]uint16{
		binary.BigEndian.Uint16(wire[4:6]),
		binary.BigEndian.Uint16(wire[6:8]),
		binary.BigEndian.Uint16(wire[8:10]),
		binary.BigEndian.Uint16(wire[10:12]),
	}
	offset := 12
	for range int(counts[0]) {
		_, next, err := dns.UnpackDomainName(wire, offset)
		if err != nil || next <= offset || next+4 > len(wire) {
			return fmt.Errorf("question section does not match its header count")
		}
		offset = next + 4
	}
	for section := 1; section < len(counts); section++ {
		for range int(counts[section]) {
			headerOffset, err := unpackRawDNSName(wire, offset, len(wire), true)
			if err != nil || headerOffset+10 > len(wire) {
				return fmt.Errorf("resource-record section does not match its header count")
			}
			rrType := binary.BigEndian.Uint16(wire[headerOffset : headerOffset+2])
			rdataStart := headerOffset + 10
			rdataLength := int(binary.BigEndian.Uint16(wire[headerOffset+8 : rdataStart]))
			rdataEnd := rdataStart + rdataLength
			if rdataEnd < rdataStart || rdataEnd > len(wire) {
				return fmt.Errorf("resource-record RDATA exceeds the DNS message")
			}
			if auditedResponseWireType(rrType) {
				if err := validateAuditedRawRData(wire, rrType, rdataStart, rdataEnd); err != nil {
					return fmt.Errorf("invalid raw TYPE%d RDATA: %w", rrType, err)
				}
			}
			_, next, err := dns.UnpackRR(wire, offset)
			if err != nil || next != rdataEnd {
				return fmt.Errorf("resource-record section does not match its header count")
			}
			offset = next
		}
	}
	if offset != len(wire) {
		return fmt.Errorf("DNS response contains %d trailing bytes", len(wire)-offset)
	}
	return nil
}

func validateAuditedRawRData(wire []byte, rrType uint16, start, end int) error {
	if start < 0 || start >= end || end > len(wire) {
		return fmt.Errorf("RDATA must not be empty")
	}
	length := end - start
	switch rrType {
	case dns.TypeA:
		return requireRawRDataLength(length, 4)
	case dns.TypeAAAA:
		return requireRawRDataLength(length, 16)
	case dns.TypeCNAME, dns.TypeNS, dns.TypePTR:
		return validateRawSingleName(wire, start, end, true)
	case dns.TypeDNAME:
		return validateRawSingleName(wire, start, end, false)
	case dns.TypeMX:
		if length < 3 {
			return fmt.Errorf("MX requires a preference and exchange name")
		}
		return validateRawSingleName(wire, start+2, end, true)
	case dns.TypeTXT:
		return validateRawTXT(wire[start:end])
	case dns.TypeSOA:
		cursor, err := unpackRawDNSName(wire, start, end, true)
		if err != nil {
			return fmt.Errorf("SOA MNAME: %w", err)
		}
		cursor, err = unpackRawDNSName(wire, cursor, end, true)
		if err != nil {
			return fmt.Errorf("SOA RNAME: %w", err)
		}
		if end-cursor != 20 {
			return fmt.Errorf("SOA requires five complete uint32 fields")
		}
		return nil
	case dns.TypeCAA:
		return validateRawCAA(wire[start:end])
	case dns.TypeSRV:
		if length < 7 {
			return fmt.Errorf("SRV requires priority, weight, port, and target")
		}
		return validateRawSingleName(wire, start+6, end, false)
	case dns.TypeDS:
		if length < 4 {
			return fmt.Errorf("DS fixed fields are incomplete")
		}
		return nil
	case dns.TypeDNSKEY:
		if length < 4 {
			return fmt.Errorf("DNSKEY fixed fields are incomplete")
		}
		return nil
	case dns.TypeTLSA:
		if length < 3 {
			return fmt.Errorf("TLSA fixed fields are incomplete")
		}
		return nil
	case dns.TypeRRSIG:
		if length < 19 {
			return fmt.Errorf("RRSIG requires fixed fields and a signer name")
		}
		_, err := unpackRawDNSName(wire, start+18, end, false)
		if err != nil {
			return fmt.Errorf("RRSIG signer name: %w", err)
		}
		return nil
	case dns.TypeNSEC:
		cursor, err := unpackRawDNSName(wire, start, end, false)
		if err != nil {
			return fmt.Errorf("NSEC next domain: %w", err)
		}
		return validateRawTypeBitmap(wire[cursor:end], true)
	case dns.TypeNSEC3:
		return validateRawNSEC3(wire[start:end])
	case dns.TypeNSEC3PARAM:
		return validateRawNSEC3PARAM(wire[start:end])
	case dns.TypeSVCB, dns.TypeHTTPS:
		if length < 3 {
			return fmt.Errorf("SVCB-compatible RDATA requires priority and target")
		}
		cursor, err := unpackRawDNSName(wire, start+2, end, false)
		if err != nil {
			return fmt.Errorf("SVCB-compatible target: %w", err)
		}
		return validateRawSVCBParameters(wire[cursor:end])
	default:
		return fmt.Errorf("TYPE%d is not in the audited response contract", rrType)
	}
}

func requireRawRDataLength(got, want int) error {
	if got != want {
		return fmt.Errorf("RDATA length is %d, want %d", got, want)
	}
	return nil
}

func validateRawSingleName(wire []byte, start, end int, allowCompression bool) error {
	next, err := unpackRawDNSName(wire, start, end, allowCompression)
	if err != nil {
		return err
	}
	if next != end {
		return fmt.Errorf("domain name does not consume the complete RDATA")
	}
	return nil
}

func unpackRawDNSName(wire []byte, start, end int, allowCompression bool) (int, error) {
	if start < 0 || start >= end || end > len(wire) {
		return 0, fmt.Errorf("domain name is missing")
	}
	_, next, err := dns.UnpackDomainName(wire, start)
	if err != nil || next <= start || next > end {
		return 0, fmt.Errorf("domain name exceeds its field boundary")
	}
	for cursor := start; ; {
		if cursor >= next {
			return 0, fmt.Errorf("domain name has no terminating root label or pointer")
		}
		labelLength := wire[cursor]
		switch {
		case labelLength == 0:
			if cursor+1 != next {
				return 0, fmt.Errorf("domain name has trailing encoded bytes")
			}
			return next, nil
		case labelLength&0xc0 == 0xc0:
			if !allowCompression {
				return 0, fmt.Errorf("DNS name compression is forbidden for this field")
			}
			if cursor+2 != next {
				return 0, fmt.Errorf("compression pointer does not terminate the domain name")
			}
			target := int(labelLength&0x3f)<<8 | int(wire[cursor+1])
			if target >= cursor {
				return 0, fmt.Errorf("compression pointer must refer to an earlier name")
			}
			return next, nil
		case labelLength&0xc0 != 0:
			return 0, fmt.Errorf("domain name contains an unsupported label type")
		case labelLength > 63 || cursor+1+int(labelLength) > next:
			return 0, fmt.Errorf("domain label exceeds its encoded boundary")
		default:
			cursor += 1 + int(labelLength)
		}
	}
}

func validateRawTXT(rdata []byte) error {
	if len(rdata) == 0 {
		return fmt.Errorf("TXT requires at least one character-string")
	}
	for cursor := 0; cursor < len(rdata); {
		length := int(rdata[cursor])
		cursor++
		if cursor+length > len(rdata) {
			return fmt.Errorf("TXT character-string exceeds RDATA")
		}
		cursor += length
	}
	return nil
}

func validateRawCAA(rdata []byte) error {
	if len(rdata) < 2 {
		return fmt.Errorf("CAA requires flags and a property tag length")
	}
	tagLength := int(rdata[1])
	if 2+tagLength > len(rdata) {
		return fmt.Errorf("CAA property tag has an invalid length")
	}
	return nil
}

func validateRawNSEC3(rdata []byte) error {
	if len(rdata) < 6 {
		return fmt.Errorf("NSEC3 fixed fields are incomplete")
	}
	cursor := 5
	saltLength := int(rdata[4])
	if cursor+saltLength >= len(rdata) {
		return fmt.Errorf("NSEC3 salt exceeds RDATA or omits hash length")
	}
	cursor += saltLength
	hashLength := int(rdata[cursor])
	cursor++
	if cursor+hashLength > len(rdata) {
		return fmt.Errorf("NSEC3 next hashed owner name has an invalid length")
	}
	cursor += hashLength
	return validateRawTypeBitmap(rdata[cursor:], true)
}

func validateRawNSEC3PARAM(rdata []byte) error {
	if len(rdata) < 5 {
		return fmt.Errorf("NSEC3PARAM fixed fields are incomplete")
	}
	saltLength := int(rdata[4])
	if len(rdata) != 5+saltLength {
		return fmt.Errorf("NSEC3PARAM salt length does not consume the complete RDATA")
	}
	return nil
}

func validateRawTypeBitmap(bitmap []byte, allowEmpty bool) error {
	if len(bitmap) == 0 {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("type bitmap must contain at least one window")
	}
	previousWindow := -1
	for cursor := 0; cursor < len(bitmap); {
		if len(bitmap)-cursor < 2 {
			return fmt.Errorf("type bitmap window header is incomplete")
		}
		window := int(bitmap[cursor])
		length := int(bitmap[cursor+1])
		cursor += 2
		if window <= previousWindow || length < 1 || length > 32 || cursor+length > len(bitmap) {
			return fmt.Errorf("type bitmap window has an invalid order or length")
		}
		if bitmap[cursor+length-1] == 0 {
			return fmt.Errorf("type bitmap window contains a trailing zero octet")
		}
		cursor += length
		previousWindow = window
	}
	return nil
}

func validateRawSVCBParameters(parameters []byte) error {
	previousKey := -1
	for cursor := 0; cursor < len(parameters); {
		if len(parameters)-cursor < 4 {
			return fmt.Errorf("SvcParam header is incomplete")
		}
		key := int(binary.BigEndian.Uint16(parameters[cursor : cursor+2]))
		length := int(binary.BigEndian.Uint16(parameters[cursor+2 : cursor+4]))
		cursor += 4
		if key == 65535 || key <= previousKey {
			return fmt.Errorf("SvcParam keys must be unique, non-reserved, and strictly increasing")
		}
		if cursor+length > len(parameters) {
			return fmt.Errorf("SvcParam value exceeds RDATA")
		}
		if err := validateRawSVCBParameterValue(uint16(key), parameters[cursor:cursor+length]); err != nil {
			return err
		}
		cursor += length
		previousKey = key
	}
	return nil
}

func validateRawSVCBParameterValue(key uint16, value []byte) error {
	switch dns.SVCBKey(key) {
	case dns.SVCB_MANDATORY:
		if len(value) < 2 || len(value)%2 != 0 {
			return fmt.Errorf("mandatory SvcParam must contain one or more uint16 keys")
		}
		previous := -1
		for cursor := 0; cursor < len(value); cursor += 2 {
			listedKey := int(binary.BigEndian.Uint16(value[cursor : cursor+2]))
			if listedKey == int(dns.SVCB_MANDATORY) || listedKey == 65535 || listedKey <= previous {
				return fmt.Errorf("mandatory SvcParam keys must be non-reserved and strictly increasing")
			}
			previous = listedKey
		}
	case dns.SVCB_ALPN:
		if len(value) == 0 {
			return fmt.Errorf("alpn SvcParam must contain at least one protocol ID")
		}
		for cursor := 0; cursor < len(value); {
			length := int(value[cursor])
			cursor++
			if length == 0 || cursor+length > len(value) {
				return fmt.Errorf("alpn SvcParam contains an empty or truncated protocol ID")
			}
			cursor += length
		}
	case dns.SVCB_NO_DEFAULT_ALPN:
		if len(value) != 0 {
			return fmt.Errorf("no-default-alpn SvcParam value must be empty")
		}
	case dns.SVCB_PORT:
		if len(value) != 2 {
			return fmt.Errorf("port SvcParam value must contain one uint16")
		}
	case dns.SVCB_IPV4HINT:
		if len(value) == 0 || len(value)%4 != 0 {
			return fmt.Errorf("ipv4hint SvcParam must contain complete IPv4 addresses")
		}
	case dns.SVCB_ECHCONFIG:
		if err := dnsobs.ValidateSVCBECHConfigList(value); err != nil {
			return fmt.Errorf("ech SvcParam: %w", err)
		}
	case dns.SVCB_IPV6HINT:
		if len(value) == 0 || len(value)%16 != 0 {
			return fmt.Errorf("ipv6hint SvcParam must contain complete IPv6 addresses")
		}
	case dns.SVCB_DOHPATH:
		if err := dnsobs.ValidateSVCBDoHPathTemplate(string(value)); err != nil {
			return fmt.Errorf("dohpath SvcParam: %w", err)
		}
	case dns.SVCB_OHTTP:
		if len(value) != 0 {
			return fmt.Errorf("ohttp SvcParam value must be empty")
		}
	}
	return nil
}

func auditedResponseWireType(rrType uint16) bool {
	switch rrType {
	case dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeNS,
		dns.TypeSOA,
		dns.TypeCAA,
		dns.TypeSRV,
		dns.TypePTR,
		dns.TypeDS,
		dns.TypeDNSKEY,
		dns.TypeTLSA,
		dns.TypeSVCB,
		dns.TypeHTTPS,
		dns.TypeDNAME,
		dns.TypeRRSIG,
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypeNSEC3PARAM:
		return true
	default:
		return false
	}
}

func validateResponse(query, response *dns.Msg) error {
	if !response.Response {
		return fmt.Errorf("%w: QR bit is not set", ErrResponseMismatch)
	}
	if response.Id != query.Id {
		return fmt.Errorf("%w: message ID got %d, want %d", ErrResponseMismatch, response.Id, query.Id)
	}
	if response.Opcode != query.Opcode {
		return fmt.Errorf("%w: opcode got %d, want %d", ErrResponseMismatch, response.Opcode, query.Opcode)
	}
	if len(response.Question) != len(query.Question) {
		return fmt.Errorf("%w: question count got %d, want %d", ErrResponseMismatch, len(response.Question), len(query.Question))
	}
	for index := range query.Question {
		got, want := response.Question[index], query.Question[index]
		if !strings.EqualFold(dns.Fqdn(got.Name), dns.Fqdn(want.Name)) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
			return fmt.Errorf("%w: question got %s/%d/%d, want %s/%d/%d", ErrResponseMismatch, got.Name, got.Qtype, got.Qclass, want.Name, want.Qtype, want.Qclass)
		}
	}
	if err := validateResponseRecords(response, query.Question[0].Qclass); err != nil {
		return err
	}
	return nil
}

func validateTruncatedResponsePrefix(query *dns.Msg, wire []byte) error {
	if len(wire) < 12 {
		return fmt.Errorf("%w: truncated response header is %d bytes", ErrMalformedResponse, len(wire))
	}
	if !wireHasTC(wire) {
		return fmt.Errorf("%w: truncated response prefix does not set TC", ErrResponseMismatch)
	}
	if binary.BigEndian.Uint16(wire[0:2]) != query.Id {
		return fmt.Errorf("%w: truncated response ID does not match query", ErrResponseMismatch)
	}
	if wire[2]&0x80 == 0 {
		return fmt.Errorf("%w: truncated response QR bit is not set", ErrResponseMismatch)
	}
	if int((wire[2]>>3)&0x0f) != query.Opcode {
		return fmt.Errorf("%w: truncated response opcode does not match query", ErrResponseMismatch)
	}
	if binary.BigEndian.Uint16(wire[4:6]) != uint16(len(query.Question)) || len(query.Question) != 1 {
		return fmt.Errorf("%w: truncated response question count does not match query", ErrResponseMismatch)
	}
	name, offset, err := dns.UnpackDomainName(wire, 12)
	if err != nil || offset+4 > len(wire) {
		return fmt.Errorf("%w: truncated response question is incomplete", ErrMalformedResponse)
	}
	gotType := binary.BigEndian.Uint16(wire[offset : offset+2])
	gotClass := binary.BigEndian.Uint16(wire[offset+2 : offset+4])
	want := query.Question[0]
	if !strings.EqualFold(dns.Fqdn(name), dns.Fqdn(want.Name)) || gotType != want.Qtype || gotClass != want.Qclass {
		return fmt.Errorf("%w: truncated response question does not match query", ErrResponseMismatch)
	}
	return nil
}

func validateResponseRecords(message *dns.Msg, queryClass uint16) error {
	for sectionName, records := range map[string][]dns.RR{
		"answer":    message.Answer,
		"authority": message.Ns,
	} {
		for _, rr := range records {
			if nilInterface(rr) {
				return fmt.Errorf("%w: nil RR in %s section", ErrMalformedResponse, sectionName)
			}
			if rr.Header().Rrtype == dns.TypeOPT {
				return fmt.Errorf("%w: OPT is only valid in the additional section", ErrMalformedResponse)
			}
			if rr.Header().Class != queryClass {
				return fmt.Errorf("%w: RR class does not match the question", ErrMalformedResponse)
			}
		}
	}
	optCount := 0
	for _, rr := range message.Extra {
		if nilInterface(rr) {
			return fmt.Errorf("%w: nil RR in additional section", ErrMalformedResponse)
		}
		if rr.Header().Rrtype != dns.TypeOPT {
			if rr.Header().Class != queryClass {
				return fmt.Errorf("%w: additional RR class does not match the question", ErrMalformedResponse)
			}
			continue
		}
		opt, ok := rr.(*dns.OPT)
		if !ok || dns.Fqdn(rr.Header().Name) != "." {
			return fmt.Errorf("%w: invalid OPT record", ErrMalformedResponse)
		}
		if opt.UDPSize() < 512 {
			return fmt.Errorf("%w: invalid OPT UDP size", ErrMalformedResponse)
		}
		for _, option := range opt.Option {
			if nilInterface(option) {
				return fmt.Errorf("%w: nil EDNS option", ErrMalformedResponse)
			}
		}
		optCount++
		if optCount > 1 {
			return fmt.Errorf("%w: multiple OPT records", ErrMalformedResponse)
		}
	}
	if err := validateAliasSingletons(message.Answer); err != nil {
		return err
	}
	return nil
}

type aliasRRKey struct {
	owner string
	class uint16
}

func validateAliasSingletons(answers []dns.RR) error {
	cnames := make(map[aliasRRKey]string)
	dnames := make(map[aliasRRKey]string)
	for _, rr := range answers {
		switch value := rr.(type) {
		case *dns.CNAME:
			key := aliasRRKey{owner: canonicalName(value.Hdr.Name), class: value.Hdr.Class}
			target := canonicalName(value.Target)
			if previous, exists := cnames[key]; exists && previous != target {
				return fmt.Errorf("%w: conflicting CNAME targets for %s", ErrMalformedResponse, key.owner)
			}
			cnames[key] = target
		case *dns.DNAME:
			key := aliasRRKey{owner: canonicalName(value.Hdr.Name), class: value.Hdr.Class}
			target := canonicalName(value.Target)
			if previous, exists := dnames[key]; exists && previous != target {
				return fmt.Errorf("%w: conflicting DNAME targets for %s", ErrMalformedResponse, key.owner)
			}
			dnames[key] = target
		}
	}
	for cname, target := range cnames {
		bestOwner, bestTarget := "", ""
		for dname, dnameTarget := range dnames {
			if dname.class != cname.class || dname.owner == cname.owner || !dns.IsSubDomain(dname.owner, cname.owner) || len(dname.owner) <= len(bestOwner) {
				continue
			}
			bestOwner, bestTarget = dname.owner, dnameTarget
		}
		if bestOwner == "" {
			continue
		}
		synthesized, ok := synthesizeDNAME(cname.owner, bestOwner, bestTarget)
		if !ok || synthesized != target {
			return fmt.Errorf("%w: synthesized CNAME conflicts with DNAME for %s", ErrMalformedResponse, cname.owner)
		}
	}
	return nil
}

func wireHasTC(wire []byte) bool {
	return len(wire) >= 4 && wire[2]&0x02 != 0
}

func populateTruncatedResponsePrefix(result *Result, wire []byte) {
	header := truncatedResponseHeaderFromWire(wire)
	result.Message = nil
	result.RCode = header.RCode
	result.ExtendedRCode = 0
	result.Flags = header.Flags
	result.EDNS = EDNS{}
	result.Outcome = OutcomeTruncatedResponse
	result.Sections = Sections{}
	result.AliasChain = AliasChain{}
	result.NegativeTTL = nil
	result.ResponseParsed = false
	result.ResponseHeaderValidated = true
	result.ResponseTruncated = true
	result.ResultTruncated = false
	result.pendingTCPHeader = nil
}

func truncatedResponseHeaderFromWire(wire []byte) truncatedResponseHeader {
	flags := binary.BigEndian.Uint16(wire[2:4])
	return truncatedResponseHeader{
		RCode: uint8(flags & 0x000f),
		Flags: Flags{
			Response:           flags&0x8000 != 0,
			Authoritative:      flags&0x0400 != 0,
			Truncated:          flags&0x0200 != 0,
			RecursionDesired:   flags&0x0100 != 0,
			RecursionAvailable: flags&0x0080 != 0,
			ReservedZ:          flags&0x0040 != 0,
			AuthenticData:      flags&0x0020 != 0,
			CheckingDisabled:   flags&0x0010 != 0,
		},
	}
}

func retainPendingTCPHeader(result *Result, wire []byte, attempt Attempt) {
	header := truncatedResponseHeaderFromWire(wire)
	header.PeerIP = attempt.PeerIP
	header.ResponseSize = len(wire)
	header.AttemptStartedAt = attempt.StartedAt
	result.pendingTCPHeader = &header
}

func clearMalformedFallbackEvidence(result *Result) {
	result.Message = nil
	result.RCode = 0
	result.ExtendedRCode = 0
	result.Flags = Flags{}
	result.EDNS = EDNS{}
	result.Outcome = OutcomeMalformed
	result.Sections = Sections{}
	result.AliasChain = AliasChain{}
	result.NegativeTTL = nil
	result.ResponseParsed = false
	result.ResponseHeaderValidated = false
	result.ResponseTruncated = false
	result.ResultTruncated = false
	result.pendingTCPHeader = nil
}

func (e *Engine) populateResult(result *Result, message *dns.Msg) error {
	if err := validateResponseRecords(message, result.Question.Qclass); err != nil {
		result.Outcome = OutcomeMalformed
		return err
	}
	result.ResponseParsed = false
	result.ResponseHeaderValidated = false
	result.ResponseTruncated = false
	result.ResultTruncated = false
	result.Sections = Sections{}
	result.EDNS = EDNS{}
	result.AliasChain = AliasChain{}
	result.NegativeTTL = nil
	sections, recordsDropped, err := convertSections(message, e.maxRecordsPerSection)
	if err != nil {
		result.Outcome = OutcomeMalformed
		return fmt.Errorf("%w: convert records: %v", ErrMalformedResponse, err)
	}
	result.ResultTruncated = recordsDropped
	result.Message = message.Copy()
	result.RCode = uint8(message.Rcode & 0x0f)
	result.Flags = Flags{
		Response:           message.Response,
		Authoritative:      message.Authoritative,
		AuthenticData:      message.AuthenticatedData,
		CheckingDisabled:   message.CheckingDisabled,
		RecursionAvailable: message.RecursionAvailable,
		RecursionDesired:   message.RecursionDesired,
		Truncated:          message.Truncated,
		ReservedZ:          message.Zero,
	}
	result.ResponseTruncated = message.Truncated
	result.Sections = sections
	edns, ednsTruncated, err := extractEDNS(message)
	if err != nil {
		result.Outcome = OutcomeMalformed
		return fmt.Errorf("%w: parse EDNS options: %v", ErrMalformedResponse, err)
	}
	result.EDNS = edns
	result.ResultTruncated = result.ResultTruncated || ednsTruncated
	if opt := message.IsEdns0(); opt != nil {
		result.ExtendedRCode = uint8(opt.ExtendedRcode() >> 4)
	}
	result.AliasChain = buildAliasChain(result.Question, message.Answer)
	result.Outcome = classifyOutcome(result.Question, message, result.allowReferral)
	result.NegativeTTL = negativeTTL(result.Outcome, message.Ns)
	result.ResponseParsed = true
	return nil
}

func (e *Engine) composeResult(result *Result, message *dns.Msg) error {
	if e.resultComposer != nil {
		return e.resultComposer(result, message)
	}
	return e.populateResult(result, message)
}

func convertSections(message *dns.Msg, limit int) (Sections, bool, error) {
	answer, answerDropped, err := convertRecords(message.Answer, false, limit)
	if err != nil {
		return Sections{}, false, err
	}
	authority, authorityDropped, err := convertRecords(message.Ns, false, limit)
	if err != nil {
		return Sections{}, false, err
	}
	additional, additionalDropped, err := convertRecords(message.Extra, true, limit)
	if err != nil {
		return Sections{}, false, err
	}
	return Sections{Answer: answer, Authority: authority, Additional: additional}, answerDropped || authorityDropped || additionalDropped, nil
}

type responseRRSetIdentity struct {
	owner   string
	rrType  uint16
	rrClass uint16
}

type responseRRSetGroup struct {
	identity responseRRSetIdentity
	records  []dns.RR
}

func convertRecords(records []dns.RR, skipOPT bool, limit int) ([]ResourceRecord, bool, error) {
	groups := make([]responseRRSetGroup, 0, min(len(records), limit))
	groupByIdentity := make(map[responseRRSetIdentity]int, len(records))
	for _, rr := range records {
		if nilInterface(rr) {
			return nil, false, fmt.Errorf("nil resource record")
		}
		header := rr.Header()
		if header == nil {
			return nil, false, fmt.Errorf("resource record has no header")
		}
		if skipOPT && header.Rrtype == dns.TypeOPT {
			continue
		}
		owner, err := dnsobs.NormalizeWireName(header.Name)
		if err != nil {
			return nil, false, fmt.Errorf("normalize owner %q: %w", header.Name, err)
		}
		identity := responseRRSetIdentity{owner: owner, rrType: header.Rrtype, rrClass: header.Class}
		groupIndex, exists := groupByIdentity[identity]
		if !exists {
			groupIndex = len(groups)
			groupByIdentity[identity] = groupIndex
			groups = append(groups, responseRRSetGroup{identity: identity})
		}
		groups[groupIndex].records = append(groups[groupIndex].records, rr)
	}

	converted := make([]ResourceRecord, 0, min(len(records), limit))
	dropped := false
	limitClosed := false
	for _, group := range groups {
		convertedGroup := make([]ResourceRecord, 0, len(group.records))
		groupComparable := true
		rrSetRecordCount := len(group.records)
		for _, rr := range group.records {
			display, canonical, comparable, err := dnsobs.CanonicalRecordDataForRR(rr)
			if err != nil {
				return nil, false, err
			}
			if !comparable {
				groupComparable = false
				continue
			}
			convertedGroup = append(convertedGroup, ResourceRecord{
				Owner:            group.identity.owner,
				Type:             typeName(group.identity.rrType),
				Class:            className(group.identity.rrClass),
				TTL:              rr.Header().Ttl,
				DisplayRData:     display,
				CanonicalRData:   canonical,
				RRSetRecordCount: rrSetRecordCount,
			})
		}
		if !groupComparable {
			dropped = true
			continue
		}
		if limitClosed || len(convertedGroup) > limit-len(converted) {
			dropped = true
			limitClosed = true
			continue
		}
		converted = append(converted, convertedGroup...)
	}
	return converted, dropped, nil
}

func canonicalRData(rr dns.RR) (string, error) {
	canonical, comparable, err := canonicalRDataForFingerprint(rr)
	if err != nil {
		return "", err
	}
	if !comparable {
		return "", fmt.Errorf("RDATA semantics are unknown for type %d", rr.Header().Rrtype)
	}
	return canonical, nil
}

func canonicalRDataForFingerprint(rr dns.RR) (string, bool, error) {
	return dnsobs.CanonicalRDataForRR(rr)
}

func packedRData(rr dns.RR) ([]byte, error) {
	bufferSize := dns.Len(rr) + 32
	if bufferSize < 512 {
		bufferSize = 512
	}
	for bufferSize <= 65535 {
		buffer := make([]byte, bufferSize)
		offset, err := dns.PackRR(rr, buffer, 0, nil, false)
		if err != nil {
			if bufferSize == 65535 {
				return nil, err
			}
			bufferSize *= 2
			if bufferSize > 65535 {
				bufferSize = 65535
			}
			continue
		}
		_, headerEnd, err := dns.UnpackDomainName(buffer[:offset], 0)
		if err != nil || headerEnd+10 > offset {
			return nil, fmt.Errorf("invalid packed RR header")
		}
		rdataLength := int(binary.BigEndian.Uint16(buffer[headerEnd+8 : headerEnd+10]))
		rdataStart := headerEnd + 10
		if rdataStart+rdataLength != offset {
			return nil, fmt.Errorf("invalid packed RDATA length")
		}
		return append([]byte(nil), buffer[rdataStart:offset]...), nil
	}
	return nil, fmt.Errorf("resource record is too large")
}

func canonicalName(value string) string {
	return dns.CanonicalName(value)
}

func typeName(value uint16) string {
	if name := dns.TypeToString[value]; name != "" {
		if normalized, err := dnsobs.ParseResponseRRType(name); err == nil {
			return string(normalized)
		}
	}
	return fmt.Sprintf("TYPE%d", value)
}

func className(value uint16) string {
	if name := dns.ClassToString[value]; name != "" {
		return name
	}
	return fmt.Sprintf("CLASS%d", value)
}

func extractEDNS(message *dns.Msg) (EDNS, bool, error) {
	opt := message.IsEdns0()
	if opt == nil {
		return EDNS{}, false, nil
	}
	rawOptions, err := rawEDNSOptions(opt)
	if err != nil {
		return EDNS{}, false, err
	}
	if len(rawOptions) != len(opt.Option) {
		return EDNS{}, false, fmt.Errorf("decoded %d EDNS options, want %d", len(rawOptions), len(opt.Option))
	}
	truncated := len(opt.Option) > MaxEDNSOptions
	optionCount := min(len(opt.Option), MaxEDNSOptions)
	edns := EDNS{
		Present:  true,
		UDPSize:  opt.UDPSize(),
		Version:  opt.Version(),
		Flags:    uint16(opt.Hdr.Ttl),
		DNSSECOK: opt.Do(),
		Options:  make([]EDNSOption, 0, optionCount),
	}
	for index, option := range opt.Option[:optionCount] {
		edns.Options = append(edns.Options, EDNSOption{
			Code:       option.Option(),
			DataBase64: base64.StdEncoding.EncodeToString(rawOptions[index]),
		})
		switch value := option.(type) {
		case *dns.EDNS0_SUBNET:
			if edns.ECS == nil {
				edns.ECS = &ClientSubnet{Address: value.Address.String(), SourcePrefix: value.SourceNetmask, ScopePrefix: value.SourceScope}
			}
		case *dns.EDNS0_EDE:
			if len(edns.EDE) < MaxExtendedDNSErrors {
				edns.EDE = append(edns.EDE, ExtendedDNSError{Code: value.InfoCode, Text: value.ExtraText})
			} else {
				truncated = true
			}
		case *dns.EDNS0_NSID:
			if edns.NSIDHex == "" {
				edns.NSIDHex = strings.ToLower(value.Nsid)
			}
		}
	}
	return edns, truncated, nil
}

func rawEDNSOptions(opt *dns.OPT) ([][]byte, error) {
	rdata, err := packedRData(opt)
	if err != nil {
		return nil, err
	}
	options := make([][]byte, 0, len(opt.Option))
	for offset := 0; offset < len(rdata); {
		if len(rdata)-offset < 4 {
			return nil, fmt.Errorf("truncated EDNS option header")
		}
		code := binary.BigEndian.Uint16(rdata[offset : offset+2])
		length := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if length > len(rdata)-offset {
			return nil, fmt.Errorf("truncated EDNS option payload")
		}
		if len(options) >= len(opt.Option) || opt.Option[len(options)].Option() != code {
			return nil, fmt.Errorf("EDNS option code does not match parsed message")
		}
		options = append(options, append([]byte(nil), rdata[offset:offset+length]...))
		offset += length
	}
	return options, nil
}

func classifyOutcome(question dns.Question, message *dns.Msg, allowReferral bool) Outcome {
	switch message.Rcode | fullExtendedRCode(message) {
	case dns.RcodeSuccess:
		if hasTerminalAnswer(question, message.Answer) {
			return OutcomeAnswer
		}
		if allowReferral && isReferral(message) {
			return OutcomeReferral
		}
		if hasAliasAnswer(question, message.Answer) && !hasSOANegativeProof(message.Ns) {
			return OutcomeAnswer
		}
		return OutcomeNoData
	case dns.RcodeNameError:
		return OutcomeNXDomain
	case dns.RcodeServerFailure:
		return OutcomeServFail
	case dns.RcodeRefused:
		return OutcomeRefused
	default:
		return OutcomeOther
	}
}

func hasAliasAnswer(question dns.Question, answers []dns.RR) bool {
	_, ok := nextAliasHop(canonicalName(question.Name), question.Qclass, answers)
	return ok
}

func hasSOANegativeProof(authority []dns.RR) bool {
	for _, rr := range authority {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

func isReferral(message *dns.Msg) bool {
	if message.Authoritative {
		return false
	}
	for _, rr := range message.Ns {
		if rr != nil && rr.Header().Rrtype == dns.TypeNS {
			return true
		}
	}
	return false
}

func fullExtendedRCode(message *dns.Msg) int {
	if opt := message.IsEdns0(); opt != nil {
		return opt.ExtendedRcode()
	}
	return 0
}

func hasTerminalAnswer(question dns.Question, answers []dns.RR) bool {
	current := canonicalName(question.Name)
	visited := map[string]bool{}
	for range 33 {
		if visited[current] {
			return false
		}
		visited[current] = true
		for _, rr := range answers {
			header := rr.Header()
			if !strings.EqualFold(canonicalName(header.Name), current) || header.Class != question.Qclass {
				continue
			}
			if question.Qtype == dns.TypeANY || header.Rrtype == question.Qtype {
				return true
			}
		}
		hop, ok := nextAliasHop(current, question.Qclass, answers)
		if !ok {
			return false
		}
		current = hop.To
	}
	return false
}

func buildAliasChain(question dns.Question, answers []dns.RR) AliasChain {
	current := canonicalName(question.Name)
	visited := map[string]bool{current: true}
	chain := AliasChain{}
	for range 32 {
		hop, ok := nextAliasHop(current, question.Qclass, answers)
		if !ok {
			if len(chain.Hops) > 0 {
				chain.TerminalName = current
			}
			return chain
		}
		chain.Hops = append(chain.Hops, hop)
		if visited[hop.To] {
			chain.Loop = true
			chain.TerminalName = hop.To
			return chain
		}
		visited[hop.To] = true
		current = hop.To
	}
	if _, ok := nextAliasHop(current, question.Qclass, answers); ok {
		chain.Truncated = true
	}
	chain.TerminalName = current
	return chain
}

func nextAliasHop(current string, class uint16, answers []dns.RR) (AliasHop, bool) {
	// Prefer DNAME when both the DNAME and its synthesized CNAME are present,
	// so the chain retains the authoritative alias mechanism.
	var bestOwner string
	var bestTarget string
	for _, rr := range answers {
		dname, ok := rr.(*dns.DNAME)
		if !ok || dname.Hdr.Class != class {
			continue
		}
		owner := canonicalName(dname.Hdr.Name)
		if strings.EqualFold(owner, current) || !dns.IsSubDomain(owner, current) || len(owner) <= len(bestOwner) {
			continue
		}
		bestOwner = owner
		bestTarget = canonicalName(dname.Target)
	}
	if bestOwner != "" {
		target, ok := synthesizeDNAME(current, bestOwner, bestTarget)
		if !ok {
			return AliasHop{}, false
		}
		return AliasHop{Type: "DNAME", From: current, To: target}, true
	}
	for _, rr := range answers {
		cname, ok := rr.(*dns.CNAME)
		if ok && cname.Hdr.Class == class && strings.EqualFold(canonicalName(cname.Hdr.Name), current) {
			return AliasHop{Type: "CNAME", From: current, To: canonicalName(cname.Target)}, true
		}
	}
	return AliasHop{}, false
}

func synthesizeDNAME(current string, owner string, target string) (string, bool) {
	current = canonicalName(current)
	owner = canonicalName(owner)
	target = canonicalName(target)
	if current == owner || !dns.IsSubDomain(owner, current) {
		return "", false
	}
	prefix := strings.TrimSuffix(current, owner)
	if target == "." {
		return canonicalName(prefix), true
	}
	return canonicalName(prefix + target), true
}

func negativeTTL(outcome Outcome, authority []dns.RR) *uint32 {
	if outcome != OutcomeNXDomain && outcome != OutcomeNoData {
		return nil
	}
	var minimum *uint32
	for _, rr := range authority {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		value := min(soa.Hdr.Ttl, soa.Minttl)
		if minimum == nil || value < *minimum {
			copy := value
			minimum = &copy
		}
	}
	return minimum
}
