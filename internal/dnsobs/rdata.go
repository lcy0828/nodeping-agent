package dnsobs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/miekg/dns"
	"github.com/yosida95/uritemplate/v3"
)

// CanonicalRecordDataForRR returns the unique display and uncompressed wire
// forms used by observations. Only explicitly audited response RR types are
// comparable; newly added miekg/dns RR implementations default to rejected.
func CanonicalRecordDataForRR(rr dns.RR) (display string, canonical string, comparable bool, err error) {
	if nilDNSRR(rr) {
		return "", "", false, fmt.Errorf("resource record is nil")
	}
	wireType, audited := auditedResponseRRType(rr)
	if !audited || rr.Header() == nil || rr.Header().Rrtype != wireType {
		return "", "", false, nil
	}
	if !validAuditedRRSemantics(rr) {
		return "", "", false, nil
	}

	canonicalRR := canonicalizeDNSRR(dns.Copy(rr))
	rdata, err := packCanonicalRData(canonicalRR)
	if err != nil {
		return "", "", false, err
	}
	if len(rdata) == 0 {
		return "", "", false, nil
	}
	canonical = formatCanonicalWireRData(rdata)
	if len(canonical) > MaxRDataBytes {
		return "", "", false, nil
	}

	decoded, err := decodeTypedCanonicalRR(canonicalRR.Header(), canonical)
	if err != nil {
		return "", "", false, fmt.Errorf("decode generated canonical RDATA: %w", err)
	}
	if decodedType, ok := auditedResponseRRType(decoded); !ok || decodedType != wireType || !validAuditedRRSemantics(decoded) {
		return "", "", false, nil
	}
	decoded = canonicalizeDNSRR(decoded)
	decodedRData, err := packCanonicalRData(decoded)
	if err != nil {
		return "", "", false, fmt.Errorf("repack generated canonical RDATA: %w", err)
	}
	if !bytes.Equal(rdata, decodedRData) {
		return "", "", false, fmt.Errorf("canonical RDATA did not round-trip byte-for-byte")
	}
	display, err = displayRDataForTypedRR(decoded)
	if err != nil {
		return "", "", false, err
	}
	if len(display) > MaxRDataBytes {
		return "", "", false, nil
	}
	return display, canonical, true, nil
}

// CanonicalRDataForRR preserves the original API while sharing the audited
// record-data implementation used for display evidence.
func CanonicalRDataForRR(rr dns.RR) (value string, comparable bool, err error) {
	_, value, comparable, err = CanonicalRecordDataForRR(rr)
	return value, comparable, err
}

// ValidateCanonicalRData proves that value is exactly the canonical wire form
// produced for an audited typed RR.
func ValidateCanonicalRData(owner string, rrType RRType, class DNSClass, value string) error {
	_, err := DisplayRDataForCanonicalRData(owner, rrType, class, value)
	return err
}

// DisplayRDataForCanonicalRData validates canonical wire evidence and derives
// its only accepted human-readable representation.
func DisplayRDataForCanonicalRData(owner string, rrType RRType, class DNSClass, value string) (string, error) {
	normalizedOwner, err := NormalizeWireName(owner)
	if err != nil {
		return "", fmt.Errorf("normalize owner: %w", err)
	}
	normalizedType, err := ParseResponseRRType(string(rrType))
	if err != nil {
		return "", err
	}
	normalizedClass := DNSClass(strings.ToUpper(strings.TrimSpace(string(class))))
	if !normalizedClass.Valid() {
		return "", fmt.Errorf("unsupported DNS class %q", class)
	}
	if len(value) > MaxRDataBytes {
		return "", fmt.Errorf("canonical RDATA exceeds %d bytes", MaxRDataBytes)
	}
	wireLength, err := validateCanonicalWireSyntax(value)
	if err != nil {
		return "", err
	}
	if wireLength == 0 {
		return "", fmt.Errorf("canonical RDATA must not be empty")
	}

	record, err := dns.NewRR(fmt.Sprintf("%s 0 %s %s %s", normalizedOwner, normalizedClass, normalizedType, value))
	if err != nil {
		return "", fmt.Errorf("canonical RDATA does not decode as typed %s RDATA: %w", normalizedType, err)
	}
	wantType, err := dnsTypeCode(normalizedType)
	if err != nil {
		return "", err
	}
	if record == nil || record.Header() == nil || record.Header().Rrtype != wantType || record.Header().Class != dns.ClassINET {
		return "", fmt.Errorf("canonical RDATA decoded with an unexpected DNS type or class")
	}

	display, canonical, comparable, err := CanonicalRecordDataForRR(record)
	if err != nil {
		return "", fmt.Errorf("re-encode canonical RDATA: %w", err)
	}
	if !comparable {
		return "", fmt.Errorf("RDATA semantics are not in the audited response contract for type %s", normalizedType)
	}
	if value != canonical {
		return "", fmt.Errorf("canonical RDATA must equal %q", canonical)
	}
	return display, nil
}

// NormalizeWireName validates a DNS wire-derived presentation name without
// applying hostname or IDNA policy. It preserves arbitrary legal label octets
// and applies only the US-ASCII case folding required by RFC 4034.
func NormalizeWireName(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("DNS wire name is required")
	}
	buffer := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.Fqdn(input), buffer, 0, nil, false)
	if err != nil || offset < 1 || offset > len(buffer) {
		return "", fmt.Errorf("invalid DNS wire name %q", input)
	}
	decoded, next, err := dns.UnpackDomainName(buffer[:offset], 0)
	if err != nil || next != offset {
		return "", fmt.Errorf("invalid DNS wire name %q", input)
	}
	return dns.CanonicalName(decoded), nil
}

func validateCanonicalWireSyntax(value string) (int, error) {
	const prefix = `\# `
	if !strings.HasPrefix(value, prefix) {
		return 0, fmt.Errorf("canonical RDATA must use RFC 3597 wire form")
	}
	remainder := strings.TrimPrefix(value, prefix)
	separator := strings.IndexByte(remainder, ' ')
	if separator < 1 {
		return 0, fmt.Errorf("canonical RDATA must contain a decimal length and uppercase hexadecimal payload")
	}
	lengthText := remainder[:separator]
	hexText := remainder[separator+1:]
	if len(lengthText) > 1 && lengthText[0] == '0' {
		return 0, fmt.Errorf("canonical RDATA length must not contain leading zeroes")
	}
	for _, char := range lengthText {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("canonical RDATA length must be decimal")
		}
	}
	wantLength, err := strconv.Atoi(lengthText)
	if err != nil || wantLength < 0 || wantLength > 65535 {
		return 0, fmt.Errorf("canonical RDATA has an invalid wire length")
	}
	if len(hexText) != wantLength*2 {
		return 0, fmt.Errorf("canonical RDATA payload does not match its wire length")
	}
	for _, char := range hexText {
		if (char < '0' || char > '9') && (char < 'A' || char > 'F') {
			return 0, fmt.Errorf("canonical RDATA payload must be uppercase hexadecimal without whitespace")
		}
	}
	return wantLength, nil
}

func auditedResponseRRType(rr dns.RR) (uint16, bool) {
	switch rr.(type) {
	case *dns.A:
		return dns.TypeA, true
	case *dns.AAAA:
		return dns.TypeAAAA, true
	case *dns.CNAME:
		return dns.TypeCNAME, true
	case *dns.MX:
		return dns.TypeMX, true
	case *dns.TXT:
		return dns.TypeTXT, true
	case *dns.NS:
		return dns.TypeNS, true
	case *dns.SOA:
		return dns.TypeSOA, true
	case *dns.CAA:
		return dns.TypeCAA, true
	case *dns.SRV:
		return dns.TypeSRV, true
	case *dns.PTR:
		return dns.TypePTR, true
	case *dns.DS:
		return dns.TypeDS, true
	case *dns.DNSKEY:
		return dns.TypeDNSKEY, true
	case *dns.TLSA:
		return dns.TypeTLSA, true
	case *dns.SVCB:
		return dns.TypeSVCB, true
	case *dns.HTTPS:
		return dns.TypeHTTPS, true
	case *dns.DNAME:
		return dns.TypeDNAME, true
	case *dns.RRSIG:
		return dns.TypeRRSIG, true
	case *dns.NSEC:
		return dns.TypeNSEC, true
	case *dns.NSEC3:
		return dns.TypeNSEC3, true
	case *dns.NSEC3PARAM:
		return dns.TypeNSEC3PARAM, true
	default:
		return 0, false
	}
}

func validAuditedRRSemantics(rr dns.RR) bool {
	switch value := rr.(type) {
	case *dns.SVCB:
		return validSVCBParameters(value)
	case *dns.HTTPS:
		return validSVCBParameters(&value.SVCB)
	default:
		return true
	}
}

func validCAATag(tag string) bool {
	if tag == "" {
		return false
	}
	for index := 0; index < len(tag); index++ {
		char := tag[index]
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validSVCBParameters(record *dns.SVCB) bool {
	present := make(map[dns.SVCBKey]bool, len(record.Value))
	var mandatory *dns.SVCBMandatory
	hasALPN := false
	hasNoDefaultALPN := false
	var previous dns.SVCBKey
	for index, pair := range record.Value {
		if nilSVCBPair(pair) {
			return false
		}
		key := pair.Key()
		if key == 65535 || (index > 0 && key <= previous) {
			return false
		}
		previous = key
		present[key] = true
		switch key {
		case dns.SVCB_MANDATORY:
			value, ok := pair.(*dns.SVCBMandatory)
			if !ok || len(value.Code) == 0 {
				return false
			}
			for mandatoryIndex, listedKey := range value.Code {
				if listedKey == dns.SVCB_MANDATORY || listedKey == 65535 || (mandatoryIndex > 0 && listedKey <= value.Code[mandatoryIndex-1]) {
					return false
				}
			}
			mandatory = value
		case dns.SVCB_ALPN:
			value, ok := pair.(*dns.SVCBAlpn)
			if !ok || len(value.Alpn) == 0 {
				return false
			}
			for _, protocol := range value.Alpn {
				if protocol == "" || len(protocol) > 255 {
					return false
				}
			}
			hasALPN = true
		case dns.SVCB_NO_DEFAULT_ALPN:
			if _, ok := pair.(*dns.SVCBNoDefaultAlpn); !ok {
				return false
			}
			hasNoDefaultALPN = true
		case dns.SVCB_PORT:
			if _, ok := pair.(*dns.SVCBPort); !ok {
				return false
			}
		case dns.SVCB_IPV4HINT:
			value, ok := pair.(*dns.SVCBIPv4Hint)
			if !ok || len(value.Hint) == 0 {
				return false
			}
			for _, address := range value.Hint {
				if address.To4() == nil {
					return false
				}
			}
		case dns.SVCB_ECHCONFIG:
			value, ok := pair.(*dns.SVCBECHConfig)
			if !ok || ValidateSVCBECHConfigList(value.ECH) != nil {
				return false
			}
		case dns.SVCB_IPV6HINT:
			value, ok := pair.(*dns.SVCBIPv6Hint)
			if !ok || len(value.Hint) == 0 {
				return false
			}
			for _, address := range value.Hint {
				if len(address) != 16 || address.To4() != nil {
					return false
				}
			}
		case dns.SVCB_DOHPATH:
			value, ok := pair.(*dns.SVCBDoHPath)
			if !ok || ValidateSVCBDoHPathTemplate(value.Template) != nil {
				return false
			}
		case dns.SVCB_OHTTP:
			if _, ok := pair.(*dns.SVCBOhttp); !ok {
				return false
			}
		}
	}
	if record.Priority == 0 {
		return true
	}
	if hasNoDefaultALPN && !hasALPN {
		return false
	}
	if mandatory == nil {
		return true
	}
	for _, key := range mandatory.Code {
		if !present[key] {
			return false
		}
	}
	return true
}

// ValidateSVCBECHConfigList checks the nested TLS vectors carried by the ech
// SvcParam without interpreting version-specific ECHConfig contents.
func ValidateSVCBECHConfigList(value []byte) error {
	if len(value) < 6 {
		return fmt.Errorf("ECHConfigList must contain at least one ECHConfig")
	}
	listLength := int(binary.BigEndian.Uint16(value[:2]))
	if listLength != len(value)-2 {
		return fmt.Errorf("ECHConfigList length does not consume the complete SvcParam value")
	}
	for cursor := 2; cursor < len(value); {
		if len(value)-cursor < 4 {
			return fmt.Errorf("ECHConfig header is incomplete")
		}
		configLength := int(binary.BigEndian.Uint16(value[cursor+2 : cursor+4]))
		cursor += 4
		if configLength > len(value)-cursor {
			return fmt.Errorf("ECHConfig contents exceed ECHConfigList")
		}
		cursor += configLength
	}
	return nil
}

// ValidateSVCBDoHPathTemplate checks the RFC 9461 dohpath value as an RFC
// 6570 relative URI Template and proves a DNS-message expansion is an HTTP
// request path. DNS messages use the base64url alphabet represented below.
func ValidateSVCBDoHPathTemplate(value string) error {
	if value == "" || !utf8.ValidString(value) {
		return fmt.Errorf("dohpath must contain a non-empty UTF-8 URI Template")
	}
	template, err := uritemplate.New(value)
	if err != nil {
		return fmt.Errorf("dohpath is not a valid RFC 6570 URI Template: %w", err)
	}
	hasDNSVariable := false
	for _, variable := range template.Varnames() {
		if variable == "dns" {
			hasDNSVariable = true
			break
		}
	}
	if !hasDNSVariable {
		return fmt.Errorf("dohpath URI Template must contain the dns variable")
	}
	prefix := strings.Repeat("A", 9999)
	dnsMessages := [...]string{prefix + "B", prefix + "C"}
	var expanded [len(dnsMessages)]string
	for index, dnsMessage := range dnsMessages {
		expanded[index], err = template.Expand(uritemplate.Values{
			"dns": uritemplate.String(dnsMessage),
		})
		if err != nil {
			return fmt.Errorf("expand dohpath URI Template: %w", err)
		}
		if err := validateSVCBDoHExpandedPath(expanded[index]); err != nil {
			return err
		}
	}
	if expanded[0] == expanded[1] {
		return fmt.Errorf("dohpath URI Template must preserve the complete dns variable")
	}
	return nil
}

func validateSVCBDoHExpandedPath(expanded string) error {
	parsedReference, err := url.Parse(expanded)
	if err != nil || parsedReference.IsAbs() || parsedReference.Host != "" || parsedReference.Fragment != "" {
		return fmt.Errorf("expanded dohpath must be a relative URI without an authority or fragment")
	}
	parsedPath, err := url.ParseRequestURI(expanded)
	if err != nil || parsedPath.IsAbs() || parsedPath.Host != "" || parsedPath.Fragment != "" || !strings.HasPrefix(expanded, "/") {
		return fmt.Errorf("expanded dohpath must be a valid HTTP :path value")
	}
	return nil
}

func nilSVCBPair(pair dns.SVCBKeyValue) bool {
	if pair == nil {
		return true
	}
	value := reflect.ValueOf(pair)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func formatCanonicalWireRData(rdata []byte) string {
	return fmt.Sprintf("\\# %d %s", len(rdata), strings.ToUpper(hex.EncodeToString(rdata)))
}

func decodeTypedCanonicalRR(header *dns.RR_Header, canonical string) (dns.RR, error) {
	record, err := dns.NewRR(fmt.Sprintf("%s 0 CLASS%d TYPE%d %s", dns.CanonicalName(header.Name), header.Class, header.Rrtype, canonical))
	if err != nil {
		return nil, err
	}
	return record, nil
}

func displayRDataForTypedRR(rr dns.RR) (string, error) {
	full := rr.String()
	header := rr.Header().String()
	if !strings.HasPrefix(full, header) {
		return "", fmt.Errorf("typed RR display does not contain its header prefix")
	}
	display := strings.TrimSpace(strings.TrimPrefix(full, header))
	if display == "" {
		return "", fmt.Errorf("typed RR has empty display RDATA")
	}
	return display, nil
}

func dnsTypeCode(rrType RRType) (uint16, error) {
	if code, ok := dns.StringToType[string(rrType)]; ok {
		return code, nil
	}
	text := string(rrType)
	if !strings.HasPrefix(text, "TYPE") {
		return 0, fmt.Errorf("unsupported DNS response type %q", rrType)
	}
	code, err := strconv.ParseUint(strings.TrimPrefix(text, "TYPE"), 10, 16)
	if err != nil || code == 0 {
		return 0, fmt.Errorf("invalid RFC 3597 DNS response type %q", rrType)
	}
	return uint16(code), nil
}

func packCanonicalRData(rr dns.RR) ([]byte, error) {
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

func canonicalizeDNSRR(rr dns.RR) dns.RR {
	rr.Header().Name = dns.CanonicalName(rr.Header().Name)
	switch value := rr.(type) {
	case *dns.NS:
		value.Ns = dns.CanonicalName(value.Ns)
	case *dns.CNAME:
		value.Target = dns.CanonicalName(value.Target)
	case *dns.DNAME:
		value.Target = dns.CanonicalName(value.Target)
	case *dns.PTR:
		value.Ptr = dns.CanonicalName(value.Ptr)
	case *dns.MX:
		value.Mx = dns.CanonicalName(value.Mx)
	case *dns.SOA:
		value.Ns = dns.CanonicalName(value.Ns)
		value.Mbox = dns.CanonicalName(value.Mbox)
	case *dns.SRV:
		value.Target = dns.CanonicalName(value.Target)
	case *dns.RRSIG:
		value.SignerName = dns.CanonicalName(value.SignerName)
	case *dns.NSEC:
		value.NextDomain = dns.CanonicalName(value.NextDomain)
		sort.Slice(value.TypeBitMap, func(i, j int) bool { return value.TypeBitMap[i] < value.TypeBitMap[j] })
	case *dns.NSEC3:
		sort.Slice(value.TypeBitMap, func(i, j int) bool { return value.TypeBitMap[i] < value.TypeBitMap[j] })
	case *dns.SVCB:
		value.Target = dns.CanonicalName(value.Target)
	case *dns.HTTPS:
		value.Target = dns.CanonicalName(value.Target)
	case *dns.CAA:
		if validCAATag(value.Tag) {
			value.Tag = strings.ToLower(value.Tag)
		}
	}
	return rr
}

func nilDNSRR(rr dns.RR) bool {
	if rr == nil {
		return true
	}
	value := reflect.ValueOf(rr)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
