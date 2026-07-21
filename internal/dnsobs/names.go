package dnsobs

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var lookupIDNA = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

var unicodeDots = strings.NewReplacer(
	"\u3002", ".",
	"\uff0e", ".",
	"\uff61", ".",
)

type namePolicy struct {
	allowServiceLabels bool
	allowWildcard      bool
}

func NormalizeFQDN(input string) (string, error) {
	return normalizeFQDN(input, namePolicy{})
}

// NormalizeOwnerName accepts leading-underscore DNS labels and a leading
// wildcard because both can occur in returned owner names. Query validation
// accepts underscore labels but intentionally remains stricter about wildcards.
func NormalizeOwnerName(input string) (string, error) {
	return normalizeFQDN(input, namePolicy{allowServiceLabels: true, allowWildcard: true})
}

func NormalizeQuestionName(input string, rrType RRType) (string, error) {
	if rrType == RRTypePTR {
		return NormalizePTRName(input)
	}
	policy := namePolicy{allowServiceLabels: true}
	name, err := normalizeFQDN(input, policy)
	if err != nil {
		return "", err
	}
	if rrType == RRTypeSRV {
		if err := validateSRVQName(name); err != nil {
			return "", err
		}
	}
	if rrType == RRTypeTLSA {
		if err := validateTLSAQName(name); err != nil {
			return "", err
		}
	}
	return name, nil
}

func NormalizePTRName(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if addr, err := netip.ParseAddr(trimmed); err == nil && addr.Zone() == "" {
		return ReverseName(addr), nil
	}
	name, err := normalizeFQDN(trimmed, namePolicy{})
	if err != nil {
		return "", fmt.Errorf("invalid PTR name: %w", err)
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	switch {
	case len(labels) == 6 && labels[4] == "in-addr" && labels[5] == "arpa":
		for _, label := range labels[:4] {
			value, err := strconv.Atoi(label)
			if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != label {
				return "", fmt.Errorf("invalid PTR name: IPv4 reverse labels must be canonical octets")
			}
		}
		return name, nil
	case len(labels) == 34 && labels[32] == "ip6" && labels[33] == "arpa":
		for _, label := range labels[:32] {
			if len(label) != 1 || !isLowerHex(label[0]) {
				return "", fmt.Errorf("invalid PTR name: IPv6 reverse labels must be single hexadecimal nibbles")
			}
		}
		return name, nil
	default:
		return "", fmt.Errorf("invalid PTR name: expected an IP address or canonical reverse name")
	}
}

func ReverseName(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	if addr.Is4() {
		octets := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])
	}
	bytes := addr.As16()
	var builder strings.Builder
	builder.Grow(32*2 + len("ip6.arpa."))
	const hex = "0123456789abcdef"
	for i := len(bytes) - 1; i >= 0; i-- {
		builder.WriteByte(hex[bytes[i]&0x0f])
		builder.WriteByte('.')
		builder.WriteByte(hex[bytes[i]>>4])
		builder.WriteByte('.')
	}
	builder.WriteString("ip6.arpa.")
	return builder.String()
}

func UnicodeFQDN(input string) (string, error) {
	ascii, err := NormalizeOwnerName(input)
	if err != nil {
		return "", err
	}
	if ascii == "." {
		return ascii, nil
	}
	labels := strings.Split(strings.TrimSuffix(ascii, "."), ".")
	for i, label := range labels {
		if label == "*" || strings.HasPrefix(label, "_") {
			continue
		}
		value, err := lookupIDNA.ToUnicode(label)
		if err != nil {
			return "", fmt.Errorf("invalid internationalized name: %w", err)
		}
		labels[i] = value
	}
	return strings.Join(labels, ".") + ".", nil
}

func normalizeFQDN(input string, policy namePolicy) (string, error) {
	if !utf8.ValidString(input) {
		return "", fmt.Errorf("DNS name is not valid UTF-8")
	}
	name := unicodeDots.Replace(strings.TrimSpace(input))
	if name == "" {
		return "", fmt.Errorf("DNS name is required")
	}
	if name == "." {
		return ".", nil
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("DNS name contains an empty label")
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" {
			return "", fmt.Errorf("DNS name contains an empty label")
		}
		if label == "*" {
			if !policy.allowWildcard || i != 0 {
				return "", fmt.Errorf("wildcard label is not allowed")
			}
			continue
		}
		if strings.HasPrefix(label, "_") {
			if !policy.allowServiceLabels {
				return "", fmt.Errorf("underscore label is not allowed for this query type")
			}
			normalized, err := normalizeServiceLabel(label)
			if err != nil {
				return "", err
			}
			labels[i] = normalized
			continue
		}
		ascii, err := lookupIDNA.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("invalid DNS label %q: %w", label, err)
		}
		ascii = strings.ToLower(ascii)
		if len(ascii) == 0 || len(ascii) > 63 {
			return "", fmt.Errorf("DNS label length must be between 1 and 63 octets")
		}
		labels[i] = ascii
	}
	normalized := strings.Join(labels, ".") + "."
	if wireNameLength(labels) > 255 {
		return "", fmt.Errorf("DNS name exceeds the 255-octet wire limit")
	}
	return normalized, nil
}

func normalizeServiceLabel(label string) (string, error) {
	if len(label) < 2 || len(label) > 63 {
		return "", fmt.Errorf("underscore label length must be between 2 and 63 octets")
	}
	value := strings.ToLower(label[1:])
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return "", fmt.Errorf("underscore label contains an invalid character")
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return "", fmt.Errorf("underscore label must not start or end with a hyphen")
	}
	return "_" + value, nil
}

func validateSRVQName(name string) error {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 3 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return fmt.Errorf("SRV name must start with _service._protocol")
	}
	for _, label := range labels[2:] {
		if strings.HasPrefix(label, "_") {
			return fmt.Errorf("SRV domain suffix must not contain underscore labels")
		}
	}
	return nil
}

func validateTLSAQName(name string) error {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 3 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return fmt.Errorf("TLSA name must start with _port._transport")
	}
	port, err := strconv.Atoi(strings.TrimPrefix(labels[0], "_"))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("TLSA service label must contain a port from 1 to 65535")
	}
	switch labels[1] {
	case "_tcp", "_udp", "_sctp":
	default:
		return fmt.Errorf("TLSA transport label must be _tcp, _udp, or _sctp")
	}
	for _, label := range labels[2:] {
		if strings.HasPrefix(label, "_") {
			return fmt.Errorf("TLSA domain suffix must not contain underscore labels")
		}
	}
	return nil
}

func wireNameLength(labels []string) int {
	length := 1
	for _, label := range labels {
		length += 1 + len(label)
	}
	return length
}

func isLowerHex(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
}
