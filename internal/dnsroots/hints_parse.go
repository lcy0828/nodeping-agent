package dnsroots

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type rootServerAddresses struct {
	ipv4 map[netip.Addr]struct{}
	ipv6 map[netip.Addr]struct{}
}

func ParseRootHints(value []byte) (HintsSummary, error) {
	if len(value) == 0 || len(value) > maxHintsBytes {
		return HintsSummary{}, fmt.Errorf("%w: size %d", ErrInvalidHints, len(value))
	}
	servers := make(map[string]struct{}, RootServerCount)
	glue := make(map[string]*rootServerAddresses, RootServerCount)
	parser := dns.NewZoneParser(bytes.NewReader(value), ".", "named.root")
	parser.SetIncludeAllowed(false)
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		header := rr.Header()
		if header.Class != dns.ClassINET || header.Ttl == 0 {
			return HintsSummary{}, fmt.Errorf("%w: non-IN record or zero TTL", ErrInvalidHints)
		}
		switch record := rr.(type) {
		case *dns.NS:
			if header.Name != "." {
				return HintsSummary{}, fmt.Errorf("%w: NS owner must be root", ErrInvalidHints)
			}
			name := canonicalRootServerName(record.Ns)
			if name == "" {
				return HintsSummary{}, fmt.Errorf("%w: invalid root server name", ErrInvalidHints)
			}
			if _, exists := servers[name]; exists {
				return HintsSummary{}, fmt.Errorf("%w: duplicate root server %s", ErrInvalidHints, name)
			}
			servers[name] = struct{}{}
		case *dns.A:
			if err := addRootAddress(glue, header.Name, record.A.String(), false); err != nil {
				return HintsSummary{}, err
			}
		case *dns.AAAA:
			if err := addRootAddress(glue, header.Name, record.AAAA.String(), true); err != nil {
				return HintsSummary{}, err
			}
		default:
			return HintsSummary{}, fmt.Errorf("%w: unsupported record type %s", ErrInvalidHints, dns.TypeToString[header.Rrtype])
		}
	}
	if err := parser.Err(); err != nil {
		return HintsSummary{}, fmt.Errorf("%w: %v", ErrInvalidHints, err)
	}
	if len(servers) != RootServerCount {
		return HintsSummary{}, fmt.Errorf("%w: got %d root servers, want %d", ErrInvalidHints, len(servers), RootServerCount)
	}
	summary := HintsSummary{RootServerCount: len(servers)}
	for name := range glue {
		if _, exists := servers[name]; !exists {
			return HintsSummary{}, fmt.Errorf("%w: glue owner %s has no root NS", ErrInvalidHints, name)
		}
	}
	for name := range servers {
		addresses := glue[name]
		if addresses == nil {
			return HintsSummary{}, fmt.Errorf("%w: %s has no glue", ErrInvalidHints, name)
		}
		if len(addresses.ipv4) == 0 || len(addresses.ipv6) == 0 {
			return HintsSummary{}, fmt.Errorf("%w: %s is missing IPv4 or IPv6 glue", ErrInvalidHints, name)
		}
		summary.IPv4Count += len(addresses.ipv4)
		summary.IPv6Count += len(addresses.ipv6)
	}
	return summary, nil
}

func canonicalRootServerName(value string) string {
	name := strings.ToLower(dns.Fqdn(strings.TrimSpace(value)))
	if _, valid := dns.IsDomainName(name); !valid || !strings.HasSuffix(name, ".root-servers.net.") {
		return ""
	}
	labels := dns.SplitDomainName(name)
	if len(labels) != 3 || len(labels[0]) != 1 || labels[0][0] < 'a' || labels[0][0] > 'm' {
		return ""
	}
	return name
}

func addRootAddress(glue map[string]*rootServerAddresses, owner, value string, ipv6 bool) error {
	name := canonicalRootServerName(owner)
	if name == "" {
		return fmt.Errorf("%w: invalid glue owner %s", ErrInvalidHints, owner)
	}
	server := glue[name]
	if server == nil {
		server = &rootServerAddresses{ipv4: map[netip.Addr]struct{}{}, ipv6: map[netip.Addr]struct{}{}}
		glue[name] = server
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() {
		return fmt.Errorf("%w: invalid glue address for %s", ErrInvalidHints, owner)
	}
	if address.Is6() != ipv6 {
		return fmt.Errorf("%w: glue address family mismatch for %s", ErrInvalidHints, owner)
	}
	set := server.ipv4
	if ipv6 {
		set = server.ipv6
	}
	if _, duplicate := set[address]; duplicate {
		return fmt.Errorf("%w: duplicate glue address for %s", ErrInvalidHints, owner)
	}
	set[address] = struct{}{}
	return nil
}
