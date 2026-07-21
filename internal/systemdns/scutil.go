package systemdns

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type indexedText struct {
	index int
	value string
	line  int
}

type scutilBlock struct {
	ordinal int

	nameservers    map[int]indexedText
	searchDomains  map[int]indexedText
	domain         string
	domainSet      bool
	order          uint32
	orderSet       bool
	interfaceIndex uint32
	interfaceName  string
	interfaceSet   bool
	flags          []string
	options        []string
	port           uint16
	portSet        bool
	timeoutSeconds uint32
	timeoutRaw     uint32
	timeoutSet     bool
}

// ParseSCUtilDNS parses the stable, non-localized property format emitted by
// `scutil --dns`. Section headings are ignored; resolver property names are
// parsed strictly. Parsed endpoints are not system-trusted; only native
// discovery grants trust.
func ParseSCUtilDNS(input []byte) (DiscoveryResult, error) {
	limits, err := normalizeLimits(Limits{})
	if err != nil {
		return DiscoveryResult{}, err
	}
	return parseSCUtilDNS(input, limits)
}

func parseSCUtilDNS(input []byte, limits Limits) (DiscoveryResult, error) {
	if len(input) > limits.MaxInputBytes {
		return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformDarwin, "parse_scutil", "input", 0, "command output exceeds the byte limit", nil)
	}
	if err := validateTextInput(input); err != nil {
		return DiscoveryResult{}, malformedSCUtil("input", 0, err.Error(), err)
	}
	if bytes.Count(input, []byte{'\n'})+1 > limits.MaxLines {
		return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "lines", 0, "line count exceeds the configured limit", nil)
	}
	result := DiscoveryResult{
		Platform: PlatformDarwin,
		Options: ResolverOptions{
			TimeoutSeconds: defaultTimeoutSeconds,
			Attempts:       defaultAttempts,
		},
	}

	var current *scutilBlock
	blockCount := 0
	lines := strings.Split(string(input), "\n")
	for lineIndex, rawLine := range lines {
		lineNumber := lineIndex + 1
		if len(rawLine) > limits.MaxLineBytes {
			return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformDarwin, "parse_scutil", "line", lineNumber, "line exceeds the byte limit", nil)
		}
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if isResolverHeader(line) {
			if current != nil {
				if err := appendSCUtilBlock(&result, current, limits); err != nil {
					return DiscoveryResult{}, err
				}
			}
			blockCount++
			if blockCount > limits.MaxResolverBlocks {
				return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "resolver_blocks", lineNumber, "resolver block count exceeds the configured limit", nil)
			}
			current = &scutilBlock{
				ordinal:       blockCount - 1,
				nameservers:   make(map[int]indexedText),
				searchDomains: make(map[int]indexedText),
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "resolver" {
			return DiscoveryResult{}, malformedSCUtil("resolver_header", lineNumber, "resolver header must use 'resolver #N' syntax", nil)
		}
		if current == nil {
			if isKnownSCUtilPrefix(line) {
				return DiscoveryResult{}, malformedSCUtil("property", lineNumber, "resolver property appears outside a resolver block", nil)
			}
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			if isKnownSCUtilPrefix(line) {
				return DiscoveryResult{}, malformedSCUtil("property", lineNumber, "recognized resolver property is missing ':'", nil)
			}
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if err := parseSCUtilProperty(current, key, value, lineNumber, limits); err != nil {
			return DiscoveryResult{}, err
		}
	}
	if current != nil {
		if err := appendSCUtilBlock(&result, current, limits); err != nil {
			return DiscoveryResult{}, err
		}
	}
	if len(result.Resolvers) == 0 && len(result.UnsupportedRoutes) == 0 {
		return DiscoveryResult{}, discoveryError(ErrorNoResolvers, PlatformDarwin, "parse_scutil", "nameserver", 0, "command output contains no usable nameserver", nil)
	}
	return result, nil
}

func isResolverHeader(line string) bool {
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "resolver" || len(fields[1]) < 2 || fields[1][0] != '#' {
		return false
	}
	value, err := strconv.ParseUint(fields[1][1:], 10, 32)
	return err == nil && value > 0
}

func isKnownSCUtilPrefix(line string) bool {
	for _, prefix := range []string{"nameserver", "search domain", "domain", "order", "if_index", "flags", "options", "port", "timeout"} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func parseSCUtilProperty(block *scutilBlock, key, value string, line int, limits Limits) error {
	if index, matched, err := parseIndexedProperty(key, "nameserver"); matched {
		if err != nil {
			return malformedSCUtil("nameserver", line, err.Error(), err)
		}
		if value == "" {
			return malformedSCUtil("nameserver", line, "value is empty", nil)
		}
		if _, duplicate := block.nameservers[index]; duplicate {
			return malformedSCUtil("nameserver", line, "index is duplicated", nil)
		}
		if len(block.nameservers) >= limits.MaxResolvers {
			return discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "nameserver", line, "nameserver count exceeds the configured limit", nil)
		}
		block.nameservers[index] = indexedText{index: index, value: value, line: line}
		return nil
	}
	if index, matched, err := parseIndexedProperty(key, "search domain"); matched {
		if err != nil {
			return malformedSCUtil("search_domain", line, err.Error(), err)
		}
		if _, duplicate := block.searchDomains[index]; duplicate {
			return malformedSCUtil("search_domain", line, "index is duplicated", nil)
		}
		domain, err := normalizeName(value, true)
		if err != nil {
			return malformedSCUtil("search_domain", line, err.Error(), err)
		}
		if len(block.searchDomains) >= limits.MaxSearchDomains {
			return discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "search_domain", line, "search domain count exceeds the configured limit", nil)
		}
		block.searchDomains[index] = indexedText{index: index, value: domain, line: line}
		return nil
	}

	switch key {
	case "domain":
		if block.domainSet {
			return malformedSCUtil("domain", line, "property is duplicated", nil)
		}
		domain, err := normalizeName(value, true)
		if err != nil {
			return malformedSCUtil("domain", line, err.Error(), err)
		}
		block.domain = domain
		block.domainSet = true
	case "order":
		if block.orderSet {
			return malformedSCUtil("order", line, "property is duplicated", nil)
		}
		order, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return malformedSCUtil("order", line, "must be an unsigned decimal integer", err)
		}
		block.order = uint32(order)
		block.orderSet = true
	case "if_index":
		if block.interfaceSet {
			return malformedSCUtil("if_index", line, "property is duplicated", nil)
		}
		index, name, err := parseInterface(value, limits.MaxInterfaceNameBytes)
		if err != nil {
			return malformedSCUtil("if_index", line, err.Error(), err)
		}
		block.interfaceIndex = index
		block.interfaceName = name
		block.interfaceSet = true
	case "flags":
		if block.flags != nil {
			return malformedSCUtil("flags", line, "property is duplicated", nil)
		}
		flags, err := parseFlags(value, limits)
		if err != nil {
			return malformedSCUtil("flags", line, err.Error(), err)
		}
		block.flags = flags
	case "options":
		if block.options != nil {
			return malformedSCUtil("options", line, "property is duplicated", nil)
		}
		options, err := parseSCUtilOptions(value, limits)
		if err != nil {
			return malformedSCUtil("options", line, err.Error(), err)
		}
		block.options = options
	case "port":
		if block.portSet {
			return malformedSCUtil("port", line, "property is duplicated", nil)
		}
		port, err := parseResolverPort(value)
		if err != nil {
			return malformedSCUtil("port", line, err.Error(), err)
		}
		block.port = port
		block.portSet = true
	case "timeout":
		if block.timeoutSet {
			return malformedSCUtil("timeout", line, "property is duplicated", nil)
		}
		timeout, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return malformedSCUtil("timeout", line, "must be an unsigned decimal integer", err)
		}
		block.timeoutRaw = uint32(timeout)
		block.timeoutSeconds = clampOption(uint32(timeout), minimumOptionValue, maximumTimeoutSeconds)
		block.timeoutSet = true
	}
	return nil
}

func parseIndexedProperty(key, prefix string) (int, bool, error) {
	if !strings.HasPrefix(key, prefix) {
		return 0, false, nil
	}
	remainder := strings.TrimPrefix(key, prefix)
	if len(remainder) < 3 || remainder[0] != '[' || remainder[len(remainder)-1] != ']' {
		return 0, true, fmt.Errorf("index must use %s[N] syntax", prefix)
	}
	index, err := strconv.ParseUint(remainder[1:len(remainder)-1], 10, 31)
	if err != nil {
		return 0, true, fmt.Errorf("index must be a non-negative decimal integer")
	}
	return int(index), true, nil
}

func parseInterface(value string, maxNameBytes int) (uint32, string, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields) > 2 {
		return 0, "", fmt.Errorf("must use INDEX or INDEX (NAME) syntax")
	}
	index, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || index == 0 {
		return 0, "", fmt.Errorf("interface index must be a positive decimal integer")
	}
	if len(fields) == 1 {
		return uint32(index), "", nil
	}
	rawName := fields[1]
	if len(rawName) < 3 || rawName[0] != '(' || rawName[len(rawName)-1] != ')' {
		return 0, "", fmt.Errorf("interface name must be parenthesized")
	}
	name := rawName[1 : len(rawName)-1]
	if err := validateInterfaceName(name, maxNameBytes); err != nil {
		return 0, "", err
	}
	return uint32(index), name, nil
}

func validateInterfaceName(value string, maxBytes int) error {
	if value == "" {
		return fmt.Errorf("interface name is empty")
	}
	if len(value) > maxBytes {
		return fmt.Errorf("interface name exceeds the byte limit")
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '(' || character == ')' || character == '%' {
			return fmt.Errorf("interface name contains an unsupported character")
		}
	}
	return nil
}

func parseFlags(value string, limits Limits) ([]string, error) {
	if value == "" {
		return []string{}, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > limits.MaxFlagsPerResolver {
		return nil, fmt.Errorf("flag count exceeds the configured limit")
	}
	flags := make([]string, 0, len(parts))
	for _, part := range parts {
		flag := strings.TrimSpace(part)
		if flag == "" {
			return nil, fmt.Errorf("flag is empty")
		}
		if len(flag) > limits.MaxFlagBytes {
			return nil, fmt.Errorf("flag exceeds the byte limit")
		}
		for _, existing := range flags {
			if strings.EqualFold(existing, flag) {
				return nil, fmt.Errorf("flag is duplicated")
			}
		}
		flags = append(flags, flag)
	}
	return flags, nil
}

func parseSCUtilOptions(value string, limits Limits) ([]string, error) {
	if value == "" {
		return []string{}, nil
	}
	parts := strings.Fields(value)
	if len(parts) > limits.MaxFlagsPerResolver {
		return nil, fmt.Errorf("option count exceeds the configured limit")
	}
	options := make([]string, 0, len(parts))
	for _, option := range parts {
		if len(option) > limits.MaxFlagBytes {
			return nil, fmt.Errorf("option exceeds the byte limit")
		}
		for _, existing := range options {
			if strings.EqualFold(existing, option) {
				return nil, fmt.Errorf("option is duplicated")
			}
		}
		options = append(options, option)
	}
	return options, nil
}

func parseResolverPort(value string) (uint16, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, fmt.Errorf("port must be a decimal integer")
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(parsed), nil
}

func splitSCUtilNameserver(value string) (string, uint16, bool, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", 0, false, fmt.Errorf("resolver address must not contain whitespace")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			zone := address.Zone()
			if dot := strings.LastIndexByte(zone, '.'); dot >= 0 {
				if _, portErr := parseResolverPort(zone[dot+1:]); portErr == nil {
					return "", 0, false, fmt.Errorf("zoned IPv6 address ending in a decimal component is ambiguous; use the resolver port property")
				}
			}
		}
		return value, 0, false, nil
	}

	dot := strings.LastIndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return value, 0, false, nil
	}
	port, portErr := parseResolverPort(value[dot+1:])
	if portErr != nil {
		return value, 0, false, nil
	}
	addressText := value[:dot]
	if _, err := netip.ParseAddr(addressText); err != nil {
		return "", 0, false, fmt.Errorf("dotted resolver port prefix is not an IP literal")
	}
	return addressText, port, true, nil
}

func parseSCUtilEndpoint(value, fallbackZone string, defaultPort uint16) (Endpoint, error) {
	addressText, port, portSet, err := splitSCUtilNameserver(value)
	if err != nil {
		return Endpoint{}, err
	}
	endpoint, err := parseSystemEndpoint(addressText, fallbackZone)
	if err != nil {
		return Endpoint{}, err
	}
	endpoint.port = defaultPort
	if portSet {
		endpoint.port = port
	}
	return endpoint, nil
}

func appendSCUtilBlock(result *DiscoveryResult, block *scutilBlock, limits Limits) error {
	search := sortedIndexedValues(block.searchDomains)
	searchDomains := make([]string, 0, len(search))
	for _, domain := range search {
		searchDomains = append(searchDomains, domain.value)
		result.SearchDomains = appendUniqueName(result.SearchDomains, domain.value)
		if len(result.SearchDomains) > limits.MaxSearchDomains {
			return discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "search_domain", domain.line, "aggregate search domain count exceeds the configured limit", nil)
		}
	}
	port := uint16(53)
	if block.portSet {
		port = block.port
	}
	timeoutSeconds := uint32(defaultTimeoutSeconds)
	if block.timeoutSet {
		timeoutSeconds = block.timeoutSeconds
	}
	scoped := hasFlag(block.flags, "Scoped")
	if scoped && !block.interfaceSet {
		return malformedSCUtil("flags", 0, "Scoped resolver is missing if_index", nil)
	}
	if len(block.nameservers) == 0 {
		configured := block.domainSet || len(block.searchDomains) != 0 || block.orderSet || block.interfaceSet || block.flags != nil || block.options != nil || block.portSet || block.timeoutSet
		if !configured {
			return nil
		}
		result.UnsupportedRoutes = append(result.UnsupportedRoutes, UnsupportedRoute{
			ScopeDomain:              block.domain,
			SearchDomains:            append([]string(nil), searchDomains...),
			Scoped:                   scoped,
			Order:                    block.order,
			OrderSet:                 block.orderSet,
			InterfaceIndex:           block.interfaceIndex,
			InterfaceName:            block.interfaceName,
			Flags:                    append([]string(nil), block.flags...),
			NativeOptions:            append([]string(nil), block.options...),
			Port:                     port,
			TimeoutSeconds:           timeoutSeconds,
			ConfiguredTimeoutSeconds: block.timeoutRaw,
			TimeoutConfigured:        block.timeoutSet,
			Reason:                   "resolver client has no directly usable unicast nameserver",
			discoveryIndex:           block.ordinal,
			groupIndex:               block.ordinal,
		})
		return nil
	}
	servers := sortedIndexedValues(block.nameservers)
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		fallbackZone := ""
		if block.interfaceName != "" {
			fallbackZone = block.interfaceName
		} else if block.interfaceIndex != 0 {
			fallbackZone = strconv.FormatUint(uint64(block.interfaceIndex), 10)
		}
		endpoint, err := parseSCUtilEndpoint(server.value, fallbackZone, port)
		if err != nil {
			return malformedSCUtil("nameserver", server.line, err.Error(), err)
		}
		if endpoint.zone != "" && block.interfaceSet && endpoint.zone != block.interfaceName && endpoint.zone != strconv.FormatUint(uint64(block.interfaceIndex), 10) {
			return malformedSCUtil("nameserver", server.line, "IPv6 zone does not match the resolver interface", nil)
		}
		key := endpointKey(endpoint)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if len(result.Resolvers) >= limits.MaxResolvers {
			return discoveryError(ErrorTooMany, PlatformDarwin, "parse_scutil", "nameserver", server.line, "resolver count exceeds the configured limit", nil)
		}
		resolver := Resolver{
			Endpoint:                 endpoint,
			Source:                   SourceSCUtil,
			ScopeDomain:              block.domain,
			SearchDomains:            append([]string(nil), searchDomains...),
			Order:                    block.order,
			OrderSet:                 block.orderSet,
			InterfaceIndex:           block.interfaceIndex,
			InterfaceName:            block.interfaceName,
			Flags:                    append([]string(nil), block.flags...),
			NativeOptions:            append([]string(nil), block.options...),
			TimeoutSeconds:           timeoutSeconds,
			ConfiguredTimeoutSeconds: block.timeoutRaw,
			TimeoutConfigured:        block.timeoutSet,
			discoveryIndex:           len(result.Resolvers),
			groupIndex:               block.ordinal,
		}
		resolver.Scoped = scoped
		result.Resolvers = append(result.Resolvers, resolver)
	}
	return nil
}

func sortedIndexedValues(values map[int]indexedText) []indexedText {
	indexed := make([]indexedText, 0, len(values))
	for _, value := range values {
		indexed = append(indexed, value)
	}
	sort.Slice(indexed, func(left, right int) bool {
		return indexed[left].index < indexed[right].index
	})
	return indexed
}

func hasFlag(flags []string, expected string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, expected) {
			return true
		}
	}
	return false
}

func malformedSCUtil(field string, line int, message string, err error) error {
	return discoveryError(ErrorMalformed, PlatformDarwin, "parse_scutil", field, line, message, err)
}
