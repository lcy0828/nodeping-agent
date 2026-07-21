package systemdns

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

const (
	defaultTimeoutSeconds = 5
	defaultAttempts       = 2
	maximumNameServers    = 3
	// resolv.conf(5) defines these effective resolver bounds.
	minimumOptionValue    = 1
	maximumTimeoutSeconds = 30
	maximumAttempts       = 5
)

// ParseResolvConf parses bounded resolv.conf input using the production
// defaults. Unknown directives and options are ignored as resolv.conf permits.
// Parsed endpoints are not system-trusted; only native discovery grants trust.
func ParseResolvConf(input []byte) (DiscoveryResult, error) {
	limits, err := normalizeLimits(Limits{})
	if err != nil {
		return DiscoveryResult{}, err
	}
	return parseResolvConf(input, limits)
}

func parseResolvConf(input []byte, limits Limits) (DiscoveryResult, error) {
	if len(input) > limits.MaxInputBytes {
		return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformLinux, "parse_resolv_conf", "input", 0, "configuration exceeds the byte limit", nil)
	}
	if err := validateTextInput(input); err != nil {
		return DiscoveryResult{}, malformedResolv("input", 0, err.Error(), err)
	}
	if bytes.Count(input, []byte{'\n'})+1 > limits.MaxLines {
		return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformLinux, "parse_resolv_conf", "lines", 0, "line count exceeds the configured limit", nil)
	}
	result := DiscoveryResult{
		Platform: PlatformLinux,
		Options: ResolverOptions{
			TimeoutSeconds: defaultTimeoutSeconds,
			Attempts:       defaultAttempts,
		},
	}
	lines := strings.Split(string(input), "\n")
	for lineIndex, rawLine := range lines {
		lineNumber := lineIndex + 1
		if len(rawLine) > limits.MaxLineBytes {
			return DiscoveryResult{}, discoveryError(ErrorTooLarge, PlatformLinux, "parse_resolv_conf", "line", lineNumber, "line exceeds the byte limit", nil)
		}
		line := stripResolvComment(rawLine)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			// resolv.conf has exactly MAXNS effective slots. Once filled,
			// later nameserver lines do not affect the system resolver.
			if len(result.Resolvers) >= maximumNameServers {
				continue
			}
			if len(fields) != 2 {
				return DiscoveryResult{}, malformedResolv("nameserver", lineNumber, "must contain exactly one IP literal", nil)
			}
			endpoint, err := parseSystemEndpoint(fields[1], "")
			if err != nil {
				return DiscoveryResult{}, malformedResolv("nameserver", lineNumber, err.Error(), err)
			}
			if len(result.Resolvers) >= limits.MaxResolvers {
				return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformLinux, "parse_resolv_conf", "nameserver", lineNumber, "resolver count exceeds the configured limit", nil)
			}
			result.Resolvers = append(result.Resolvers, Resolver{
				Endpoint:       endpoint,
				Source:         SourceResolvConf,
				discoveryIndex: len(result.Resolvers),
				groupIndex:     len(result.Resolvers),
			})
		case "domain":
			if len(fields) != 2 {
				return DiscoveryResult{}, malformedResolv("domain", lineNumber, "must contain exactly one DNS suffix", nil)
			}
			domain, err := normalizeName(fields[1], true)
			if err != nil {
				return DiscoveryResult{}, malformedResolv("domain", lineNumber, err.Error(), err)
			}
			result.Domain = domain
			result.SearchDomains = nil
		case "search":
			if len(fields) < 2 {
				return DiscoveryResult{}, malformedResolv("search", lineNumber, "must contain at least one DNS suffix", nil)
			}
			search := make([]string, 0, len(fields)-1)
			for _, value := range fields[1:] {
				domain, err := normalizeName(value, true)
				if err != nil {
					return DiscoveryResult{}, malformedResolv("search", lineNumber, err.Error(), err)
				}
				search = appendUniqueName(search, domain)
				if len(search) > limits.MaxSearchDomains {
					return DiscoveryResult{}, discoveryError(ErrorTooMany, PlatformLinux, "parse_resolv_conf", "search", lineNumber, "search domain count exceeds the configured limit", nil)
				}
			}
			result.Domain = ""
			result.SearchDomains = search
		case "options":
			if err := parseResolvOptions(&result.Options, fields[1:], lineNumber); err != nil {
				return DiscoveryResult{}, err
			}
		}
	}
	if len(result.Resolvers) == 0 {
		endpoint, err := parseSystemEndpoint("127.0.0.1", "")
		if err != nil {
			return DiscoveryResult{}, discoveryError(ErrorMalformed, PlatformLinux, "parse_resolv_conf", "default_nameserver", 0, err.Error(), err)
		}
		result.Resolvers = append(result.Resolvers, Resolver{
			Endpoint:       endpoint,
			Source:         SourceResolvConf,
			discoveryIndex: 0,
			groupIndex:     0,
		})
	}
	search := effectiveSearch(result.Domain, result.SearchDomains)
	for index := range result.Resolvers {
		result.Resolvers[index].SearchDomains = append([]string(nil), search...)
	}
	return result, nil
}

func stripResolvComment(line string) string {
	comment := len(line)
	if index := strings.IndexByte(line, '#'); index >= 0 && index < comment {
		comment = index
	}
	if index := strings.IndexByte(line, ';'); index >= 0 && index < comment {
		comment = index
	}
	return strings.TrimSpace(line[:comment])
}

func parseResolvOptions(options *ResolverOptions, values []string, line int) error {
	for _, value := range values {
		switch {
		case value == "rotate":
			options.Rotate = true
		case strings.HasPrefix(value, "timeout:"):
			number, err := parseUintOption(value, "timeout:")
			if err != nil {
				return malformedResolv("options.timeout", line, err.Error(), err)
			}
			options.ConfiguredTimeoutSeconds = number
			options.TimeoutSeconds = clampOption(number, minimumOptionValue, maximumTimeoutSeconds)
			options.TimeoutConfigured = true
		case strings.HasPrefix(value, "attempts:"):
			number, err := parseUintOption(value, "attempts:")
			if err != nil {
				return malformedResolv("options.attempts", line, err.Error(), err)
			}
			options.ConfiguredAttempts = number
			options.Attempts = clampOption(number, minimumOptionValue, maximumAttempts)
			options.AttemptsConfigured = true
		}
	}
	return nil
}

func parseUintOption(value, prefix string) (uint32, error) {
	raw := strings.TrimPrefix(value, prefix)
	if raw == "" {
		return 0, fmt.Errorf("value is empty")
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("value must be a decimal integer")
	}
	return uint32(parsed), nil
}

func clampOption(value, minimum, maximum uint32) uint32 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func effectiveSearch(domain string, search []string) []string {
	if len(search) != 0 {
		return search
	}
	if domain != "" {
		return []string{domain}
	}
	return nil
}

func malformedResolv(field string, line int, message string, err error) error {
	return discoveryError(ErrorMalformed, PlatformLinux, "parse_resolv_conf", field, line, message, err)
}
