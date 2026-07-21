package dnsengine

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"nodeping/internal/dnsobs"
	"nodeping/internal/systemdns"
)

type resolvedEndpoint struct {
	protocol                 Protocol
	dialAddress              string
	connectIP                net.IP
	serverName               string
	dohURL                   *url.URL
	port                     uint16
	systemPlatform           systemdns.Platform
	systemBindInterfaceIndex uint32
}

// NewTrustedSystemEndpoint converts an opaque native-selection target into an
// engine endpoint. The target seals the endpoint, platform, and route
// interface. It is intentionally absent from Endpoint's wire representation,
// and resolveEndpoint revalidates it before every exchange.
func NewTrustedSystemEndpoint(target systemdns.DialTarget, protocol Protocol) (Endpoint, error) {
	if !target.IsTrustedSystem() {
		return Endpoint{}, fmt.Errorf("%w: system resolver is not from trusted native operating-system selection", ErrInvalidEndpoint)
	}
	if protocol != ProtocolUDP && protocol != ProtocolTCP {
		return Endpoint{}, fmt.Errorf("%w: system resolver requires UDP or TCP", ErrInvalidEndpoint)
	}
	trusted := target
	address := target.Address().String()
	return Endpoint{
		Protocol:      protocol,
		Address:       address,
		ConnectIP:     address,
		Port:          target.Port(),
		trustedSystem: &trusted,
	}, nil
}

func resolveEndpoint(endpoint Endpoint, allowPrivateConnectIP bool) (resolvedEndpoint, error) {
	protocol := Protocol(strings.ToLower(strings.TrimSpace(string(endpoint.Protocol))))
	if protocol == "" {
		protocol = ProtocolUDP
	}
	if !protocol.valid() {
		return resolvedEndpoint{}, fmt.Errorf("%w: unsupported protocol %q", ErrInvalidEndpoint, endpoint.Protocol)
	}
	if endpoint.trustedSystem != nil {
		return resolveTrustedSystemEndpoint(endpoint, protocol)
	}

	address := strings.TrimSpace(endpoint.Address)
	if address == "" {
		return resolvedEndpoint{}, fmt.Errorf("%w: address is required", ErrInvalidEndpoint)
	}
	connectIP, err := parseConnectIP(endpoint.ConnectIP)
	if err != nil {
		return resolvedEndpoint{}, err
	}
	if protocol == ProtocolDoH {
		return resolveDoHEndpoint(endpoint, address, connectIP, allowPrivateConnectIP)
	}
	if strings.Contains(address, "://") {
		return resolvedEndpoint{}, fmt.Errorf("%w: %s address must not be a URL", ErrInvalidEndpoint, protocol)
	}

	host, explicitPort, err := splitAddress(address)
	if err != nil {
		return resolvedEndpoint{}, err
	}
	port := endpoint.Port
	if port == 0 {
		port = protocol.defaultPort()
	}
	if explicitPort != 0 {
		if endpoint.Port != 0 && endpoint.Port != explicitPort {
			return resolvedEndpoint{}, fmt.Errorf("%w: address port and port field disagree", ErrInvalidEndpoint)
		}
		port = explicitPort
	}
	if connectIP == nil {
		connectIP = net.ParseIP(host)
		if connectIP == nil {
			return resolvedEndpoint{}, fmt.Errorf("%w: hostname address requires a fixed connect_ip", ErrInvalidEndpoint)
		}
	} else if addressIP := net.ParseIP(host); addressIP != nil && !addressIP.Equal(connectIP) {
		return resolvedEndpoint{}, fmt.Errorf("%w: address IP and connect_ip disagree", ErrInvalidEndpoint)
	}
	if err := validateConnectIP(connectIP, allowPrivateConnectIP); err != nil {
		return resolvedEndpoint{}, err
	}
	serverName, err := normalizeServerName(endpoint.ServerName)
	if err != nil {
		return resolvedEndpoint{}, err
	}
	if serverName == "" && (protocol == ProtocolDoT || protocol == ProtocolDoQ) {
		return resolvedEndpoint{}, fmt.Errorf("%w: encrypted DNS requires an explicit DNS server_name", ErrInvalidEndpoint)
	}

	return resolvedEndpoint{
		protocol:    protocol,
		dialAddress: net.JoinHostPort(connectIP.String(), strconv.Itoa(int(port))),
		connectIP:   connectIP,
		serverName:  serverName,
		port:        port,
	}, nil
}

func resolveTrustedSystemEndpoint(endpoint Endpoint, protocol Protocol) (resolvedEndpoint, error) {
	trusted := endpoint.trustedSystem
	if trusted == nil || !trusted.IsTrustedSystem() {
		return resolvedEndpoint{}, fmt.Errorf("%w: system resolver provenance is invalid", ErrInvalidEndpoint)
	}
	if protocol != ProtocolUDP && protocol != ProtocolTCP {
		return resolvedEndpoint{}, fmt.Errorf("%w: system resolver requires UDP or TCP", ErrInvalidEndpoint)
	}
	address := trusted.Address().String()
	if endpoint.Address != address || endpoint.ConnectIP != address || endpoint.Port != trusted.Port() || endpoint.ServerName != "" {
		return resolvedEndpoint{}, fmt.Errorf("%w: trusted system resolver fields were modified", ErrInvalidEndpoint)
	}
	connectIP := net.ParseIP(address)
	if connectIP == nil {
		return resolvedEndpoint{}, fmt.Errorf("%w: trusted system resolver address is invalid", ErrInvalidEndpoint)
	}
	return resolvedEndpoint{
		protocol:                 protocol,
		dialAddress:              trusted.DialAddress(),
		connectIP:                connectIP,
		port:                     trusted.Port(),
		systemPlatform:           trusted.Platform(),
		systemBindInterfaceIndex: trusted.BindInterfaceIndex(),
	}, nil
}

func resolveDoHEndpoint(endpoint Endpoint, address string, connectIP net.IP, allowPrivateConnectIP bool) (resolvedEndpoint, error) {
	if !strings.Contains(address, "://") {
		host, explicitPort, err := splitAddress(address)
		if err != nil {
			return resolvedEndpoint{}, err
		}
		port := endpoint.Port
		if port == 0 {
			port = ProtocolDoH.defaultPort()
		}
		if explicitPort != 0 {
			if endpoint.Port != 0 && endpoint.Port != explicitPort {
				return resolvedEndpoint{}, fmt.Errorf("%w: address port and port field disagree", ErrInvalidEndpoint)
			}
			port = explicitPort
		}
		address = "https://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + "/dns-query"
	}
	parsed, err := url.Parse(address)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return resolvedEndpoint{}, fmt.Errorf("%w: DoH address must be an HTTPS URL", ErrInvalidEndpoint)
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return resolvedEndpoint{}, fmt.Errorf("%w: DoH URL must not contain user info, query, or fragment", ErrInvalidEndpoint)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/dns-query"
	}
	normalizedPath, err := dnsobs.NormalizeDoHPath(path)
	if err != nil {
		return resolvedEndpoint{}, fmt.Errorf("%w: invalid DoH path", ErrInvalidEndpoint)
	}
	parsedPath, err := url.Parse(normalizedPath)
	if err != nil {
		return resolvedEndpoint{}, fmt.Errorf("%w: invalid DoH path", ErrInvalidEndpoint)
	}
	parsed.Path = parsedPath.Path
	parsed.RawPath = parsedPath.RawPath
	logicalHost, err := normalizeEndpointHost(parsed.Hostname())
	if err != nil {
		return resolvedEndpoint{}, err
	}
	parsedPort := ProtocolDoH.defaultPort()
	if parsed.Port() != "" {
		value, parseErr := strconv.ParseUint(parsed.Port(), 10, 16)
		if parseErr != nil || value == 0 {
			return resolvedEndpoint{}, fmt.Errorf("%w: invalid DoH port", ErrInvalidEndpoint)
		}
		parsedPort = uint16(value)
		if endpoint.Port != 0 && endpoint.Port != parsedPort {
			return resolvedEndpoint{}, fmt.Errorf("%w: DoH URL port and port field disagree", ErrInvalidEndpoint)
		}
		parsed.Host = net.JoinHostPort(logicalHost, strconv.Itoa(int(parsedPort)))
	} else if endpoint.Port != 0 {
		parsedPort = endpoint.Port
		parsed.Host = net.JoinHostPort(logicalHost, strconv.Itoa(int(parsedPort)))
	} else {
		parsed.Host = logicalHost
		if strings.Contains(logicalHost, ":") {
			parsed.Host = "[" + logicalHost + "]"
		}
	}
	if connectIP == nil {
		connectIP = net.ParseIP(logicalHost)
		if connectIP == nil {
			return resolvedEndpoint{}, fmt.Errorf("%w: DoH hostname requires a fixed connect_ip", ErrInvalidEndpoint)
		}
	} else if addressIP := net.ParseIP(logicalHost); addressIP != nil && !addressIP.Equal(connectIP) {
		return resolvedEndpoint{}, fmt.Errorf("%w: DoH URL IP and connect_ip disagree", ErrInvalidEndpoint)
	}
	if err := validateConnectIP(connectIP, allowPrivateConnectIP); err != nil {
		return resolvedEndpoint{}, err
	}
	serverName, err := normalizeServerName(endpoint.ServerName)
	if err != nil {
		return resolvedEndpoint{}, err
	}
	if serverName == "" {
		return resolvedEndpoint{}, fmt.Errorf("%w: DoH requires an explicit DNS server_name", ErrInvalidEndpoint)
	}
	return resolvedEndpoint{
		protocol:    ProtocolDoH,
		dialAddress: net.JoinHostPort(connectIP.String(), strconv.Itoa(int(parsedPort))),
		connectIP:   connectIP,
		serverName:  serverName,
		dohURL:      parsed,
		port:        parsedPort,
	}, nil
}

func validateConnectIP(ip net.IP, allowPrivate bool) error {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: invalid connect_ip", ErrInvalidEndpoint)
	}
	address = address.Unmap()
	if !allowPrivate && !dnsobs.IsPublicDNSAddress(address) {
		return fmt.Errorf("%w: connect_ip must be a public DNS address", ErrInvalidEndpoint)
	}
	return nil
}

func parseConnectIP(value string) (net.IP, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("%w: connect_ip must be an IP literal", ErrInvalidEndpoint)
	}
	return ip, nil
}

func splitAddress(address string) (string, uint16, error) {
	if host, portText, err := net.SplitHostPort(address); err == nil {
		port, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || port == 0 || strings.TrimSpace(host) == "" {
			return "", 0, fmt.Errorf("%w: invalid address port", ErrInvalidEndpoint)
		}
		normalized, normalizeErr := normalizeEndpointHost(host)
		if normalizeErr != nil {
			return "", 0, normalizeErr
		}
		return normalized, uint16(port), nil
	}
	if net.ParseIP(address) != nil {
		return net.ParseIP(address).String(), 0, nil
	}
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		inner := strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
		if ip := net.ParseIP(inner); ip != nil {
			return ip.String(), 0, nil
		}
	}
	if strings.Contains(address, ":") {
		return "", 0, fmt.Errorf("%w: malformed host and port", ErrInvalidEndpoint)
	}
	if strings.TrimSpace(address) == "" {
		return "", 0, fmt.Errorf("%w: address is required", ErrInvalidEndpoint)
	}
	normalized, err := normalizeEndpointHost(address)
	if err != nil {
		return "", 0, err
	}
	return normalized, 0, nil
}

func normalizeEndpointHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: endpoint host is required", ErrInvalidEndpoint)
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	name, err := dnsobs.NormalizeFQDN(value)
	if err != nil || name == "." {
		return "", fmt.Errorf("%w: invalid endpoint host", ErrInvalidEndpoint)
	}
	return strings.TrimSuffix(name, "."), nil
}

func normalizeServerName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if net.ParseIP(value) != nil {
		return "", fmt.Errorf("%w: server_name must be a DNS host name", ErrInvalidEndpoint)
	}
	name, err := dnsobs.NormalizeFQDN(value)
	if err != nil || name == "." {
		return "", fmt.Errorf("%w: invalid server_name", ErrInvalidEndpoint)
	}
	return strings.TrimSuffix(name, "."), nil
}
