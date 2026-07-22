package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errUnsafeProbeDestination = errors.New("probe target resolved to a private or reserved IP")
	errInvalidProbeIPFamily   = errors.New("ip_family must be ipv4 or ipv6")
	errProbeIPFamilyMismatch  = errors.New("probe target does not have an address in the requested IP family")
	lookupProbeNetIP          = net.DefaultResolver.LookupNetIP
)

type probeIPFamily uint8

const (
	probeIPFamilyAny probeIPFamily = iota
	probeIPFamilyIPv4
	probeIPFamilyIPv6
)

func (f probeIPFamily) String() string {
	switch f {
	case probeIPFamilyIPv4:
		return "ipv4"
	case probeIPFamilyIPv6:
		return "ipv6"
	default:
		return ""
	}
}

func (f probeIPFamily) lookupNetwork() string {
	switch f {
	case probeIPFamilyIPv4:
		return "ip4"
	case probeIPFamilyIPv6:
		return "ip6"
	default:
		return "ip"
	}
}

func (f probeIPFamily) displayName() string {
	switch f {
	case probeIPFamilyIPv4:
		return "IPv4"
	case probeIPFamilyIPv6:
		return "IPv6"
	default:
		return "IP"
	}
}

func probeIPFamilyForAddr(addr netip.Addr) probeIPFamily {
	if !addr.IsValid() {
		return probeIPFamilyAny
	}
	if addr.Unmap().Is4() {
		return probeIPFamilyIPv4
	}
	return probeIPFamilyIPv6
}

func requestedProbeIPFamily(options map[string]any) (probeIPFamily, error) {
	value := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "ip_family")))
	switch value {
	case "", "auto":
		return probeIPFamilyAny, nil
	case "ipv4", "4":
		return probeIPFamilyIPv4, nil
	case "ipv6", "6":
		return probeIPFamilyIPv6, nil
	default:
		return probeIPFamilyAny, fmt.Errorf("%w: got %q", errInvalidProbeIPFamily, value)
	}
}

type probeTargetResolver struct {
	allowPrivate bool
	family       probeIPFamily
	familyErr    error

	mu    sync.Mutex
	cache map[string]netip.Addr
}

type resolvedProbeAddress struct {
	Host string
	Port string
	IP   netip.Addr
}

func newProbeTargetResolver(options map[string]any) *probeTargetResolver {
	family, familyErr := requestedProbeIPFamily(options)
	return &probeTargetResolver{
		allowPrivate: trustedPrivateTargetTask(options),
		family:       family,
		familyErr:    familyErr,
		cache:        make(map[string]netip.Addr),
	}
}

// Private targets are reserved for backend-created service health checks. The
// backend strips these markers from ordinary tasks before dispatch.
func trustedPrivateTargetTask(options map[string]any) bool {
	return boolOptionDefault(options, "allow_private_targets", false) &&
		boolOptionDefault(options, "health_check", false) &&
		strings.EqualFold(strings.TrimSpace(stringOptionAny(options, "health_check_kind")), "service_http")
}

func (r *probeTargetResolver) pinHost(host string, addr netip.Addr) error {
	if r == nil {
		return errors.New("probe target resolver is required")
	}
	if r.familyErr != nil {
		return r.familyErr
	}
	validatedHost, err := validateProbeHost(host)
	if err != nil {
		return err
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return errors.New("probe target address is invalid")
	}
	if r.family != probeIPFamilyAny && probeIPFamilyForAddr(addr) != r.family {
		return fmt.Errorf("%w: target %q is %s but the task requires %s", errProbeIPFamilyMismatch, host, probeIPFamilyForAddr(addr).displayName(), r.family.displayName())
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(validatedHost, "."))
	if !r.allowPrivate && (strings.EqualFold(normalizedHost, "localhost") || !isPublicProbeAddr(addr)) {
		return errUnsafeProbeDestination
	}

	cacheKey := r.family.String() + "\x00" + normalizedHost
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]netip.Addr)
	}
	r.cache[cacheKey] = addr
	r.mu.Unlock()
	return nil
}

func (r *probeTargetResolver) resolveHost(ctx context.Context, host string) (netip.Addr, error) {
	if r.familyErr != nil {
		return netip.Addr{}, r.familyErr
	}
	host, err := validateProbeHost(host)
	if err != nil {
		return netip.Addr{}, err
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	cacheKey := r.family.String() + "\x00" + normalizedHost
	if !r.allowPrivate && strings.EqualFold(normalizedHost, "localhost") {
		return netip.Addr{}, errUnsafeProbeDestination
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if addr, ok := r.cache[cacheKey]; ok {
		return addr, nil
	}

	if addr, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		addr = addr.Unmap()
		if r.family != probeIPFamilyAny && probeIPFamilyForAddr(addr) != r.family {
			return netip.Addr{}, fmt.Errorf("%w: target %q is %s but the task requires %s", errProbeIPFamilyMismatch, host, probeIPFamilyForAddr(addr).displayName(), r.family.displayName())
		}
		if !r.allowPrivate && !isPublicProbeAddr(addr) {
			return netip.Addr{}, errUnsafeProbeDestination
		}
		r.cache[cacheKey] = addr
		return addr, nil
	}

	addrs, err := lookupProbeNetIP(ctx, r.family.lookupNetwork(), host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve probe target %q: %w", host, err)
	}
	if len(addrs) == 0 {
		if r.family != probeIPFamilyAny {
			return netip.Addr{}, fmt.Errorf("%w: probe target %q has no %s address", errProbeIPFamilyMismatch, host, r.family.displayName())
		}
		return netip.Addr{}, fmt.Errorf("probe target %q did not resolve to an IP", host)
	}
	var selected netip.Addr
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if r.family != probeIPFamilyAny && probeIPFamilyForAddr(addr) != r.family {
			continue
		}
		if !r.allowPrivate && !isPublicProbeAddr(addr) {
			return netip.Addr{}, errUnsafeProbeDestination
		}
		if !selected.IsValid() {
			selected = addr
		}
	}
	if !selected.IsValid() {
		if r.family != probeIPFamilyAny {
			return netip.Addr{}, fmt.Errorf("%w: probe target %q has no %s address", errProbeIPFamilyMismatch, host, r.family.displayName())
		}
		return netip.Addr{}, fmt.Errorf("probe target %q did not resolve to a usable IP", host)
	}
	r.cache[cacheKey] = selected
	return selected, nil
}

func (r *probeTargetResolver) resolveHostPort(ctx context.Context, target string) (resolvedProbeAddress, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return resolvedProbeAddress{}, errors.New("probe target is required")
	}
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, "\x00\r\n\t /\\?#@") {
		return resolvedProbeAddress{}, errors.New("probe target contains invalid characters")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return resolvedProbeAddress{}, fmt.Errorf("probe target must use host:port: %w", err)
	}
	port, err = validateProbePort(port)
	if err != nil {
		return resolvedProbeAddress{}, err
	}
	addr, err := r.resolveHost(ctx, host)
	if err != nil {
		return resolvedProbeAddress{}, err
	}
	return resolvedProbeAddress{Host: strings.Trim(host, "[]"), Port: port, IP: addr}, nil
}

func (r *probeTargetResolver) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	resolved, err := r.resolveHostPort(ctx, address)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, defaultProbeDialTimeout(network))}
	return dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), resolved.Port))
}

func validateProbeHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", errors.New("probe target host is required")
	}
	if host != raw || strings.HasPrefix(host, "-") || strings.ContainsAny(host, "\x00\r\n\t /\\?#@") {
		return "", errors.New("probe target host contains invalid characters")
	}
	plain := strings.Trim(host, "[]")
	if plain == "" || len(plain) > 253 {
		return "", errors.New("probe target host is invalid")
	}
	if strings.Contains(plain, "%") {
		return "", errors.New("scoped IP targets are not allowed")
	}
	if strings.Contains(plain, ":") {
		if _, err := netip.ParseAddr(plain); err != nil {
			return "", errors.New("probe target host is invalid")
		}
		return plain, nil
	}
	for _, label := range strings.Split(strings.TrimSuffix(plain, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("probe target host is invalid")
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
				continue
			}
			return "", errors.New("probe target host is invalid")
		}
	}
	return plain, nil
}

func validateProbePort(raw string) (string, error) {
	port := strings.TrimSpace(raw)
	if port == "" || port != raw {
		return "", errors.New("probe target port is required")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
		return "", errors.New("probe target port must be a number between 1 and 65535")
	}
	return port, nil
}

func defaultProbeDialTimeout(network string) time.Duration {
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		return 3 * time.Second
	}
	return 5 * time.Second
}

func isPublicProbeAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedProbePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var reservedProbePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}
