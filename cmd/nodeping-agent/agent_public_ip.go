package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	publicIPRequestTimeout   = 5 * time.Second
	publicIPDiscoveryTimeout = 8 * time.Second
)

var publicIPDiscoveryEndpoints = map[probeIPFamily][]string{
	probeIPFamilyIPv4: {
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
	},
	probeIPFamilyIPv6: {
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	},
}

type publicIPDiscovery struct {
	IPv4 string
	IPv6 string
}

type publicIPFamilyResult struct {
	family probeIPFamily
	ip     string
}

func (d publicIPDiscovery) primary() string {
	if d.IPv4 != "" {
		return d.IPv4
	}
	return d.IPv6
}

func (d publicIPDiscovery) families() []string {
	families := make([]string, 0, 2)
	if d.IPv4 != "" {
		families = append(families, probeIPFamilyIPv4.String())
	}
	if d.IPv6 != "" {
		families = append(families, probeIPFamilyIPv6.String())
	}
	return families
}

// discoverPublicIP remains the compatibility entry point for callers that
// expect one primary address. New reporting code uses discoverPublicIPs.
func discoverPublicIP(ctx context.Context) string {
	discoveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := discoverPublicIPFamilies(discoveryCtx)
	var ipv6 string
	ipv4Done := false
	ipv6Done := false
	for range 2 {
		result := <-results
		if result.family == probeIPFamilyIPv4 {
			if result.ip != "" {
				return result.ip
			}
			ipv4Done = true
			if ipv6Done {
				return ipv6
			}
			continue
		}
		ipv6 = result.ip
		ipv6Done = true
		if ipv4Done {
			return ipv6
		}
	}
	return ipv6
}

func discoverPublicIPs(ctx context.Context) publicIPDiscovery {
	results := discoverPublicIPFamilies(ctx)
	discovery := publicIPDiscovery{}
	for range 2 {
		result := <-results
		switch result.family {
		case probeIPFamilyIPv4:
			discovery.IPv4 = result.ip
		case probeIPFamilyIPv6:
			discovery.IPv6 = result.ip
		}
	}
	return discovery
}

func discoverPublicIPFamilies(ctx context.Context) <-chan publicIPFamilyResult {
	results := make(chan publicIPFamilyResult, 2)
	for _, family := range []probeIPFamily{probeIPFamilyIPv4, probeIPFamilyIPv6} {
		family := family
		go func() {
			results <- publicIPFamilyResult{family: family, ip: discoverPublicIPFamily(ctx, family)}
		}()
	}
	return results
}

func discoverPublicIPForOptions(ctx context.Context, options map[string]any) (string, error) {
	family, err := requestedProbeIPFamily(options)
	if err != nil {
		return "", err
	}
	if family == probeIPFamilyAny {
		ip := discoverPublicIP(ctx)
		if ip == "" {
			return "", errors.New("public IP discovery failed")
		}
		return ip, nil
	}
	ip := discoverPublicIPFamily(ctx, family)
	if ip == "" {
		return "", errors.New("public " + family.displayName() + " discovery failed")
	}
	return ip, nil
}

func discoverPublicIPFamily(ctx context.Context, family probeIPFamily) string {
	if family != probeIPFamilyIPv4 && family != probeIPFamilyIPv6 {
		return ""
	}
	familyCtx, cancel := context.WithTimeout(ctx, publicIPDiscoveryTimeout)
	defer cancel()
	client := newPublicIPHTTPClient(family)
	defer client.CloseIdleConnections()
	return discoverPublicIPFromEndpoints(familyCtx, family, publicIPDiscoveryEndpoints[family], client)
}

func discoverPublicIPFromEndpoints(ctx context.Context, family probeIPFamily, endpoints []string, client *http.Client) string {
	if client == nil || (family != probeIPFamilyIPv4 && family != probeIPFamilyIPv6) {
		return ""
	}
	for _, endpoint := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			continue
		}
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(string(body)))
		if parseErr == nil {
			addr = addr.Unmap()
			if probeIPFamilyForAddr(addr) == family && isPublicProbeAddr(addr) {
				return addr.String()
			}
		}
	}
	return ""
}

func newPublicIPHTTPClient(family probeIPFamily) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = publicIPFamilyDialContext(family, (&net.Dialer{}).DialContext)
	return &http.Client{
		Timeout:       publicIPRequestTimeout,
		Transport:     transport,
		CheckRedirect: secureControlPlaneRedirect,
	}
}

type publicIPDialContextFunc func(context.Context, string, string) (net.Conn, error)

func publicIPFamilyDialContext(family probeIPFamily, dial publicIPDialContextFunc) publicIPDialContextFunc {
	return func(ctx context.Context, _ string, address string) (net.Conn, error) {
		network := "tcp4"
		if family == probeIPFamilyIPv6 {
			network = "tcp6"
		}
		return dial(ctx, network, address)
	}
}
