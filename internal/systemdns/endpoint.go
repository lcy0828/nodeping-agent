package systemdns

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/netip"
	"strings"
)

const endpointProvenanceDomain = "nodeping.systemdns.native-endpoint.v1\x00"

func parseSystemEndpoint(value, fallbackZone string) (Endpoint, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return Endpoint{}, fmt.Errorf("resolver address must be a non-empty IP literal without whitespace")
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return Endpoint{}, fmt.Errorf("resolver address must be an IP literal: %w", err)
	}

	zone := address.Zone()
	address = address.WithZone("").Unmap()
	if zone == "" && address.Is6() && address.IsLinkLocalUnicast() {
		zone = fallbackZone
	}
	if err := validateZone(address, zone); err != nil {
		return Endpoint{}, err
	}
	if address.IsUnspecified() {
		return Endpoint{}, fmt.Errorf("unspecified resolver address is not usable")
	}
	if address.IsMulticast() {
		return Endpoint{}, fmt.Errorf("multicast resolver address is not usable")
	}
	if address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return Endpoint{}, fmt.Errorf("broadcast resolver address is not usable")
	}
	if address.Is6() && address.IsLinkLocalUnicast() && zone == "" {
		return Endpoint{}, fmt.Errorf("IPv6 link-local resolver requires a zone")
	}

	return Endpoint{
		address: address,
		zone:    zone,
		port:    53,
	}, nil
}

func sealEndpoint(endpoint Endpoint) (Endpoint, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return Endpoint{}, err
	}
	endpoint.provenance = endpointDigest(endpoint)
	return endpoint, nil
}

func endpointProvenanceValid(endpoint Endpoint) bool {
	if err := validateEndpoint(endpoint); err != nil {
		return false
	}
	expected := endpointDigest(endpoint)
	return subtle.ConstantTimeCompare(endpoint.provenance[:], expected[:]) == 1
}

func endpointDigest(endpoint Endpoint) [32]byte {
	payload := endpointProvenanceDomain + endpoint.address.String() + "\x00" + endpoint.zone + "\x00" + fmt.Sprint(endpoint.port)
	return sha256.Sum256([]byte(payload))
}

func validateEndpoint(endpoint Endpoint) error {
	address := endpoint.address
	if !address.IsValid() || address.Zone() != "" {
		return fmt.Errorf("resolver address must be a valid bare IP address")
	}
	if endpoint.port == 0 {
		return fmt.Errorf("resolver port must be non-zero")
	}
	if err := validateZone(address, endpoint.zone); err != nil {
		return err
	}
	if address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("resolver address is not usable")
	}
	if address.Is6() && address.IsLinkLocalUnicast() && endpoint.zone == "" {
		return fmt.Errorf("IPv6 link-local resolver requires a zone")
	}
	return nil
}

func validateZone(address netip.Addr, zone string) error {
	if zone == "" {
		return nil
	}
	if !address.Is6() {
		return fmt.Errorf("zone is only valid for an IPv6 resolver")
	}
	if !address.IsLinkLocalUnicast() {
		return fmt.Errorf("zone is only accepted for an IPv6 link-local resolver")
	}
	if len(zone) > 64 {
		return fmt.Errorf("resolver zone exceeds 64 bytes")
	}
	for _, character := range zone {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return fmt.Errorf("resolver zone contains an unsupported character")
	}
	return nil
}

func endpointKey(endpoint Endpoint) string {
	return endpoint.address.String() + "%" + endpoint.zone + ":" + fmt.Sprint(endpoint.port)
}
