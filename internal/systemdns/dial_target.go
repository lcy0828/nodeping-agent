package systemdns

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

const dialTargetProvenanceDomain = "nodeping.systemdns.native-dial-target.v1\x00"

func newDialTarget(platform Platform, resolver Resolver) (DialTarget, error) {
	if !resolver.Endpoint.IsTrustedSystem() {
		return DialTarget{}, fmt.Errorf("resolver endpoint provenance is invalid")
	}

	var bindInterfaceIndex uint32
	switch platform {
	case PlatformLinux:
		// resolv.conf contains no route-interface metadata. IPv6 link-local
		// routing remains pinned by the endpoint's sealed zone.
	case PlatformDarwin:
		bindInterfaceIndex = resolver.RouteInterfaceIndex
		if bindInterfaceIndex == 0 {
			bindInterfaceIndex = resolver.InterfaceIndex
		}
		if resolver.Scoped && bindInterfaceIndex == 0 {
			return DialTarget{}, fmt.Errorf("scoped macOS resolver is missing its bind interface")
		}
	case PlatformWindows:
		bindInterfaceIndex = resolver.RouteInterfaceIndex
		if bindInterfaceIndex == 0 {
			return DialTarget{}, fmt.Errorf("Windows resolver is missing its route interface")
		}
	default:
		return DialTarget{}, fmt.Errorf("unsupported system DNS platform %q", platform)
	}

	target := DialTarget{
		endpoint:           resolver.Endpoint,
		platform:           platform,
		bindInterfaceIndex: bindInterfaceIndex,
	}
	if err := validateDialTarget(target); err != nil {
		return DialTarget{}, err
	}
	target.provenance = dialTargetDigest(target)
	return target, nil
}

func dialTargetProvenanceValid(target DialTarget) bool {
	if target.provenance == ([32]byte{}) || validateDialTarget(target) != nil {
		return false
	}
	expected := dialTargetDigest(target)
	return subtle.ConstantTimeCompare(target.provenance[:], expected[:]) == 1
}

func validateDialTarget(target DialTarget) error {
	if !target.endpoint.IsTrustedSystem() {
		return fmt.Errorf("resolver endpoint provenance is invalid")
	}
	switch target.platform {
	case PlatformLinux:
		if target.bindInterfaceIndex != 0 {
			return fmt.Errorf("Linux resolv.conf target cannot carry a bind interface")
		}
	case PlatformDarwin:
		// A zero index is valid for an unscoped default resolver.
	case PlatformWindows:
		if target.bindInterfaceIndex == 0 {
			return fmt.Errorf("Windows resolver target requires a route interface")
		}
	default:
		return fmt.Errorf("unsupported system DNS platform %q", target.platform)
	}
	return nil
}

func dialTargetDigest(target DialTarget) [32]byte {
	payload := make([]byte, 0, len(dialTargetProvenanceDomain)+32+len(target.platform)+5)
	payload = append(payload, dialTargetProvenanceDomain...)
	payload = append(payload, target.endpoint.provenance[:]...)
	payload = append(payload, 0)
	payload = append(payload, target.platform...)
	payload = append(payload, 0)
	var interfaceBytes [4]byte
	binary.BigEndian.PutUint32(interfaceBytes[:], target.bindInterfaceIndex)
	payload = append(payload, interfaceBytes[:]...)
	return sha256.Sum256(payload)
}
