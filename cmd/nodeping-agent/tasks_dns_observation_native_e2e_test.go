//go:build dns_native_e2e

package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"nodeping/internal/dnsobs"
)

func TestNativeSystemDNSObservationUDPAndTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("native system DNS E2E is disabled in short mode")
	}

	for _, protocol := range []dnsobs.Protocol{dnsobs.ProtocolUDP, dnsobs.ProtocolTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			request := testSystemDNSRequest("round-native-system-" + string(protocol))
			request.Operations[0].Endpoint.Protocol = protocol
			request.Limits.AttemptTimeoutMS = 5_000
			batch, err := executeDNSObservationRequest(ctx, request, defaultDNSWireEngineFactory, newDNSOperationGate(1), nil)
			if err != nil {
				t.Fatalf("native system DNS %s observation: %v", protocol, err)
			}
			if len(batch.Observations) != 1 {
				t.Fatalf("native system DNS %s observations = %d", protocol, len(batch.Observations))
			}

			observation := batch.Observations[0]
			if observation.Endpoint.Kind != dnsobs.EndpointSystem || observation.Endpoint.Port != 53 {
				t.Fatalf("native system DNS %s endpoint = %+v", protocol, observation.Endpoint)
			}
			if observation.TransportStatus != dnsobs.TransportSuccess || observation.ResponseAttempt < 1 || observation.PeerIP == "" {
				t.Fatalf("native system DNS %s observation = %+v", protocol, observation)
			}
			assertBareNativeDNSPeer(t, "observation", observation.PeerIP)
			for index, attempt := range observation.Attempts {
				if attempt.PeerIP != "" {
					assertBareNativeDNSPeer(t, "attempt", attempt.PeerIP)
				}
				if protocol == dnsobs.ProtocolTCP && attempt.Protocol != dnsobs.ProtocolTCP {
					t.Fatalf("native system DNS TCP attempt %d used %q", index, attempt.Protocol)
				}
			}
		})
	}
}

func assertBareNativeDNSPeer(t testing.TB, field, value string) {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.Zone() != "" || strings.Contains(value, "%") {
		t.Fatalf("native system DNS %s peer is not a bare IP: %q", field, value)
	}
}
