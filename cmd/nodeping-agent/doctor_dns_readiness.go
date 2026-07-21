package main

import (
	"context"

	"nodeping/internal/dnsengine"
	"nodeping/internal/dnstapcollector"
	"nodeping/internal/systemdns"
)

const (
	doctorDNSReasonReady                      = "ready"
	doctorDNSReasonDiscoveryFailed            = "discovery_failed"
	doctorDNSReasonNoResolvers                = "no_resolvers"
	doctorDNSReasonNotConfigured              = "not_configured"
	doctorDNSReasonRequiredComponentsNotReady = "required_components_not_ready"
)

func collectDNSObservationReadiness(ctx context.Context, cfg config) doctorDNSObservationReadiness {
	resolverCount := 0
	discovery, discoveryErr := systemdns.Discover(ctx)
	if discoveryErr == nil {
		resolverCount = len(discovery.Resolvers)
	}

	var engineCapabilities dnsengine.Capabilities
	if engine, err := dnsengine.New(dnsengine.Config{}); err == nil {
		engineCapabilities = engine.Capabilities()
	}
	collectorReadiness := dnstapCollectorComponentReadiness(dnstapcollector.SelfCheck(ctx, ""))
	readiness := dnsObservationReadinessWithCollector(resolverCount, discoveryErr, engineCapabilities, collectorReadiness)
	readiness.Fixtures = dnsEngineFixtureComponentReadiness(dnsengine.SelfCheck(ctx))
	readiness.RootHints, readiness.TrustAnchor = collectDNSRootMaterialReadiness(ctx, cfg)
	finalizeDNSObservationReadiness(&readiness)
	return readiness
}

func dnsObservationReadinessFrom(resolverCount int, discoveryErr error, capabilities dnsengine.Capabilities) doctorDNSObservationReadiness {
	return dnsObservationReadinessWithCollector(resolverCount, discoveryErr, capabilities, unavailableDNSComponent())
}

func dnsObservationReadinessWithCollector(
	resolverCount int,
	discoveryErr error,
	capabilities dnsengine.Capabilities,
	collectorReadiness doctorComponentReadiness,
) doctorDNSObservationReadiness {
	readiness := doctorDNSObservationReadiness{
		ReasonCode:         doctorDNSReasonRequiredComponentsNotReady,
		SystemDNSDiscovery: systemDNSDiscoveryReadiness(resolverCount, discoveryErr),
		WireTransports:     dnsWireCodeAvailability(capabilities),
		UnboundWorker:      unavailableDNSComponent(),
		DNSTapCollector:    collectorReadiness,
		RootHints:          unavailableDNSComponent(),
		TrustAnchor:        unavailableDNSComponent(),
		Fixtures:           unavailableDNSComponent(),
	}
	finalizeDNSObservationReadiness(&readiness)
	return readiness
}

func finalizeDNSObservationReadiness(readiness *doctorDNSObservationReadiness) {
	readiness.Ready = readiness.SystemDNSDiscovery.Ready &&
		readiness.WireTransports.AllAvailable &&
		readiness.Fixtures.Ready
	if readiness.Ready {
		readiness.ReasonCode = doctorDNSReasonReady
	} else {
		readiness.ReasonCode = doctorDNSReasonRequiredComponentsNotReady
	}
}

func dnsEngineFixtureComponentReadiness(result dnsengine.SelfCheckResult) doctorComponentReadiness {
	if result.Ready && result.ReasonCode == dnsengine.SelfCheckReady {
		return doctorComponentReadiness{Ready: true, ReasonCode: doctorDNSReasonReady}
	}
	switch result.ReasonCode {
	case dnsengine.SelfCheckListenerFailed,
		dnsengine.SelfCheckEngineFailed,
		dnsengine.SelfCheckExchangeFailed,
		dnsengine.SelfCheckEvidenceMismatch,
		dnsengine.SelfCheckDeadlineExceeded:
		return doctorComponentReadiness{ReasonCode: string(result.ReasonCode)}
	default:
		return unavailableDNSComponent()
	}
}

func dnstapCollectorComponentReadiness(result dnstapcollector.SelfCheckResult) doctorComponentReadiness {
	if result.Ready && result.ReasonCode == dnstapcollector.SelfCheckReady {
		return doctorComponentReadiness{Ready: true, ReasonCode: doctorDNSReasonReady}
	}
	switch result.ReasonCode {
	case dnstapcollector.SelfCheckListenerFailed,
		dnstapcollector.SelfCheckAcceptFailed,
		dnstapcollector.SelfCheckProducerFailed,
		dnstapcollector.SelfCheckCollectionFailed,
		dnstapcollector.SelfCheckEvidenceMismatch,
		dnstapcollector.SelfCheckDeadlineExceeded:
		return doctorComponentReadiness{ReasonCode: result.ReasonCode}
	default:
		return doctorComponentReadiness{ReasonCode: doctorDNSReasonNotConfigured}
	}
}

func systemDNSDiscoveryReadiness(resolverCount int, discoveryErr error) doctorComponentReadiness {
	switch {
	case discoveryErr != nil:
		return doctorComponentReadiness{ReasonCode: doctorDNSReasonDiscoveryFailed}
	case resolverCount < 1:
		return doctorComponentReadiness{ReasonCode: doctorDNSReasonNoResolvers}
	default:
		return doctorComponentReadiness{Ready: true, ReasonCode: doctorDNSReasonReady}
	}
}

func dnsWireCodeAvailability(capabilities dnsengine.Capabilities) doctorDNSWireCodeAvailability {
	availability := doctorDNSWireCodeAvailability{}
	for _, protocol := range capabilities.WireProtocols {
		switch protocol {
		case dnsengine.ProtocolUDP:
			availability.UDP = true
		case dnsengine.ProtocolTCP:
			availability.TCP = true
		case dnsengine.ProtocolDoT:
			availability.DoT = true
		case dnsengine.ProtocolDoH:
			availability.DoH = true
		case dnsengine.ProtocolDoQ:
			availability.DoQ = true
		}
	}
	availability.AllAvailable = availability.UDP && availability.TCP && availability.DoT && availability.DoH && availability.DoQ
	return availability
}

func unavailableDNSComponent() doctorComponentReadiness {
	return doctorComponentReadiness{ReasonCode: doctorDNSReasonNotConfigured}
}

func dnsObservationDoctorChecks(readiness doctorDNSObservationReadiness) []doctorCheck {
	checks := []doctorCheck{
		dnsCodeDoctorCheck("dns_wire_udp_code", "DNS UDP transport code", readiness.WireTransports.UDP),
		dnsCodeDoctorCheck("dns_wire_tcp_code", "DNS TCP transport code", readiness.WireTransports.TCP),
		dnsCodeDoctorCheck("dns_wire_dot_code", "DNS DoT transport code", readiness.WireTransports.DoT),
		dnsCodeDoctorCheck("dns_wire_doh_code", "DNS DoH transport code", readiness.WireTransports.DoH),
		dnsCodeDoctorCheck("dns_wire_doq_code", "DNS DoQ transport code", readiness.WireTransports.DoQ),
		dnsReadinessDoctorCheck("dns_unbound_worker", "DNS Unbound worker", readiness.UnboundWorker.Ready, readiness.UnboundWorker.ReasonCode),
		dnsReadinessDoctorCheck("dns_dnstap_collector", "DNS dnstap collector", readiness.DNSTapCollector.Ready, readiness.DNSTapCollector.ReasonCode),
		dnsReadinessDoctorCheck("dns_root_hints", "DNS root hints", readiness.RootHints.Ready, readiness.RootHints.ReasonCode),
		dnsReadinessDoctorCheck("dns_trust_anchor", "DNS trust anchor", readiness.TrustAnchor.Ready, readiness.TrustAnchor.ReasonCode),
		dnsReadinessDoctorCheck("dns_local_fixtures", "DNS local fixtures", readiness.Fixtures.Ready, readiness.Fixtures.ReasonCode),
	}
	return checks
}

func dnsSystemDiscoveryDoctorCheck(readiness doctorDNSObservationReadiness) doctorCheck {
	return dnsReadinessDoctorCheck(
		"dns_system_discovery",
		"DNS system discovery",
		readiness.SystemDNSDiscovery.Ready,
		readiness.SystemDNSDiscovery.ReasonCode,
	)
}

func dnsReadinessDoctorCheck(key, name string, ready bool, reasonCode string) doctorCheck {
	if ready && reasonCode == doctorDNSReasonReady {
		return doctorCheck{Key: key, Name: name, Status: "ok", Message: reasonCode}
	}
	return doctorCheck{Key: key, Name: name, Status: "warn", Message: reasonCode}
}

func dnsCodeDoctorCheck(key, name string, available bool) doctorCheck {
	if available {
		return doctorCheck{Key: key, Name: name, Status: "ok", Message: "code_available"}
	}
	return doctorCheck{Key: key, Name: name, Status: "warn", Message: "code_unavailable"}
}
