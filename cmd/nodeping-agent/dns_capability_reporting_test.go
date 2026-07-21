package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nodeping/internal/dnsengine"
	"nodeping/internal/dnstapcollector"
)

func TestRegisterPayloadWithholdsDNSObserveCapabilityWhenWireCodeIsAvailable(t *testing.T) {
	readiness := failClosedDNSReadinessWithWireCode(t)
	seedDependencySnapshotForDNSCapabilityTest(t, readiness)

	payloads := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/register" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payloads <- payload
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"agent_id":"agent-test","agent_token":"agent-token"}`)
	}))
	defer server.Close()

	if _, err := registerAgent(context.Background(), config{
		ServerURL:   server.URL,
		Token:       "binding-token",
		AgentID:     "agent-test",
		Version:     "nodeping-agent/test",
		Concurrency: 4,
		HTTPClient:  server.Client(),
	}); err != nil {
		t.Fatalf("registerAgent: %v", err)
	}
	requireFailClosedDNSCapabilityPayload(t, <-payloads)
}

func TestHeartbeatPayloadWithholdsDNSObserveCapabilityWhenWireCodeIsAvailable(t *testing.T) {
	readiness := failClosedDNSReadinessWithWireCode(t)
	seedDependencySnapshotForDNSCapabilityTest(t, readiness)

	payloads := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/heartbeat" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
		select {
		case payloads <- payload:
		default:
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		heartbeatLoop(ctx, config{
			ServerURL:         server.URL,
			AgentID:           "agent-test",
			AgentToken:        "agent-token",
			Version:           "nodeping-agent/test",
			Concurrency:       4,
			HeartbeatInterval: time.Hour,
			HTTPClient:        server.Client(),
		})
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case payload := <-payloads:
		requireFailClosedDNSCapabilityPayload(t, payload)
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat request was not received")
	}
}

func TestDNSObservationReadinessRedactsDiscoveryErrors(t *testing.T) {
	const sensitive = "/var/lib/nodeping/private/token-value"
	readiness := dnsObservationReadinessFrom(0, errors.New(sensitive), dnsengine.Capabilities{})
	if readiness.SystemDNSDiscovery.Ready || readiness.SystemDNSDiscovery.ReasonCode != doctorDNSReasonDiscoveryFailed {
		t.Fatalf("system DNS discovery readiness = %+v", readiness.SystemDNSDiscovery)
	}
	raw, err := json.Marshal(readiness)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(sensitive)) || bytes.Contains(raw, []byte("token-value")) {
		t.Fatalf("readiness leaked discovery error: %s", raw)
	}
}

func TestReadyDNSTapCollectorDoesNotEnableAggregateCapability(t *testing.T) {
	engine, err := dnsengine.New(dnsengine.Config{})
	if err != nil {
		t.Fatalf("create DNS engine: %v", err)
	}
	component := dnstapCollectorComponentReadiness(dnstapcollector.SelfCheckResult{
		Ready: true, ReasonCode: dnstapcollector.SelfCheckReady,
	})
	readiness := dnsObservationReadinessWithCollector(1, nil, engine.Capabilities(), component)
	if !readiness.DNSTapCollector.Ready || readiness.DNSTapCollector.ReasonCode != doctorDNSReasonReady {
		t.Fatalf("collector readiness = %+v", readiness.DNSTapCollector)
	}
	if readiness.Ready || readiness.ReasonCode != doctorDNSReasonRequiredComponentsNotReady {
		t.Fatalf("aggregate readiness escaped fail-closed state: %+v", readiness)
	}
	for name, component := range map[string]doctorComponentReadiness{
		"unbound": readiness.UnboundWorker, "root_hints": readiness.RootHints,
		"trust_anchor": readiness.TrustAnchor, "fixtures": readiness.Fixtures,
	} {
		if component.Ready {
			t.Fatalf("%s unexpectedly ready: %+v", name, component)
		}
	}
}

func TestDNSTapCollectorReadinessReasonIsAllowlisted(t *testing.T) {
	component := dnstapCollectorComponentReadiness(dnstapcollector.SelfCheckResult{
		ReasonCode: dnstapcollector.SelfCheckEvidenceMismatch,
	})
	if component.Ready || component.ReasonCode != dnstapcollector.SelfCheckEvidenceMismatch {
		t.Fatalf("known failure = %+v", component)
	}
	unknown := dnstapCollectorComponentReadiness(dnstapcollector.SelfCheckResult{ReasonCode: "/private/token-value"})
	if unknown.Ready || unknown.ReasonCode != doctorDNSReasonNotConfigured {
		t.Fatalf("unknown failure was not redacted: %+v", unknown)
	}
}

func TestCoreDNSReadinessDoesNotDependOnAdvancedIterativeComponents(t *testing.T) {
	engine, err := dnsengine.New(dnsengine.Config{})
	if err != nil {
		t.Fatalf("create DNS engine: %v", err)
	}
	readiness := dnsObservationReadinessWithCollector(1, nil, engine.Capabilities(), unavailableDNSComponent())
	readiness.Fixtures = dnsEngineFixtureComponentReadiness(dnsengine.SelfCheckResult{
		Ready: true, ReasonCode: dnsengine.SelfCheckReady,
	})
	finalizeDNSObservationReadiness(&readiness)
	if !readiness.Ready || readiness.ReasonCode != doctorDNSReasonReady {
		t.Fatalf("core readiness = %+v", readiness)
	}
	for name, component := range map[string]doctorComponentReadiness{
		"unbound_worker": readiness.UnboundWorker,
		"dnstap":         readiness.DNSTapCollector,
		"root_hints":     readiness.RootHints,
		"trust_anchor":   readiness.TrustAnchor,
	} {
		if component.Ready {
			t.Fatalf("advanced component %s unexpectedly ready: %+v", name, component)
		}
	}

	snapshot := doctorSnapshotFromChecks(nil, config{})
	snapshot.DNSObservationReadiness = readiness
	appendDNSObservationCapability(&snapshot)
	if !stringSliceContains(snapshot.Capabilities, dnsObserveCapability) {
		t.Fatalf("ready core capability missing: %+v", snapshot.Capabilities)
	}
}

func TestCoreDNSFixtureFailureWithholdsCapability(t *testing.T) {
	engine, err := dnsengine.New(dnsengine.Config{})
	if err != nil {
		t.Fatalf("create DNS engine: %v", err)
	}
	readiness := dnsObservationReadinessWithCollector(1, nil, engine.Capabilities(), unavailableDNSComponent())
	readiness.Fixtures = dnsEngineFixtureComponentReadiness(dnsengine.SelfCheckResult{
		ReasonCode: dnsengine.SelfCheckEvidenceMismatch,
	})
	finalizeDNSObservationReadiness(&readiness)
	snapshot := doctorSnapshotFromChecks(nil, config{})
	snapshot.DNSObservationReadiness = readiness
	appendDNSObservationCapability(&snapshot)
	if readiness.Ready || stringSliceContains(snapshot.Capabilities, dnsObserveCapability) {
		t.Fatalf("failed fixture enabled capability: readiness=%+v capabilities=%v", readiness, snapshot.Capabilities)
	}
}

func failClosedDNSReadinessWithWireCode(t *testing.T) doctorDNSObservationReadiness {
	t.Helper()
	engine, err := dnsengine.New(dnsengine.Config{})
	if err != nil {
		t.Fatalf("create DNS wire engine: %v", err)
	}
	readiness := dnsObservationReadinessWithCollector(1, nil, engine.Capabilities(), doctorComponentReadiness{
		Ready: true, ReasonCode: doctorDNSReasonReady,
	})
	if !readiness.WireTransports.AllAvailable || !readiness.WireTransports.UDP || !readiness.WireTransports.TCP ||
		!readiness.WireTransports.DoT || !readiness.WireTransports.DoH || !readiness.WireTransports.DoQ {
		t.Fatalf("wire code availability = %+v", readiness.WireTransports)
	}
	if readiness.Ready || readiness.ReasonCode != doctorDNSReasonRequiredComponentsNotReady {
		t.Fatalf("incomplete readiness must fail closed: %+v", readiness)
	}
	if !readiness.DNSTapCollector.Ready || readiness.DNSTapCollector.ReasonCode != doctorDNSReasonReady {
		t.Fatalf("dnstap collector readiness = %+v", readiness.DNSTapCollector)
	}
	for name, component := range map[string]doctorComponentReadiness{
		"unbound_worker": readiness.UnboundWorker,
		"root_hints":     readiness.RootHints,
		"trust_anchor":   readiness.TrustAnchor,
		"fixtures":       readiness.Fixtures,
	} {
		if component.Ready || component.ReasonCode != doctorDNSReasonNotConfigured {
			t.Fatalf("%s readiness = %+v", name, component)
		}
	}
	discoveryCheck := dnsSystemDiscoveryDoctorCheck(readiness)
	if discoveryCheck.Key != "dns_system_discovery" || discoveryCheck.Status != "ok" {
		t.Fatalf("system DNS discovery doctor row = %+v", discoveryCheck)
	}
	return readiness
}

func seedDependencySnapshotForDNSCapabilityTest(t *testing.T, readiness doctorDNSObservationReadiness) {
	t.Helper()
	checks := []doctorCheck{
		{Key: "dns_lookup", Name: "dns lookup", Status: "ok"},
		dnsSystemDiscoveryDoctorCheck(readiness),
	}
	snapshot := doctorSnapshotFromChecks(checks, config{Version: "nodeping-agent/test", AgentID: "agent-test"})
	snapshot.DNSObservationReadiness = readiness

	dependencySnapshotCache.Lock()
	previousSnapshot := dependencySnapshotCache.snapshot
	previousExpiry := dependencySnapshotCache.expires
	dependencySnapshotCache.snapshot = snapshot
	dependencySnapshotCache.expires = time.Now().Add(time.Hour)
	dependencySnapshotCache.Unlock()
	t.Cleanup(func() {
		dependencySnapshotCache.Lock()
		dependencySnapshotCache.snapshot = previousSnapshot
		dependencySnapshotCache.expires = previousExpiry
		dependencySnapshotCache.Unlock()
	})
}

func requireFailClosedDNSCapabilityPayload(t *testing.T, payload map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(dnsObserveCapability)) {
		t.Fatalf("incomplete Agent advertised %q: %s", dnsObserveCapability, raw)
	}

	dependencies, ok := payload["dependency_status"].(map[string]any)
	if !ok {
		t.Fatalf("dependency_status missing: %+v", payload)
	}
	dependencyRaw, err := json.Marshal(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	var serverStatus struct {
		DNSObservationReadiness struct {
			Ready          bool `json:"ready"`
			WireTransports struct {
				AllAvailable bool `json:"all_available"`
			} `json:"wire_transports"`
		} `json:"dns_observation_readiness"`
	}
	if err := json.Unmarshal(dependencyRaw, &serverStatus); err != nil {
		t.Fatalf("decode server dependency status: %v", err)
	}
	if serverStatus.DNSObservationReadiness.Ready || !serverStatus.DNSObservationReadiness.WireTransports.AllAvailable {
		t.Fatalf("server readiness contract mismatch: %+v", serverStatus.DNSObservationReadiness)
	}
	checks, ok := dependencies["checks"].([]any)
	if !ok {
		t.Fatalf("dependency checks missing: %+v", dependencies)
	}
	discoveryCheckFound := false
	for _, rawCheck := range checks {
		check, ok := rawCheck.(map[string]any)
		if ok && check["key"] == "dns_system_discovery" && check["status"] == "ok" {
			discoveryCheckFound = true
			break
		}
	}
	if !discoveryCheckFound {
		t.Fatalf("dns_system_discovery=ok check missing: %+v", checks)
	}
	readiness, ok := dependencies["dns_observation_readiness"].(map[string]any)
	if !ok {
		t.Fatalf("DNS readiness missing: %+v", dependencies)
	}
	if readiness["ready"] != false || readiness["reason_code"] != doctorDNSReasonRequiredComponentsNotReady {
		t.Fatalf("DNS readiness did not fail closed: %+v", readiness)
	}
	wire, ok := readiness["wire_transports"].(map[string]any)
	if !ok || wire["all_available"] != true {
		t.Fatalf("wire code availability missing: %+v", readiness)
	}
	for _, key := range []string{"udp", "tcp", "dot", "doh", "doq"} {
		if wire[key] != true {
			t.Fatalf("wire code %q = %#v, want true: %+v", key, wire[key], wire)
		}
	}
	collector, ok := readiness["dnstap_collector"].(map[string]any)
	if !ok || collector["ready"] != true || collector["reason_code"] != doctorDNSReasonReady {
		t.Fatalf("dnstap collector readiness missing: %+v", readiness["dnstap_collector"])
	}
	for _, key := range []string{"unbound_worker", "root_hints", "trust_anchor", "fixtures"} {
		component, ok := readiness[key].(map[string]any)
		if !ok || component["ready"] != false || component["reason_code"] != doctorDNSReasonNotConfigured {
			t.Fatalf("component %q did not fail closed: %+v", key, readiness[key])
		}
	}
	discovery, ok := readiness["system_dns_discovery"].(map[string]any)
	if !ok || discovery["ready"] != true || discovery["reason_code"] != doctorDNSReasonReady {
		t.Fatalf("system DNS discovery status missing: %+v", readiness)
	}
}
