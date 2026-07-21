package systemdns_test

import (
	"encoding/json"
	"testing"

	"nodeping/internal/systemdns"
)

func TestEndpointCannotBeForgedByExternalStructOrJSON(t *testing.T) {
	t.Parallel()

	endpoint := systemdns.Endpoint{}
	if endpoint.IsTrustedSystem() {
		t.Fatal("externally constructible zero endpoint is trusted")
	}
	err := json.Unmarshal([]byte(`{"address":"127.0.0.1","zone":"","port":53,"provenance":"system"}`), &endpoint)
	if err == nil {
		t.Fatal("Endpoint JSON decoding unexpectedly succeeded")
	}
	if endpoint.IsTrustedSystem() {
		t.Fatal("JSON manufactured a trusted endpoint")
	}
}

func TestDialTargetCannotBeForgedByExternalStructOrJSON(t *testing.T) {
	t.Parallel()

	target := systemdns.DialTarget{}
	if target.IsTrustedSystem() {
		t.Fatal("externally constructible zero dial target is trusted")
	}
	err := json.Unmarshal([]byte(`{"address":"127.0.0.1","port":53,"platform":"linux","bind_interface_index":1}`), &target)
	if err == nil {
		t.Fatal("DialTarget JSON decoding unexpectedly succeeded")
	}
	if target.IsTrustedSystem() {
		t.Fatal("JSON manufactured a trusted dial target")
	}
}
