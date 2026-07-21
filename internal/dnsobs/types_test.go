package dnsobs

import (
	"errors"
	"reflect"
	"testing"
)

func TestSupportedQueryTypesAreExactAndDefensive(t *testing.T) {
	want := []RRType{
		RRTypeA, RRTypeAAAA, RRTypeCNAME, RRTypeMX, RRTypeTXT, RRTypeNS,
		RRTypeSOA, RRTypeCAA, RRTypeSRV, RRTypePTR, RRTypeDS, RRTypeDNSKEY,
		RRTypeTLSA, RRTypeSVCB, RRTypeHTTPS,
	}
	got := SupportedQueryTypes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedQueryTypes() = %v, want %v", got, want)
	}
	got[0] = RRTypeTXT
	if SupportedQueryTypes()[0] != RRTypeA {
		t.Fatal("SupportedQueryTypes returned mutable package storage")
	}
}

func TestEnumsRejectUnknownValues(t *testing.T) {
	if Mode("forward").Valid() || EndpointKind("resolver_pool").Valid() || Protocol("https").Valid() {
		t.Fatal("transport enums accepted unknown values")
	}
	if TransportStatus("failed").Valid() || DNSOutcome("other").Valid() || Comparison("matched").Valid() || DNSSECStatus("valid").Valid() {
		t.Fatal("result enums accepted unknown values")
	}
	if NSState("fully_synced").Valid() {
		t.Fatal("NS state accepted a misleading universal synchronization state")
	}
}

func TestObservationFullRCode(t *testing.T) {
	base := uint8(0)
	extended := uint8(1)
	observation := Observation{RCode: &base, ExtendedRCode: &extended}
	if got, ok := observation.FullRCode(); !ok || got != 16 {
		t.Fatalf("FullRCode() = %d, %v, want 16, true", got, ok)
	}
	if _, ok := (Observation{}).FullRCode(); ok {
		t.Fatal("FullRCode reported an absent response as present")
	}
}

func TestValidateSchemaReturnsStructuredError(t *testing.T) {
	err := ValidateSchema("dns-observation/v2")
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T, want *ValidationError", err)
	}
	if validationErr.Field != "schema" || validationErr.Code != "UNSUPPORTED_SCHEMA" {
		t.Fatalf("validation error = %+v", validationErr)
	}
}
