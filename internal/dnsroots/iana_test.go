package dnsroots

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseIANAAnchorXMLTracksActiveKSKRollover(t *testing.T) {
	t.Parallel()
	value := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="root" source="http://data.iana.org/root-anchors/root-anchors.xml">
  <Zone>.</Zone>
  <KeyDigest id="old" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
    <KeyTag>19036</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>
    <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
  </KeyDigest>
  <KeyDigest id="current" validFrom="2017-02-02T00:00:00+00:00">
    <KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
    <PublicKey>` + strings.Repeat("QQ", 64) + `==</PublicKey><Flags>257</Flags>
  </KeyDigest>
</TrustAnchor>`)
	// Replace the deliberately simple encoded key with valid base64 for 96 bytes.
	value = []byte(strings.Replace(string(value), strings.Repeat("QQ", 64)+"==", strings.Repeat("QUFB", 32), 1))
	summary, err := ParseIANAAnchorXML(value, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(summary.AllKeyTags, []uint16{19036, 20326}) || !reflect.DeepEqual(summary.ActiveKeyTags, []uint16{20326}) {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestParseIANAAnchorXMLRejectsUnknownOrMissingActiveMaterial(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"unknown": `<TrustAnchor id="root" source="http://data.iana.org/root-anchors/root-anchors.xml"><Zone>.</Zone><Other/></TrustAnchor>`,
		"no keys": `<TrustAnchor id="root" source="http://data.iana.org/root-anchors/root-anchors.xml"><Zone>.</Zone></TrustAnchor>`,
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseIANAAnchorXML([]byte(value), time.Now().UTC()); err == nil {
				t.Fatal("invalid XML was accepted")
			}
		})
	}
}
