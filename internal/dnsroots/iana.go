package dnsroots

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IANAAnchorSummary struct {
	Zone          string
	AllKeyTags    []uint16
	ActiveKeyTags []uint16
}

type ianaTrustAnchor struct {
	XMLName xml.Name        `xml:"TrustAnchor"`
	ID      string          `xml:"id,attr"`
	Source  string          `xml:"source,attr"`
	Zone    string          `xml:"Zone"`
	Keys    []ianaKeyDigest `xml:"KeyDigest"`
	Unknown []unknownXML    `xml:",any"`
}

type ianaKeyDigest struct {
	ID         string       `xml:"id,attr"`
	ValidFrom  string       `xml:"validFrom,attr"`
	ValidUntil string       `xml:"validUntil,attr"`
	KeyTag     string       `xml:"KeyTag"`
	Algorithm  string       `xml:"Algorithm"`
	DigestType string       `xml:"DigestType"`
	Digest     string       `xml:"Digest"`
	PublicKey  string       `xml:"PublicKey"`
	Flags      string       `xml:"Flags"`
	Unknown    []unknownXML `xml:",any"`
}

type unknownXML struct {
	XMLName xml.Name
}

func ParseIANAAnchorXML(value []byte, at time.Time) (IANAAnchorSummary, error) {
	if len(value) == 0 || len(value) > maxAnchorBytes {
		return IANAAnchorSummary{}, fmt.Errorf("invalid IANA root anchor XML size %d", len(value))
	}
	decoder := xml.NewDecoder(bytes.NewReader(value))
	decoder.Strict = true
	var document ianaTrustAnchor
	if err := decoder.Decode(&document); err != nil {
		return IANAAnchorSummary{}, fmt.Errorf("decode IANA root anchor XML: %w", err)
	}
	var trailing xml.Token
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return IANAAnchorSummary{}, fmt.Errorf("IANA root anchor XML has trailing data")
		}
		return IANAAnchorSummary{}, err
	}
	if document.ID == "" || document.Source != "http://data.iana.org/root-anchors/root-anchors.xml" ||
		strings.TrimSpace(document.Zone) != "." || len(document.Keys) == 0 || len(document.Unknown) != 0 {
		return IANAAnchorSummary{}, fmt.Errorf("unexpected IANA root anchor document identity")
	}
	seen := make(map[uint16]bool, len(document.Keys))
	summary := IANAAnchorSummary{Zone: "."}
	for index, key := range document.Keys {
		if key.ID == "" || len(key.Unknown) != 0 {
			return IANAAnchorSummary{}, fmt.Errorf("invalid IANA key digest %d", index)
		}
		keyTag, err := parseUint16(key.KeyTag)
		if err != nil || keyTag == 0 || seen[keyTag] {
			return IANAAnchorSummary{}, fmt.Errorf("invalid or duplicate IANA key tag %q", key.KeyTag)
		}
		seen[keyTag] = true
		if strings.TrimSpace(key.Algorithm) != "8" || strings.TrimSpace(key.DigestType) != "2" {
			return IANAAnchorSummary{}, fmt.Errorf("unsupported IANA key parameters for %d", keyTag)
		}
		digest := strings.TrimSpace(key.Digest)
		decodedDigest, err := hex.DecodeString(digest)
		if err != nil || len(decodedDigest) != 32 || strings.ToUpper(hex.EncodeToString(decodedDigest)) != digest {
			return IANAAnchorSummary{}, fmt.Errorf("invalid IANA SHA-256 digest for %d", keyTag)
		}
		validFrom, err := time.Parse(time.RFC3339, key.ValidFrom)
		if err != nil {
			return IANAAnchorSummary{}, fmt.Errorf("invalid IANA validFrom for %d", keyTag)
		}
		active := !at.UTC().Before(validFrom.UTC())
		if key.ValidUntil != "" {
			validUntil, err := time.Parse(time.RFC3339, key.ValidUntil)
			if err != nil || !validUntil.After(validFrom) {
				return IANAAnchorSummary{}, fmt.Errorf("invalid IANA validUntil for %d", keyTag)
			}
			active = active && at.UTC().Before(validUntil.UTC())
		}
		if active {
			publicKey, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(key.PublicKey))
			if err != nil || len(publicKey) < 64 || strings.TrimSpace(key.Flags) != "257" {
				return IANAAnchorSummary{}, fmt.Errorf("active IANA key %d is missing DNSKEY material", keyTag)
			}
			summary.ActiveKeyTags = append(summary.ActiveKeyTags, keyTag)
		}
		summary.AllKeyTags = append(summary.AllKeyTags, keyTag)
	}
	sort.Slice(summary.AllKeyTags, func(i, j int) bool { return summary.AllKeyTags[i] < summary.AllKeyTags[j] })
	sort.Slice(summary.ActiveKeyTags, func(i, j int) bool { return summary.ActiveKeyTags[i] < summary.ActiveKeyTags[j] })
	if len(summary.ActiveKeyTags) == 0 {
		return IANAAnchorSummary{}, fmt.Errorf("IANA root anchor XML has no active keys")
	}
	return summary, nil
}

func parseUint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	return uint16(parsed), err
}
