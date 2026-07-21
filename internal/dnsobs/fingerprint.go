package dnsobs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strings"
	"unicode/utf8"
)

const fingerprintPrefix = RRSetFingerprintAlgorithm + ":"

func FingerprintRRSet(owner string, rrType RRType, class DNSClass, canonicalRData []string) (string, error) {
	normalizedOwner, err := NormalizeWireName(owner)
	if err != nil {
		return "", fmt.Errorf("normalize RRset owner: %w", err)
	}
	normalizedType, err := ParseResponseRRType(string(rrType))
	if err != nil {
		return "", err
	}
	if normalizedType == RRTypeRRSIG || normalizedType == RRTypeOPT {
		return "", fmt.Errorf("%s records are excluded from RRset fingerprints", normalizedType)
	}
	normalizedClass := DNSClass(strings.ToUpper(strings.TrimSpace(string(class))))
	if !normalizedClass.Valid() {
		return "", fmt.Errorf("unsupported DNS class %q", class)
	}
	if len(canonicalRData) == 0 {
		return "", fmt.Errorf("RRset must contain at least one canonical RDATA value")
	}

	values := make([]string, 0, len(canonicalRData))
	seen := make(map[string]struct{}, len(canonicalRData))
	for index, value := range canonicalRData {
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("canonical RDATA is not valid UTF-8")
		}
		if value == "" {
			return "", fmt.Errorf("canonical RDATA must not be empty")
		}
		if len(value) > MaxRDataBytes {
			return "", fmt.Errorf("canonical RDATA exceeds %d bytes", MaxRDataBytes)
		}
		if err := ValidateCanonicalRData(normalizedOwner, normalizedType, normalizedClass, value); err != nil {
			return "", fmt.Errorf("canonical RDATA value %d: %w", index, err)
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)

	digest := sha256.New()
	writeFingerprintField(digest, RRSetFingerprintVersion)
	writeFingerprintField(digest, normalizedOwner)
	writeFingerprintField(digest, string(normalizedType))
	writeFingerprintField(digest, string(normalizedClass))
	for _, value := range values {
		writeFingerprintField(digest, value)
	}
	return fingerprintPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}

func FingerprintRecords(records []ResourceRecord) (string, error) {
	if len(records) == 0 {
		return "", fmt.Errorf("RRset must contain at least one record")
	}
	first := records[0]
	if first.RRSetRecordCount <= 0 || first.RRSetRecordCount > MaxSectionRecordLimit {
		return "", fmt.Errorf("invalid RRset record count %d", first.RRSetRecordCount)
	}
	values := make([]string, 0, len(records))
	for i, record := range records {
		if record.RRSetRecordCount != first.RRSetRecordCount {
			return "", fmt.Errorf("inconsistent RRset record count at record %d", i)
		}
		owner, err := NormalizeWireName(record.Owner)
		if err != nil {
			return "", fmt.Errorf("record %d owner: %w", i, err)
		}
		rrType, err := ParseResponseRRType(string(record.Type))
		if err != nil {
			return "", fmt.Errorf("record %d type: %w", i, err)
		}
		class := DNSClass(strings.ToUpper(strings.TrimSpace(string(record.Class))))
		if i == 0 {
			first.Owner = owner
			first.Type = rrType
			first.Class = class
		} else if owner != first.Owner || rrType != first.Type || class != first.Class {
			return "", fmt.Errorf("records do not belong to one RRset")
		}
		values = append(values, record.CanonicalRData)
	}
	if first.RRSetRecordCount != len(records) {
		return "", fmt.Errorf("RRset record count %d does not match %d records", first.RRSetRecordCount, len(records))
	}
	return FingerprintRRSet(first.Owner, first.Type, first.Class, values)
}

func ApplyRRSetFingerprints(sections *Sections) error {
	if sections == nil {
		return fmt.Errorf("sections are required")
	}
	type group struct {
		owner           string
		rrType          RRType
		class           DNSClass
		values          []string
		records         []*ResourceRecord
		expectedCount   int
		countPath       string
		fingerprintable bool
	}
	allSections := [][]ResourceRecord{sections.Answer, sections.Authority, sections.Additional}
	sectionNames := []string{"answer", "authority", "additional"}
	for sectionIndex := range allSections {
		groups := make(map[string]*group)
		orderedGroups := make([]*group, 0, len(allSections[sectionIndex]))
		for recordIndex := range allSections[sectionIndex] {
			record := &allSections[sectionIndex][recordIndex]
			countPath := fmt.Sprintf("sections.%s[%d].rrset_record_count", sectionNames[sectionIndex], recordIndex)
			switch {
			case record.RRSetRecordCount == 0:
				return invalid(countPath, "MISSING_RRSET_RECORD_COUNT", "rrset_record_count is required")
			case record.RRSetRecordCount < 0 || record.RRSetRecordCount > MaxSectionRecordLimit:
				return invalid(countPath, "INVALID_RRSET_RECORD_COUNT", fmt.Sprintf("rrset_record_count must be from 1 to %d", MaxSectionRecordLimit))
			}
			owner, err := NormalizeWireName(record.Owner)
			if err != nil {
				return fmt.Errorf("record owner: %w", err)
			}
			rrType, err := ParseResponseRRType(string(record.Type))
			if err != nil {
				return err
			}
			class := DNSClass(strings.ToUpper(strings.TrimSpace(string(record.Class))))
			if !class.Valid() {
				return fmt.Errorf("unsupported DNS class %q", record.Class)
			}
			record.Owner = owner
			record.Type = rrType
			record.Class = class
			key := owner + "\x00" + string(rrType) + "\x00" + string(class)
			current := groups[key]
			if current == nil {
				current = &group{
					owner: owner, rrType: rrType, class: class,
					expectedCount: record.RRSetRecordCount, countPath: countPath,
					fingerprintable: rrType != RRTypeRRSIG,
				}
				groups[key] = current
				orderedGroups = append(orderedGroups, current)
			} else if record.RRSetRecordCount != current.expectedCount {
				return invalid(countPath, "INCONSISTENT_RRSET_RECORD_COUNT", "records in one RRset must declare the same rrset_record_count")
			}
			current.values = append(current.values, record.CanonicalRData)
			current.records = append(current.records, record)
		}
		for _, current := range orderedGroups {
			if current.expectedCount != len(current.records) {
				return invalid(current.countPath, "RRSET_RECORD_COUNT_MISMATCH", fmt.Sprintf("rrset_record_count declares %d records but section contains %d", current.expectedCount, len(current.records)))
			}
			if !current.fingerprintable {
				for _, record := range current.records {
					if record.RRSetFingerprint != "" {
						return fmt.Errorf("RRSIG record must not have an RRset fingerprint")
					}
				}
				continue
			}
			fingerprint, err := FingerprintRRSet(current.owner, current.rrType, current.class, current.values)
			if err != nil {
				return err
			}
			for _, record := range current.records {
				if record.RRSetFingerprint != "" && record.RRSetFingerprint != fingerprint {
					return fmt.Errorf("RRset fingerprint does not match canonical record data")
				}
				record.RRSetFingerprint = fingerprint
			}
		}
	}
	sections.Answer = allSections[0]
	sections.Authority = allSections[1]
	sections.Additional = allSections[2]
	return nil
}

func ValidRRSetFingerprint(value string) bool {
	if !strings.HasPrefix(value, fingerprintPrefix) {
		return false
	}
	digest := strings.TrimPrefix(value, fingerprintPrefix)
	if len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func writeFingerprintField(target hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = target.Write(length[:])
	_, _ = target.Write([]byte(value))
}
