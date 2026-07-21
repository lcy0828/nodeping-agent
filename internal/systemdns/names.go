package systemdns

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

func normalizeName(value string, allowRoot bool) (string, error) {
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("DNS name has leading or trailing whitespace")
	}
	if value == "." && allowRoot {
		return ".", nil
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", fmt.Errorf("DNS name is empty")
	}

	labels := strings.Split(value, ".")
	for index, label := range labels {
		if label == "" {
			return "", fmt.Errorf("DNS name contains an empty label")
		}
		ascii, err := normalizeLabel(label)
		if err != nil {
			return "", fmt.Errorf("label %d: %w", index+1, err)
		}
		if len(ascii) > 63 {
			return "", fmt.Errorf("label %d exceeds 63 bytes", index+1)
		}
		labels[index] = strings.ToLower(ascii)
	}
	result := strings.Join(labels, ".")
	if len(result) > 253 {
		return "", fmt.Errorf("DNS name exceeds 253 bytes")
	}
	return result, nil
}

func normalizeLabel(value string) (string, error) {
	if !strings.ContainsRune(value, '_') {
		ascii, err := idna.Lookup.ToASCII(value)
		if err != nil {
			return "", err
		}
		return ascii, nil
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' {
			continue
		}
		return "", fmt.Errorf("underscore labels must otherwise be ASCII letters, digits, or hyphens")
	}
	if strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return "", fmt.Errorf("label starts or ends with a hyphen")
	}
	return value, nil
}

func suffixScore(name, suffix string) (int, bool) {
	if suffix == "" || suffix == "." {
		return 0, true
	}
	if name == suffix {
		return strings.Count(suffix, ".") + 1, true
	}
	if strings.HasSuffix(name, "."+suffix) {
		return strings.Count(suffix, ".") + 1, true
	}
	return -1, false
}

func appendUniqueName(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
