package main

import (
	"fmt"
	"regexp"
	"strings"
)

var agentLatestVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

func persistAgentLatestVersion(path string, value string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	normalized, err := normalizeAgentLatestVersion(value)
	if err != nil {
		return err
	}
	return persistAgentStateFile(path, []byte(normalized+"\n"))
}

func normalizeAgentLatestVersion(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "nodeping-agent/")
	value = strings.TrimPrefix(value, "v")
	if len(value) == 0 || len(value) > 128 || !agentLatestVersionPattern.MatchString(value) {
		return "", fmt.Errorf("invalid latest agent version %q", value)
	}
	return "v" + value, nil
}
