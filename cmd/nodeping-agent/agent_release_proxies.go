package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxAgentReleaseProxies = 32

var releaseProxyQueryParamPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func persistAgentReleaseProxies(path string, proxies []agentReleaseProxy) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	items := append([]agentReleaseProxy(nil), proxies...)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Priority != items[j].Priority {
			return items[i].Priority > items[j].Priority
		}
		return items[i].ID < items[j].ID
	})
	if len(items) > maxAgentReleaseProxies {
		items = items[:maxAgentReleaseProxies]
	}
	var content strings.Builder
	for _, proxy := range items {
		normalized, err := normalizeAgentReleaseProxy(proxy)
		if err != nil {
			return err
		}
		content.WriteString(strconv.FormatInt(normalized.ID, 10))
		content.WriteByte('\t')
		content.WriteString(normalized.Mode)
		content.WriteByte('\t')
		content.WriteString(normalized.BaseURL)
		content.WriteByte('\t')
		content.WriteString(normalized.QueryParam)
		content.WriteByte('\n')
	}
	return persistAgentStateFile(path, []byte(content.String()))
}

func normalizeAgentReleaseProxy(proxy agentReleaseProxy) (agentReleaseProxy, error) {
	proxy.Name = strings.TrimSpace(proxy.Name)
	proxy.BaseURL = strings.TrimSpace(proxy.BaseURL)
	proxy.Mode = strings.ToLower(strings.TrimSpace(proxy.Mode))
	proxy.QueryParam = strings.TrimSpace(proxy.QueryParam)
	if proxy.ID <= 0 {
		return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "id must be positive")
	}
	if len(proxy.BaseURL) > 2048 {
		return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "base URL is too long")
	}
	parsed, err := validateSecureBaseURL(proxy.BaseURL, "release proxy base_url")
	if err != nil {
		return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, err.Error())
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "base URL must use HTTPS")
	}
	proxy.BaseURL = strings.TrimRight(parsed.String(), "/") + "/"
	switch proxy.Mode {
	case "host_path", "full_url":
		if proxy.QueryParam != "" {
			return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "query_param is allowed only in query mode")
		}
	case "query":
		if !releaseProxyQueryParamPattern.MatchString(proxy.QueryParam) {
			return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "query mode requires a valid query_param")
		}
	default:
		return agentReleaseProxy{}, errorsForReleaseProxy(proxy.Name, "unsupported mode")
	}
	return proxy, nil
}

func errorsForReleaseProxy(name string, message string) error {
	if strings.TrimSpace(name) == "" {
		name = "unnamed"
	}
	return fmt.Errorf("release proxy %q: %s", name, message)
}
