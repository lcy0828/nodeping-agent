package systemdns

import (
	"fmt"
	"sort"
)

type resolverCandidate struct {
	resolver Resolver
	score    int
	matched  bool
}

// ResolversForName returns the ordered resolver set for name without applying
// a rotation offset.
func (result DiscoveryResult) ResolversForName(name string) ([]Resolver, error) {
	return result.Select(Selection{Name: name})
}

// SelectTrusted applies resolver routing only after proving that every usable
// endpoint came from an unmodified native operating-system discovery result.
// Parsed fixtures and Discoverer instances with injected I/O are deliberately
// rejected so callers cannot turn arbitrary private addresses into trusted
// system DNS dial targets.
func (result DiscoveryResult) SelectTrusted(selection Selection) ([]Resolver, error) {
	if err := validateResult(result, true); err != nil {
		return nil, err
	}
	return result.Select(selection)
}

// SelectTrustedDialTargets applies resolver routing to a complete trusted
// native snapshot and seals each selected resolver together with the route
// interface required for its socket. Callers should use these targets for
// direct system DNS exchanges instead of extracting resolver endpoints.
func (result DiscoveryResult) SelectTrustedDialTargets(selection Selection) ([]DialTarget, error) {
	if err := validateResult(result, true); err != nil {
		return nil, err
	}
	resolvers, err := result.Select(selection)
	if err != nil {
		return nil, err
	}
	targets := make([]DialTarget, len(resolvers))
	for index, resolver := range resolvers {
		target, targetErr := newDialTarget(result.Platform, resolver)
		if targetErr != nil {
			return nil, discoveryError(
				ErrorMalformed,
				result.Platform,
				"select",
				fmt.Sprintf("resolvers[%d].dial_target", index),
				0,
				targetErr.Error(),
				targetErr,
			)
		}
		targets[index] = target
	}
	return targets, nil
}

// Select applies platform routing, stable ordering, endpoint deduplication,
// and the optional resolv.conf rotation policy.
func (result DiscoveryResult) Select(selection Selection) ([]Resolver, error) {
	name, err := normalizeName(selection.Name, true)
	if err != nil {
		return nil, discoveryError(ErrorInvalidInput, result.Platform, "select", "name", 0, err.Error(), err)
	}

	candidates := make([]resolverCandidate, 0, len(result.Resolvers))
	for _, resolver := range result.Resolvers {
		score, matched := suffixScore(name, resolver.ScopeDomain)
		candidates = append(candidates, resolverCandidate{
			resolver: cloneResolver(resolver),
			score:    score,
			matched:  matched,
		})
	}

	switch result.Platform {
	case PlatformDarwin:
		if route := result.unsupportedDarwinRoute(name, selection.InterfaceIndex); route != nil {
			return nil, discoveryError(
				ErrorUnsupported,
				PlatformDarwin,
				"select",
				"resolver_route",
				0,
				fmt.Sprintf("system resolver route for %q is not directly queryable: %s", route.ScopeDomain, route.Reason),
				nil,
			)
		}
		candidates = selectDarwinCandidates(candidates, selection.InterfaceIndex)
		sort.SliceStable(candidates, func(left, right int) bool {
			return lessDarwin(candidates[left].resolver, candidates[right].resolver)
		})
	case PlatformWindows:
		sort.SliceStable(candidates, func(left, right int) bool {
			return lessWindows(candidates[left], candidates[right])
		})
	default:
		sort.SliceStable(candidates, func(left, right int) bool {
			return candidates[left].resolver.discoveryIndex < candidates[right].resolver.discoveryIndex
		})
	}

	ordered := make([]Resolver, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	deduplicate := result.Platform != PlatformLinux
	for _, candidate := range candidates {
		key := endpointKey(candidate.resolver.Endpoint)
		if deduplicate {
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
		}
		ordered = append(ordered, candidate.resolver)
	}
	if len(ordered) == 0 {
		return nil, discoveryError(ErrorNoResolvers, result.Platform, "select", "resolvers", 0, "no resolver matches the requested name and interface", nil)
	}
	if result.Options.Rotate && len(ordered) > 1 {
		offset := int(selection.Rotation % uint64(len(ordered)))
		ordered = append(ordered[offset:], ordered[:offset]...)
	}
	return ordered, nil
}

func (result DiscoveryResult) unsupportedDarwinRoute(name string, interfaceIndex uint32) *UnsupportedRoute {
	type routeMatch struct {
		score       int
		matched     bool
		scoped      bool
		interfaceID uint32
		scope       string
		unsupported *UnsupportedRoute
	}
	matches := make([]routeMatch, 0, len(result.Resolvers)+len(result.UnsupportedRoutes))
	for index := range result.Resolvers {
		resolver := &result.Resolvers[index]
		if !darwinRouteEligible(resolver.Scoped, resolver.InterfaceIndex, resolver.ScopeDomain, interfaceIndex) {
			continue
		}
		score, matched := suffixScore(name, resolver.ScopeDomain)
		matches = append(matches, routeMatch{score: score, matched: matched, scoped: resolver.Scoped, interfaceID: resolver.InterfaceIndex, scope: resolver.ScopeDomain})
	}
	for index := range result.UnsupportedRoutes {
		route := &result.UnsupportedRoutes[index]
		if !darwinRouteEligible(route.Scoped, route.InterfaceIndex, route.ScopeDomain, interfaceIndex) {
			continue
		}
		score, matched := suffixScore(name, route.ScopeDomain)
		matches = append(matches, routeMatch{score: score, matched: matched, scoped: route.Scoped, interfaceID: route.InterfaceIndex, scope: route.ScopeDomain, unsupported: route})
	}

	maxScore := 0
	for _, match := range matches {
		if match.matched && match.score > maxScore {
			maxScore = match.score
		}
	}
	if maxScore > 0 {
		for _, match := range matches {
			if match.unsupported != nil && match.matched && match.score == maxScore {
				return match.unsupported
			}
		}
		return nil
	}

	if interfaceIndex != 0 {
		hasScopedDefault := false
		for _, match := range matches {
			if match.scoped && match.interfaceID == interfaceIndex && (match.scope == "" || match.scope == ".") {
				hasScopedDefault = true
			}
		}
		if hasScopedDefault {
			for _, match := range matches {
				if match.unsupported != nil && match.scoped && match.interfaceID == interfaceIndex && (match.scope == "" || match.scope == ".") {
					return match.unsupported
				}
			}
			return nil
		}
	}
	for _, match := range matches {
		if match.unsupported != nil && !match.scoped && (match.scope == "" || match.scope == ".") {
			return match.unsupported
		}
	}
	return nil
}

func darwinRouteEligible(scoped bool, resolverInterface uint32, scope string, requestedInterface uint32) bool {
	if !scoped {
		return true
	}
	if requestedInterface != 0 && resolverInterface != 0 && resolverInterface != requestedInterface {
		return false
	}
	if scope != "" && scope != "." {
		return true
	}
	return requestedInterface != 0 && resolverInterface == requestedInterface
}

func selectDarwinCandidates(candidates []resolverCandidate, interfaceIndex uint32) []resolverCandidate {
	eligible := make([]resolverCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		resolver := candidate.resolver
		if !darwinRouteEligible(resolver.Scoped, resolver.InterfaceIndex, resolver.ScopeDomain, interfaceIndex) {
			continue
		}
		eligible = append(eligible, candidate)
	}

	maxScore := 0
	for _, candidate := range eligible {
		if candidate.matched && candidate.score > maxScore {
			maxScore = candidate.score
		}
	}
	selected := make([]resolverCandidate, 0, len(eligible))
	if maxScore == 0 && interfaceIndex != 0 {
		for _, candidate := range eligible {
			resolver := candidate.resolver
			if resolver.Scoped && resolver.InterfaceIndex == interfaceIndex && (resolver.ScopeDomain == "" || resolver.ScopeDomain == ".") {
				selected = append(selected, candidate)
			}
		}
		if len(selected) > 0 {
			return selected
		}
	}
	for _, candidate := range eligible {
		if maxScore > 0 {
			if candidate.matched && candidate.score == maxScore {
				selected = append(selected, candidate)
			}
			continue
		}
		if candidate.resolver.ScopeDomain == "" || candidate.resolver.ScopeDomain == "." {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func lessDarwin(left, right Resolver) bool {
	if left.groupIndex == right.groupIndex {
		return left.discoveryIndex < right.discoveryIndex
	}
	if left.OrderSet != right.OrderSet {
		return left.OrderSet
	}
	if left.Order != right.Order {
		return left.Order < right.Order
	}
	return left.discoveryIndex < right.discoveryIndex
}

func lessWindows(left, right resolverCandidate) bool {
	// Windows preserves configured DNS server order within one adapter. Across
	// adapters, prefer the complete metric of the route that will dial the
	// server; stable discovery order breaks equal-metric ties.
	if left.resolver.groupIndex == right.resolver.groupIndex {
		return left.resolver.discoveryIndex < right.resolver.discoveryIndex
	}
	leftMetric := effectiveMetric(left.resolver)
	rightMetric := effectiveMetric(right.resolver)
	if leftMetric != rightMetric {
		return leftMetric < rightMetric
	}
	return left.resolver.discoveryIndex < right.resolver.discoveryIndex
}

func effectiveMetric(resolver Resolver) uint64 {
	if !resolver.MetricSet || !resolver.RouteInterfaceMetricSet || !resolver.RouteMetricSet {
		return ^uint64(0)
	}
	return uint64(resolver.RouteInterfaceMetric) + uint64(resolver.RouteMetric)
}

func cloneResolver(resolver Resolver) Resolver {
	resolver.SearchDomains = append([]string(nil), resolver.SearchDomains...)
	resolver.Flags = append([]string(nil), resolver.Flags...)
	resolver.NativeOptions = append([]string(nil), resolver.NativeOptions...)
	return resolver
}

func validateResult(result DiscoveryResult, requireTrusted bool) error {
	if len(result.Resolvers) == 0 && len(result.UnsupportedRoutes) == 0 {
		return discoveryError(ErrorNoResolvers, result.Platform, "discover", "resolvers", 0, "the operating system reported no usable DNS resolvers", nil)
	}
	if requireTrusted && !snapshotProvenanceValid(result) {
		return discoveryError(ErrorMalformed, result.Platform, "discover", "snapshot_trust", 0, "system resolver snapshot is not an unmodified native discovery result", nil)
	}
	for index, resolver := range result.Resolvers {
		if err := validateEndpoint(resolver.Endpoint); err != nil {
			return discoveryError(ErrorMalformed, result.Platform, "discover", fmt.Sprintf("resolvers[%d].endpoint", index), 0, err.Error(), err)
		}
		if requireTrusted && !resolver.Endpoint.IsTrustedSystem() {
			return discoveryError(ErrorMalformed, result.Platform, "discover", fmt.Sprintf("resolvers[%d].trust", index), 0, "system resolver is not marked as trusted system input", nil)
		}
	}
	if len(result.UnsupportedRoutes) != 0 && result.Platform != PlatformDarwin {
		return discoveryError(ErrorMalformed, result.Platform, "discover", "unsupported_routes", 0, "unsupported resolver routes are only valid on macOS", nil)
	}
	return nil
}
