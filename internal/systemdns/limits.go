package systemdns

import "fmt"

// Limits bounds every variable-length operating-system input.
type Limits struct {
	MaxInputBytes           int
	MaxLineBytes            int
	MaxLines                int
	MaxResolvers            int
	MaxSearchDomains        int
	MaxResolverBlocks       int
	MaxFlagsPerResolver     int
	MaxFlagBytes            int
	MaxInterfaceNameBytes   int
	MaxWindowsAdapters      int
	MaxDNSServersPerAdapter int
	MaxWindowsBufferBytes   int
	MaxWindowsRoutes        int
}

// DefaultLimits returns production discovery limits.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:           512 << 10,
		MaxLineBytes:            8 << 10,
		MaxLines:                8192,
		MaxResolvers:            128,
		MaxSearchDomains:        32,
		MaxResolverBlocks:       128,
		MaxFlagsPerResolver:     32,
		MaxFlagBytes:            256,
		MaxInterfaceNameBytes:   128,
		MaxWindowsAdapters:      128,
		MaxDNSServersPerAdapter: 32,
		MaxWindowsBufferBytes:   2 << 20,
		MaxWindowsRoutes:        4096,
	}
}

func normalizeLimits(value Limits) (Limits, error) {
	defaults := DefaultLimits()
	fields := []struct {
		name     string
		value    *int
		fallback int
		hardMax  int
	}{
		{"max_input_bytes", &value.MaxInputBytes, defaults.MaxInputBytes, 8 << 20},
		{"max_line_bytes", &value.MaxLineBytes, defaults.MaxLineBytes, 64 << 10},
		{"max_lines", &value.MaxLines, defaults.MaxLines, 65_536},
		{"max_resolvers", &value.MaxResolvers, defaults.MaxResolvers, 1024},
		{"max_search_domains", &value.MaxSearchDomains, defaults.MaxSearchDomains, 256},
		{"max_resolver_blocks", &value.MaxResolverBlocks, defaults.MaxResolverBlocks, 1024},
		{"max_flags_per_resolver", &value.MaxFlagsPerResolver, defaults.MaxFlagsPerResolver, 256},
		{"max_flag_bytes", &value.MaxFlagBytes, defaults.MaxFlagBytes, 4 << 10},
		{"max_interface_name_bytes", &value.MaxInterfaceNameBytes, defaults.MaxInterfaceNameBytes, 4 << 10},
		{"max_windows_adapters", &value.MaxWindowsAdapters, defaults.MaxWindowsAdapters, 1024},
		{"max_dns_servers_per_adapter", &value.MaxDNSServersPerAdapter, defaults.MaxDNSServersPerAdapter, 256},
		{"max_windows_buffer_bytes", &value.MaxWindowsBufferBytes, defaults.MaxWindowsBufferBytes, 16 << 20},
		{"max_windows_routes", &value.MaxWindowsRoutes, defaults.MaxWindowsRoutes, 65_536},
	}
	for _, field := range fields {
		if *field.value == 0 {
			*field.value = field.fallback
		}
		if *field.value < 0 || *field.value > field.hardMax {
			return Limits{}, discoveryError(
				ErrorInvalidInput,
				"",
				"limits",
				field.name,
				0,
				fmt.Sprintf("must be between 1 and %d", field.hardMax),
				nil,
			)
		}
	}
	if value.MaxLineBytes > value.MaxInputBytes {
		return Limits{}, discoveryError(ErrorInvalidInput, "", "limits", "max_line_bytes", 0, "must not exceed max_input_bytes", nil)
	}
	return value, nil
}
