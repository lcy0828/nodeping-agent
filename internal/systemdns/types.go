package systemdns

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Platform identifies the native configuration source used for discovery.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
)

// Source identifies the operating-system API or file behind a resolver.
type Source string

const (
	SourceResolvConf      Source = "resolv_conf"
	SourceSCUtil          Source = "scutil"
	SourceWindowsAdapters Source = "windows_adapters"
)

// Endpoint keeps an IPv6 zone separate from the address. Zone is local
// routing metadata. Its fields are intentionally opaque so package callers and
// JSON decoding cannot manufacture a system-trusted private endpoint.
type Endpoint struct {
	address    netip.Addr
	zone       string
	port       uint16
	provenance [32]byte
}

// DialTarget is one resolver selected from a complete trusted native
// discovery snapshot. In addition to the endpoint, it seals the platform and
// route interface that must be used for the socket. Its fields are opaque so
// callers cannot combine a trusted address with untrusted routing metadata.
type DialTarget struct {
	endpoint           Endpoint
	platform           Platform
	bindInterfaceIndex uint32
	provenance         [32]byte
}

// Address returns the bare resolver address without IPv6 routing scope.
func (e Endpoint) Address() netip.Addr { return e.address }

// Zone returns local IPv6 link-local routing metadata. It must never be used
// as the public peer address in an observation.
func (e Endpoint) Zone() string { return e.zone }

// Port returns the discovered resolver port.
func (e Endpoint) Port() uint16 { return e.port }

// ScopedAddress returns the address used for local dialing.
func (e Endpoint) ScopedAddress() netip.Addr {
	if e.zone == "" || !e.address.Is6() {
		return e.address
	}
	return e.address.WithZone(e.zone)
}

// DialAddress returns a host:port suitable for the local resolver transport.
func (e Endpoint) DialAddress() string {
	return net.JoinHostPort(e.ScopedAddress().String(), strconv.Itoa(int(e.port)))
}

// IsTrustedSystem reports whether this exact address, zone, and port were
// sealed by an unmodified native operating-system discovery result.
func (e Endpoint) IsTrustedSystem() bool { return endpointProvenanceValid(e) }

// UnmarshalJSON deliberately rejects all endpoint JSON. A trusted endpoint is
// a local capability and must never be reconstructed from a wire payload.
func (*Endpoint) UnmarshalJSON([]byte) error {
	return discoveryError(ErrorInvalidInput, "", "endpoint", "json", 0, "system DNS endpoints cannot be decoded from JSON", nil)
}

// Address returns the bare resolver address without IPv6 routing scope.
func (target DialTarget) Address() netip.Addr { return target.endpoint.Address() }

// Zone returns local IPv6 link-local routing metadata.
func (target DialTarget) Zone() string { return target.endpoint.Zone() }

// Port returns the port from the selected native resolver snapshot.
func (target DialTarget) Port() uint16 { return target.endpoint.Port() }

// DialAddress returns the selected resolver's local host:port dial target.
func (target DialTarget) DialAddress() string { return target.endpoint.DialAddress() }

// Platform returns the native platform whose snapshot produced this target.
func (target DialTarget) Platform() Platform { return target.platform }

// BindInterfaceIndex returns the sealed route interface for socket binding.
// Linux resolv.conf does not provide this metadata and therefore returns zero.
func (target DialTarget) BindInterfaceIndex() uint32 { return target.bindInterfaceIndex }

// IsTrustedSystem reports whether all endpoint and routing fields retain the
// provenance created by trusted native discovery and selection.
func (target DialTarget) IsTrustedSystem() bool { return dialTargetProvenanceValid(target) }

// UnmarshalJSON deliberately rejects all dial target JSON. A target is a
// process-local capability and must never be reconstructed from a wire value.
func (*DialTarget) UnmarshalJSON([]byte) error {
	return discoveryError(ErrorInvalidInput, "", "dial_target", "json", 0, "system DNS dial targets cannot be decoded from JSON", nil)
}

// Resolver is one ordered DNS endpoint and its routing data. Only endpoints
// returned by an unmodified native Discover call pass IsTrustedSystem.
type Resolver struct {
	Endpoint Endpoint
	Source   Source

	// ScopeDomain controls resolver routing. Empty and "." are default scopes.
	ScopeDomain   string
	SearchDomains []string
	Scoped        bool

	Order    uint32
	OrderSet bool

	// InterfaceIndex is the configuration-provenance interface. On Windows it
	// identifies the adapter whose DNS server list supplied this resolver.
	InterfaceIndex uint32
	// RouteInterfaceIndex is the interface selected to dial the resolver. It is
	// normally InterfaceIndex, but a Windows loopback resolver uses the local
	// loopback route while retaining its configuration provenance above.
	RouteInterfaceIndex uint32
	// InterfaceName is local routing metadata and must not be exposed publicly.
	InterfaceName string `json:"-"`
	Flags         []string
	NativeOptions []string

	// ConnectionSuffix is Windows search metadata. It is not a namespace
	// routing rule and must not influence fully-qualified resolver selection.
	ConnectionSuffix string

	TimeoutSeconds           uint32
	ConfiguredTimeoutSeconds uint32
	TimeoutConfigured        bool

	// IPv4Metric and IPv6Metric belong to the configuration-provenance adapter.
	IPv4Metric uint32
	IPv6Metric uint32
	MetricSet  bool

	// RouteInterfaceMetric and RouteMetric are the Windows dial route's
	// interface metric and route offset. Their sum is the complete route metric
	// defined by MIB_IPFORWARD_ROW2.
	RouteInterfaceMetric    uint32
	RouteInterfaceMetricSet bool
	RouteMetric             uint32
	RouteMetricSet          bool

	discoveryIndex int
	groupIndex     int
}

// UnsupportedRoute preserves a macOS resolver client that participates in
// suffix/scoped routing but has no unicast nameserver that this engine can
// contact directly (for example, an mDNS client).
type UnsupportedRoute struct {
	ScopeDomain   string
	SearchDomains []string
	Scoped        bool

	Order    uint32
	OrderSet bool

	InterfaceIndex uint32
	InterfaceName  string `json:"-"`
	Flags          []string
	NativeOptions  []string

	Port                     uint16
	TimeoutSeconds           uint32
	ConfiguredTimeoutSeconds uint32
	TimeoutConfigured        bool
	Reason                   string

	discoveryIndex int
	groupIndex     int
}

// ResolverOptions contains effective resolver behavior and whether values
// were explicitly configured by the operating system. Configured fields keep
// the original values when resolv.conf semantics clamp the effective values.
type ResolverOptions struct {
	Rotate                   bool
	TimeoutSeconds           uint32
	ConfiguredTimeoutSeconds uint32
	TimeoutConfigured        bool
	Attempts                 uint32
	ConfiguredAttempts       uint32
	AttemptsConfigured       bool
}

// DiscoveryResult is a complete, non-truncated system resolver snapshot.
type DiscoveryResult struct {
	Platform          Platform
	Resolvers         []Resolver
	UnsupportedRoutes []UnsupportedRoute
	Domain            string
	SearchDomains     []string
	Options           ResolverOptions

	provenance [32]byte
}

// Selection identifies one resolver-routing decision. Rotation is applied
// only when the discovered resolver options enable rotate.
type Selection struct {
	Name           string
	InterfaceIndex uint32
	Rotation       uint64
}

// OpenFileFunc injects resolv.conf I/O. It must return the complete file.
type OpenFileFunc func(path string) (io.ReadCloser, error)

// CommandRunner injects scutil execution. It must honor ctx and return the
// complete stdout; Discoverer independently checks the configured byte limit.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Discoverer is safe for concurrent use when its injected hooks are safe for
// concurrent use. The zero value uses platform defaults. Custom source paths
// and I/O hooks intentionally produce untrusted endpoints.
type Discoverer struct {
	ResolvConfPath string
	SCUtilPath     string
	CommandTimeout time.Duration
	Limits         Limits
	OpenFile       OpenFileFunc
	RunCommand     CommandRunner

	windowsAdapters func(context.Context, Limits) ([]windowsAdapterSnapshot, error)
	windowsRoutes   func(context.Context, Limits) ([]windowsRouteSnapshot, error)
}
