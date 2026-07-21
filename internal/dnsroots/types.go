package dnsroots

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

const (
	HintsManifestSchema    = "nodeping-root-hints/v1"
	MaterialEvidenceSchema = "nodeping-dns-root-material/v1"
	HintsSourceURL         = "https://www.internic.net/domain/named.root"
	RootServerCount        = 13

	ReasonReady            = "ready"
	ReasonNotConfigured    = "not_configured"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonMaterialInvalid  = "material_invalid"
	ReasonUsingLKG         = "using_lkg"
	ReasonLockUnavailable  = "lock_unavailable"
)

const (
	maxHintsBytes  = 1 << 20
	maxAnchorBytes = 1 << 20
)

var (
	ErrNotConfigured       = errors.New("DNS root material is not configured")
	ErrInvalidManifest     = errors.New("invalid root hints manifest")
	ErrInvalidHints        = errors.New("invalid root hints")
	ErrInvalidSignature    = errors.New("invalid root hints signature")
	ErrStaleHints          = errors.New("stale root hints manifest")
	ErrNoUsableHints       = errors.New("no usable root hints snapshot")
	ErrNoUsableTrustAnchor = errors.New("no usable trust anchor snapshot")
)

type HintsManifest struct {
	Schema          string `json:"schema"`
	Version         string `json:"version"`
	PublishedAt     string `json:"published_at"`
	SourceURL       string `json:"source_url"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	RootServerCount int    `json:"root_server_count"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

type HintsSummary struct {
	RootServerCount int
	IPv4Count       int
	IPv6Count       int
}

type HintsSnapshot struct {
	Version        string    `json:"version"`
	PublishedAt    time.Time `json:"published_at"`
	SHA256         string    `json:"sha256"`
	Size           int64     `json:"size"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	KeyID          string    `json:"key_id"`
	RootServers    int       `json:"root_servers"`
	IPv4Addresses  int       `json:"ipv4_addresses"`
	IPv6Addresses  int       `json:"ipv6_addresses"`
	Recovered      bool      `json:"recovered,omitempty"`
	Path           string    `json:"-"`
}

type AnchorSnapshot struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Recovered bool      `json:"recovered,omitempty"`
	Path      string    `json:"-"`
}

type AnchorRefreshResult struct {
	Snapshot    AnchorSnapshot
	Updated     bool
	Recovered   bool
	WarningCode string
	Warning     error
}

// MaterialSnapshot is the exact immutable root material pair acquired for one
// DNS run. Paths remain Agent-local and are excluded from JSON by the nested
// snapshot types.
type MaterialSnapshot struct {
	RootHints   HintsSnapshot  `json:"root_hints"`
	TrustAnchor AnchorSnapshot `json:"trust_anchor"`
}

// MaterialEvidence is the path-free projection safe to persist with a run or
// report to the control plane.
type MaterialEvidence struct {
	Schema      string                    `json:"schema"`
	RootHints   MaterialComponentEvidence `json:"root_hints"`
	TrustAnchor MaterialComponentEvidence `json:"trust_anchor"`
}

type MaterialComponentEvidence struct {
	Health  string `json:"health"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func (snapshot MaterialSnapshot) Evidence() MaterialEvidence {
	return MaterialEvidence{
		Schema: MaterialEvidenceSchema,
		RootHints: MaterialComponentEvidence{
			Health: materialHealth(snapshot.RootHints.Recovered), Version: snapshot.RootHints.Version,
			SHA256: snapshot.RootHints.SHA256,
		},
		TrustAnchor: MaterialComponentEvidence{
			Health: materialHealth(snapshot.TrustAnchor.Recovered), Version: snapshot.TrustAnchor.Version,
			SHA256: snapshot.TrustAnchor.SHA256,
		},
	}
}

func materialHealth(recovered bool) string {
	if recovered {
		return ReasonUsingLKG
	}
	return ReasonReady
}

type AnchorUpdater func(ctx context.Context, candidatePath string) error
type AnchorValidator func(ctx context.Context, candidatePath string) error
type AnchorValidatorFactory func(rootHintsPath string) (AnchorValidator, error)

type Keyring map[string]ed25519.PublicKey
