package dnsroots

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type unsignedHintsManifest struct {
	Schema          string `json:"schema"`
	Version         string `json:"version"`
	PublishedAt     string `json:"published_at"`
	SourceURL       string `json:"source_url"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	RootServerCount int    `json:"root_server_count"`
	KeyID           string `json:"key_id"`
}

func PublicKeyID(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:8])
}

func ParseKeyring(value string) (Keyring, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrNotConfigured
	}
	keyring := Keyring{}
	for _, encoded := range strings.Split(value, ",") {
		decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: malformed Ed25519 public key", ErrInvalidManifest)
		}
		key := ed25519.PublicKey(append([]byte(nil), decoded...))
		id := PublicKeyID(key)
		if _, duplicate := keyring[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate Ed25519 public key", ErrInvalidManifest)
		}
		keyring[id] = key
	}
	return keyring, nil
}

func NewHintsManifest(version string, publishedAt time.Time, hints []byte, privateKey ed25519.PrivateKey) (HintsManifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return HintsManifest{}, fmt.Errorf("%w: invalid signing key", ErrInvalidManifest)
	}
	summary, err := ParseRootHints(hints)
	if err != nil {
		return HintsManifest{}, err
	}
	manifest := HintsManifest{
		Schema:          HintsManifestSchema,
		Version:         strings.TrimSpace(version),
		PublishedAt:     publishedAt.UTC().Format(time.RFC3339),
		SourceURL:       HintsSourceURL,
		SHA256:          sha256Bytes(hints),
		Size:            int64(len(hints)),
		RootServerCount: summary.RootServerCount,
		KeyID:           PublicKeyID(privateKey.Public().(ed25519.PublicKey)),
	}
	if _, err := validateManifestIdentity(manifest, publishedAt.UTC().Add(time.Minute)); err != nil {
		return HintsManifest{}, err
	}
	payload, err := manifestSigningPayload(manifest)
	if err != nil {
		return HintsManifest{}, err
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return manifest, nil
}

func VerifyHintsManifest(manifest HintsManifest, hints []byte, keys Keyring, now time.Time) (HintsSummary, time.Time, error) {
	publishedAt, err := validateManifestIdentity(manifest, now)
	if err != nil {
		return HintsSummary{}, time.Time{}, err
	}
	if int64(len(hints)) != manifest.Size || sha256Bytes(hints) != manifest.SHA256 {
		return HintsSummary{}, time.Time{}, fmt.Errorf("%w: content hash or size mismatch", ErrInvalidHints)
	}
	summary, err := ParseRootHints(hints)
	if err != nil {
		return HintsSummary{}, time.Time{}, err
	}
	if summary.RootServerCount != manifest.RootServerCount {
		return HintsSummary{}, time.Time{}, fmt.Errorf("%w: root server count mismatch", ErrInvalidHints)
	}
	key, exists := keys[manifest.KeyID]
	if !exists || len(key) != ed25519.PublicKeySize || PublicKeyID(key) != manifest.KeyID {
		return HintsSummary{}, time.Time{}, fmt.Errorf("%w: untrusted key id", ErrInvalidSignature)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return HintsSummary{}, time.Time{}, fmt.Errorf("%w: malformed signature", ErrInvalidSignature)
	}
	payload, err := manifestSigningPayload(manifest)
	if err != nil {
		return HintsSummary{}, time.Time{}, err
	}
	if !ed25519.Verify(key, payload, signature) {
		return HintsSummary{}, time.Time{}, ErrInvalidSignature
	}
	return summary, publishedAt, nil
}

func validateManifestIdentity(manifest HintsManifest, now time.Time) (time.Time, error) {
	if manifest.Schema != HintsManifestSchema || !validVersion(manifest.Version) || manifest.SourceURL != HintsSourceURL ||
		!validSHA256(manifest.SHA256) || manifest.Size <= 0 || manifest.Size > maxHintsBytes ||
		manifest.RootServerCount != RootServerCount || !validKeyID(manifest.KeyID) {
		return time.Time{}, ErrInvalidManifest
	}
	parsedURL, err := url.Parse(manifest.SourceURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return time.Time{}, ErrInvalidManifest
	}
	publishedAt, err := time.Parse(time.RFC3339, manifest.PublishedAt)
	if err != nil || manifest.PublishedAt != publishedAt.UTC().Format(time.RFC3339) || publishedAt.After(now.UTC().Add(5*time.Minute)) {
		return time.Time{}, ErrInvalidManifest
	}
	return publishedAt.UTC(), nil
}

func manifestSigningPayload(manifest HintsManifest) ([]byte, error) {
	return encodeJSON(unsignedHintsManifest{
		Schema: manifest.Schema, Version: manifest.Version, PublishedAt: manifest.PublishedAt,
		SourceURL: manifest.SourceURL, SHA256: manifest.SHA256, Size: manifest.Size,
		RootServerCount: manifest.RootServerCount, KeyID: manifest.KeyID,
	})
}

func validVersion(value string) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validKeyID(value string) bool {
	if len(value) != 16 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
