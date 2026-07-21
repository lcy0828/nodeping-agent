package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Generate(options GenerateOptions) (ReleaseManifest, error) {
	if err := validateGenerateOptions(options); err != nil {
		return ReleaseManifest{}, err
	}
	created := time.Unix(options.SourceDateEpoch, 0).UTC().Format(time.RFC3339)
	if err := os.MkdirAll(options.ArtifactDir, 0o755); err != nil {
		return ReleaseManifest{}, fmt.Errorf("create artifact directory: %w", err)
	}
	licenseFiles, err := installLicenses(options.LicenseSourceDir, options.ArtifactDir)
	if err != nil {
		return ReleaseManifest{}, err
	}
	patchDigest, _, err := sha256Path(options.PatchPath)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("hash patch: %w", err)
	}
	if patchDigest != patchSHA256 {
		return ReleaseManifest{}, fmt.Errorf("patch SHA-256 = %s, want %s", patchDigest, patchSHA256)
	}
	patchSHA1, err := sha1Path(options.PatchPath)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("hash patch with SHA-1: %w", err)
	}

	noticesBytes := renderNotices()
	noticesPath := filepath.Join(options.ArtifactDir, "THIRD_PARTY_NOTICES.md")
	if err := writeFileAtomic(noticesPath, noticesBytes, 0o644); err != nil {
		return ReleaseManifest{}, err
	}
	noticesFile, err := manifestFile(options.ArtifactDir, noticesPath)
	if err != nil {
		return ReleaseManifest{}, err
	}

	manifest := ReleaseManifest{
		SchemaVersion:   metadataSchemaVersion,
		Name:            "nodeping-unbound-helper",
		Version:         unboundVersion,
		Created:         created,
		SourceDateEpoch: options.SourceDateEpoch,
		Unsigned:        true,
		Target:          options.Target,
		Toolchain:       options.Toolchain,
		Patch:           ManifestPatch{Name: patchName, SHA256: patchSHA256},
		Components:      manifestComponents(),
		Licenses:        licenseFiles,
		Notices:         noticesFile,
	}

	for _, helperName := range helperNames {
		binaryName := helperFileName(helperName, options.Target.OS)
		binaryPath := filepath.Join(options.ArtifactDir, binaryName)
		binaryDigest, binarySize, err := sha256Path(binaryPath)
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("hash helper %s: %w", helperName, err)
		}
		linked, err := linkedComponents(filepath.Join(options.LinkMapDir, helperName+".map"))
		if err != nil {
			return ReleaseManifest{}, err
		}
		if len(linked) == 0 {
			return ReleaseManifest{}, fmt.Errorf("linker map for %s contains no pinned static dependency evidence", helperName)
		}

		artifact := ManifestArtifact{
			Name: helperName, Path: binaryName, SHA256: binaryDigest, Size: binarySize,
			LinkedComponents: linked,
		}
		cycloneDXBytes, err := renderCycloneDX(manifest, artifact)
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("render CycloneDX for %s: %w", helperName, err)
		}
		spdxBytes, err := renderSPDX(manifest, artifact, patchSHA1)
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("render SPDX for %s: %w", helperName, err)
		}
		cycloneDXPath := filepath.Join(options.ArtifactDir, helperName+".cdx.json")
		spdxPath := filepath.Join(options.ArtifactDir, helperName+".spdx.json")
		if err := writeFileAtomic(cycloneDXPath, cycloneDXBytes, 0o644); err != nil {
			return ReleaseManifest{}, err
		}
		if err := writeFileAtomic(spdxPath, spdxBytes, 0o644); err != nil {
			return ReleaseManifest{}, err
		}
		artifact.CycloneDX, err = manifestFile(options.ArtifactDir, cycloneDXPath)
		if err != nil {
			return ReleaseManifest{}, err
		}
		artifact.SPDX, err = manifestFile(options.ArtifactDir, spdxPath)
		if err != nil {
			return ReleaseManifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}

	manifestBytes, err := encodeJSON(manifest)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("encode release manifest: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(options.ArtifactDir, "unbound-helper-manifest.json"), manifestBytes, 0o644); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

func validateGenerateOptions(options GenerateOptions) error {
	for name, value := range map[string]string{
		"artifact-dir": options.ArtifactDir, "link-map-dir": options.LinkMapDir,
		"license-source-dir": options.LicenseSourceDir, "patch-path": options.PatchPath,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if options.SourceDateEpoch <= 0 {
		return fmt.Errorf("source date epoch must be positive")
	}
	if options.Target.OS != "linux" && options.Target.OS != "darwin" && options.Target.OS != "windows" {
		return fmt.Errorf("unsupported target OS %q", options.Target.OS)
	}
	if options.Target.Arch != "amd64" && options.Target.Arch != "arm64" {
		return fmt.Errorf("unsupported target architecture %q", options.Target.Arch)
	}
	return validateToolchain(options.Toolchain)
}

func installLicenses(sourceDir, artifactDir string) ([]ManifestFile, error) {
	licenseDir := filepath.Join(artifactDir, "licenses")
	if err := os.MkdirAll(licenseDir, 0o755); err != nil {
		return nil, fmt.Errorf("create license directory: %w", err)
	}
	files := make([]ManifestFile, 0, len(sourceComponents))
	for _, component := range sourceComponents {
		sourcePath := filepath.Join(sourceDir, component.LicenseSourceName)
		value, err := os.ReadFile(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("read %s license: %w", component.ID, err)
		}
		digest := sha256Bytes(value)
		if digest != component.LicenseSHA256 {
			return nil, fmt.Errorf("%s license SHA-256 = %s, want %s", component.ID, digest, component.LicenseSHA256)
		}
		destination := filepath.Join(licenseDir, component.LicenseArtifactName)
		if err := writeFileAtomic(destination, value, 0o644); err != nil {
			return nil, err
		}
		file, err := manifestFile(artifactDir, destination)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func renderNotices() []byte {
	var output strings.Builder
	output.WriteString("# NodePing Unbound Helper Third-Party Notices\n\n")
	output.WriteString("This unsigned helper bundle is built from the pinned source components below.\n")
	output.WriteString("Each license file is shipped in the `licenses/` directory.\n\n")
	output.WriteString("| Component | Version | License | Source | License file |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, component := range sourceComponents {
		fmt.Fprintf(&output, "| %s | %s | %s | %s | `licenses/%s` |\n",
			component.Name, component.Version, component.License,
			component.SourceURL, component.LicenseArtifactName)
	}
	return []byte(output.String())
}

func manifestFile(root, path string) (ManifestFile, error) {
	digest, size, err := sha256Path(path)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("hash %s: %w", path, err)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("make %s relative to %s: %w", path, root, err)
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ManifestFile{}, fmt.Errorf("metadata path escapes artifact directory: %s", path)
	}
	return ManifestFile{Path: filepath.ToSlash(relative), SHA256: digest, Size: size}, nil
}

func encodeJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeFileAtomic(path string, value []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nodeping-metadata-*")
	if err != nil {
		return fmt.Errorf("create temporary metadata file for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary metadata file for %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary metadata file for %s: %w", path, err)
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("chmod temporary metadata file for %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary metadata file for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit metadata file %s: %w", path, err)
	}
	committed = true
	return nil
}

func sha256Bytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
