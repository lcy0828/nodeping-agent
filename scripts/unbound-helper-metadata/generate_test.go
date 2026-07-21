package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spdx/tools-golang/spdx"
)

func TestGenerateIsDeterministicAndComplete(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	firstDir, firstMaps := prepareTestBuild(t)
	secondDir, secondMaps := prepareTestBuild(t)
	options := testGenerateOptions(repositoryRoot, firstDir, firstMaps)
	first, err := Generate(options)
	if err != nil {
		t.Fatalf("Generate(first): %v", err)
	}
	options.ArtifactDir = secondDir
	options.LinkMapDir = secondMaps
	second, err := Generate(options)
	if err != nil {
		t.Fatalf("Generate(second): %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("manifests differ:\nfirst: %#v\nsecond: %#v", first, second)
	}
	compareArtifactTrees(t, firstDir, secondDir)
	if len(first.Artifacts) != 3 || len(first.Licenses) != len(sourceComponents) {
		t.Fatalf("incomplete manifest: %#v", first)
	}
	if got := first.Artifacts[0].LinkedComponents; !reflect.DeepEqual(got, []string{"openssl", "libevent", "expat", "protobuf-c"}) {
		t.Fatalf("unbound linked components = %v", got)
	}
	for _, artifact := range first.Artifacts {
		cycloneDXBytes, err := os.ReadFile(filepath.Join(firstDir, artifact.CycloneDX.Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateCycloneDXContents(cycloneDXBytes, first, artifact); err != nil {
			t.Fatalf("validate %s CycloneDX: %v", artifact.Name, err)
		}
		spdxBytes, err := os.ReadFile(filepath.Join(firstDir, artifact.SPDX.Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSPDXContents(spdxBytes, first, artifact); err != nil {
			t.Fatalf("validate %s SPDX: %v", artifact.Name, err)
		}
		var document spdx.Document
		if err := json.Unmarshal(spdxBytes, &document); err != nil {
			t.Fatalf("decode %s SPDX: %v", artifact.Name, err)
		}
		assertSPDXSDKPurpose(t, artifact.Name, document)
	}
	absoluteFirstDir, err := filepath.Abs(firstDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range metadataFileNames() {
		value, err := os.ReadFile(filepath.Join(firstDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(value, []byte(absoluteFirstDir)) {
			t.Fatalf("%s contains random artifact root", name)
		}
	}
}

func assertSPDXSDKPurpose(t *testing.T, artifactName string, document spdx.Document) {
	t.Helper()
	for _, pkg := range document.Packages {
		if string(pkg.PackageSPDXIdentifier) != "Package-SDK" {
			continue
		}
		if pkg.PrimaryPackagePurpose != "OPERATING_SYSTEM" {
			t.Fatalf("%s SDK primary package purpose = %q", artifactName, pkg.PrimaryPackagePurpose)
		}
		return
	}
	t.Fatalf("%s SPDX document is missing SDK package", artifactName)
}

func TestGenerateRejectsLinkMapWithoutPinnedEvidence(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	artifactDir, linkMapDir := prepareTestBuild(t)
	if err := os.WriteFile(filepath.Join(linkMapDir, "unbound.map"), []byte("system objects only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Generate(testGenerateOptions(repositoryRoot, artifactDir, linkMapDir))
	if err == nil || !strings.Contains(err.Error(), "no pinned static dependency evidence") {
		t.Fatalf("Generate error = %v", err)
	}
}

func TestManifestIntegrityRejectsTamperedBinary(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	artifactDir, linkMapDir := prepareTestBuild(t)
	manifest, err := Generate(testGenerateOptions(repositoryRoot, artifactDir, linkMapDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifest(artifactDir, manifest); err != nil {
		t.Fatalf("validateManifest before tamper: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "unbound"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateManifest(artifactDir, manifest); err == nil || !strings.Contains(err.Error(), "size or SHA-256 mismatch") {
		t.Fatalf("validateManifest after tamper = %v", err)
	}
}

func TestStrictManifestDecoderRejectsUnknownFields(t *testing.T) {
	var manifest ReleaseManifest
	err := decodeStrictJSON([]byte(`{"schemaVersion":1,"unknown":true}`), &manifest)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decodeStrictJSON error = %v", err)
	}
}

func prepareTestBuild(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	artifactDir := filepath.Join(root, "artifact")
	linkMapDir := filepath.Join(root, "maps")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkMapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, helperName := range helperNames {
		value := []byte("deterministic test helper: " + helperName + "\n")
		if err := os.WriteFile(filepath.Join(artifactDir, helperName), value, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	maps := map[string]string{
		"unbound":           "libcrypto.a libssl.a libevent.a libexpat.a libprotobuf-c.a\n",
		"unbound-checkconf": "libcrypto.a libexpat.a\n",
		"unbound-anchor":    "libcrypto.a libexpat.a\n",
	}
	for name, value := range maps {
		if err := os.WriteFile(filepath.Join(linkMapDir, name+".map"), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return artifactDir, linkMapDir
}

func testGenerateOptions(repositoryRoot, artifactDir, linkMapDir string) GenerateOptions {
	return GenerateOptions{
		ArtifactDir:      artifactDir,
		LinkMapDir:       linkMapDir,
		LicenseSourceDir: filepath.Join(repositoryRoot, "third_party", "unbound"),
		PatchPath:        filepath.Join(repositoryRoot, "third_party", "unbound", "patches", patchName),
		Target:           Target{OS: "linux", Arch: "amd64"},
		Toolchain: Toolchain{
			CompilerName: "GCC", CompilerVersion: "gcc (Ubuntu 13.3.0) 13.3.0",
			CompilerTarget: "x86_64-linux-gnu", SDKName: "ubuntu-sysroot", SDKVersion: "24.04 (glibc 2.39)",
		},
		SourceDateEpoch: 1779265372,
	}
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %s: %v", root, err)
	}
	return root
}

func compareArtifactTrees(t *testing.T, firstDir, secondDir string) {
	t.Helper()
	firstFiles := readArtifactTree(t, firstDir)
	secondFiles := readArtifactTree(t, secondDir)
	if !reflect.DeepEqual(firstFiles, secondFiles) {
		firstJSON, _ := json.MarshalIndent(firstFiles, "", "  ")
		secondJSON, _ := json.MarshalIndent(secondFiles, "", "  ")
		t.Fatalf("artifact trees differ:\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
}

func readArtifactTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = sha256Bytes(value)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
