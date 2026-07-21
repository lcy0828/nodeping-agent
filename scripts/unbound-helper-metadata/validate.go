package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
)

const (
	cycloneDXSchemaSHA256 = "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"
	cycloneDXSPDXSHA256   = "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"
	cycloneDXJSFSHA256    = "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"
	spdxSchemaSHA256      = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
)

func ValidateArtifact(artifactDir, cycloneDXSchemaPath, spdxSchemaPath string) error {
	for name, value := range map[string]string{
		"artifact-dir": artifactDir, "cyclonedx-schema": cycloneDXSchemaPath, "spdx-schema": spdxSchemaPath,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	manifestPath := filepath.Join(artifactDir, "unbound-helper-manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	var manifest ReleaseManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("decode release manifest: %w", err)
	}
	if err := validateManifest(artifactDir, manifest); err != nil {
		return err
	}
	cycloneDXSchema, err := compileCycloneDXSchema(cycloneDXSchemaPath)
	if err != nil {
		return err
	}
	spdxSchema, err := compileSPDXSchema(spdxSchemaPath)
	if err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		cycloneDXBytes, err := verifyManifestFile(artifactDir, artifact.CycloneDX)
		if err != nil {
			return fmt.Errorf("verify %s CycloneDX file: %w", artifact.Name, err)
		}
		if err := validateJSONSchema(cycloneDXSchema, cycloneDXBytes); err != nil {
			return fmt.Errorf("validate %s CycloneDX 1.6 schema: %w", artifact.Name, err)
		}
		if err := validateCycloneDXContents(cycloneDXBytes, manifest, artifact); err != nil {
			return fmt.Errorf("validate %s CycloneDX contents: %w", artifact.Name, err)
		}
		spdxBytes, err := verifyManifestFile(artifactDir, artifact.SPDX)
		if err != nil {
			return fmt.Errorf("verify %s SPDX file: %w", artifact.Name, err)
		}
		if err := validateJSONSchema(spdxSchema, spdxBytes); err != nil {
			return fmt.Errorf("validate %s SPDX 2.3 schema: %w", artifact.Name, err)
		}
		if err := validateSPDXContents(spdxBytes, manifest, artifact); err != nil {
			return fmt.Errorf("validate %s SPDX contents: %w", artifact.Name, err)
		}
	}
	absoluteArtifactDir, err := filepath.Abs(artifactDir)
	if err != nil {
		return err
	}
	for _, name := range metadataFileNames() {
		value, err := os.ReadFile(filepath.Join(artifactDir, name))
		if err != nil {
			return err
		}
		if bytes.Contains(value, []byte(absoluteArtifactDir)) {
			return fmt.Errorf("metadata file %s contains its absolute artifact directory", name)
		}
	}
	return nil
}

func validateManifest(artifactDir string, manifest ReleaseManifest) error {
	if manifest.SchemaVersion != metadataSchemaVersion || manifest.Name != "nodeping-unbound-helper" || manifest.Version != unboundVersion {
		return fmt.Errorf("unexpected release manifest identity")
	}
	if !manifest.Unsigned {
		return fmt.Errorf("release manifest must describe the current unsigned candidate")
	}
	if manifest.SourceDateEpoch <= 0 || manifest.Created != time.Unix(manifest.SourceDateEpoch, 0).UTC().Format(time.RFC3339) {
		return fmt.Errorf("release manifest created time does not match sourceDateEpoch")
	}
	if err := validateGenerateOptions(GenerateOptions{
		ArtifactDir: artifactDir, LinkMapDir: ".", LicenseSourceDir: ".", PatchPath: ".",
		Target: manifest.Target, Toolchain: manifest.Toolchain, SourceDateEpoch: manifest.SourceDateEpoch,
	}); err != nil {
		return fmt.Errorf("release manifest build identity: %w", err)
	}
	if manifest.Patch != (ManifestPatch{Name: patchName, SHA256: patchSHA256}) {
		return fmt.Errorf("release manifest patch identity mismatch")
	}
	if !reflect.DeepEqual(manifest.Components, manifestComponents()) {
		return fmt.Errorf("release manifest component inventory mismatch")
	}
	if len(manifest.Licenses) != len(sourceComponents) {
		return fmt.Errorf("release manifest has %d licenses, want %d", len(manifest.Licenses), len(sourceComponents))
	}
	for index, component := range sourceComponents {
		license := manifest.Licenses[index]
		wantPath := "licenses/" + component.LicenseArtifactName
		if license.Path != wantPath || license.SHA256 != component.LicenseSHA256 {
			return fmt.Errorf("release manifest license %d mismatch", index)
		}
		if _, err := verifyManifestFile(artifactDir, license); err != nil {
			return fmt.Errorf("verify %s license: %w", component.ID, err)
		}
	}
	if manifest.Notices.Path != "THIRD_PARTY_NOTICES.md" {
		return fmt.Errorf("unexpected notices path %q", manifest.Notices.Path)
	}
	notices, err := verifyManifestFile(artifactDir, manifest.Notices)
	if err != nil {
		return fmt.Errorf("verify notices: %w", err)
	}
	if !bytes.Equal(notices, renderNotices()) {
		return fmt.Errorf("third-party notices differ from the pinned component inventory")
	}
	if len(manifest.Artifacts) != len(helperNames) {
		return fmt.Errorf("release manifest has %d helpers, want %d", len(manifest.Artifacts), len(helperNames))
	}
	for index, helperName := range helperNames {
		artifact := manifest.Artifacts[index]
		if artifact.Name != helperName || artifact.Path != helperFileName(helperName, manifest.Target.OS) {
			return fmt.Errorf("release manifest helper %d identity mismatch", index)
		}
		binary, err := verifyManifestFile(artifactDir, ManifestFile{Path: artifact.Path, SHA256: artifact.SHA256, Size: artifact.Size})
		if err != nil {
			return fmt.Errorf("verify helper %s: %w", helperName, err)
		}
		if len(binary) == 0 {
			return fmt.Errorf("helper %s is empty", helperName)
		}
		if err := validateLinkedIDs(artifact.LinkedComponents); err != nil {
			return fmt.Errorf("helper %s linked components: %w", helperName, err)
		}
		if artifact.CycloneDX.Path != helperName+".cdx.json" || artifact.SPDX.Path != helperName+".spdx.json" {
			return fmt.Errorf("helper %s SBOM paths mismatch", helperName)
		}
	}
	return nil
}

func validateLinkedIDs(ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no pinned static dependencies")
	}
	seen := make(map[string]bool, len(ids))
	lastIndex := -1
	for _, id := range ids {
		component, ok := componentByID(id)
		if !ok || component.BuildOnly || len(component.StaticLibraryMarkers) == 0 {
			return fmt.Errorf("invalid static dependency %q", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate static dependency %q", id)
		}
		seen[id] = true
		index := componentIndex(id)
		if index <= lastIndex {
			return fmt.Errorf("static dependencies are not in canonical order")
		}
		lastIndex = index
	}
	return nil
}

func componentIndex(id string) int {
	for index, component := range sourceComponents {
		if component.ID == id {
			return index
		}
	}
	return -1
}

func compileCycloneDXSchema(mainPath string) (*jsonschema.Schema, error) {
	mainBytes, err := readPinnedFile(mainPath, cycloneDXSchemaSHA256)
	if err != nil {
		return nil, fmt.Errorf("CycloneDX schema: %w", err)
	}
	directory := filepath.Dir(mainPath)
	spdxBytes, err := readPinnedFile(filepath.Join(directory, "spdx.schema.json"), cycloneDXSPDXSHA256)
	if err != nil {
		return nil, fmt.Errorf("CycloneDX SPDX expression schema: %w", err)
	}
	jsfBytes, err := readPinnedFile(filepath.Join(directory, "jsf-0.82.schema.json"), cycloneDXJSFSHA256)
	if err != nil {
		return nil, fmt.Errorf("CycloneDX JSF schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	resources := []struct {
		url   string
		value []byte
	}{
		{"http://cyclonedx.org/schema/bom-1.6.schema.json", mainBytes},
		{"http://cyclonedx.org/schema/spdx.schema.json", spdxBytes},
		{"http://cyclonedx.org/schema/jsf-0.82.schema.json", jsfBytes},
	}
	for _, resource := range resources {
		if err := addJSONSchemaResource(compiler, resource.url, resource.value); err != nil {
			return nil, err
		}
	}
	return compiler.Compile(resources[0].url)
}

func compileSPDXSchema(path string) (*jsonschema.Schema, error) {
	value, err := readPinnedFile(path, spdxSchemaSHA256)
	if err != nil {
		return nil, fmt.Errorf("SPDX schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaURL = "http://spdx.org/rdf/terms/2.3"
	if err := addJSONSchemaResource(compiler, schemaURL, value); err != nil {
		return nil, err
	}
	return compiler.Compile(schemaURL)
}

func decodeJSONValue(value []byte) (any, error) {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return document, nil
}

func addJSONSchemaResource(compiler *jsonschema.Compiler, url string, value []byte) error {
	document, err := decodeJSONValue(value)
	if err != nil {
		return fmt.Errorf("decode schema resource %s: %w", url, err)
	}
	return compiler.AddResource(url, document)
}

func validateJSONSchema(schema *jsonschema.Schema, value []byte) error {
	document, err := decodeJSONValue(value)
	if err != nil {
		return err
	}
	return schema.Validate(document)
}

func validateCycloneDXContents(value []byte, manifest ReleaseManifest, artifact ManifestArtifact) error {
	var bom cdx.BOM
	if err := json.Unmarshal(value, &bom); err != nil {
		return err
	}
	if bom.BOMFormat != cdx.BOMFormat || bom.SpecVersion != cdx.SpecVersion1_6 || bom.Metadata == nil || bom.Metadata.Component == nil {
		return fmt.Errorf("unexpected CycloneDX identity or missing root component")
	}
	root := bom.Metadata.Component
	if root.Name != artifact.Name || root.Version != manifest.Version || !cycloneDXHasSHA256(root.Hashes, artifact.SHA256) {
		return fmt.Errorf("CycloneDX root component does not match helper")
	}
	wantRefs := map[string]bool{"component:unbound": true, "component:protobuf-c": true, "component:protobuf": true, "file:unbound-dnstap-patch": true}
	for _, id := range artifact.LinkedComponents {
		wantRefs["component:"+id] = true
	}
	if bom.Components == nil {
		return fmt.Errorf("CycloneDX components are missing")
	}
	for _, component := range *bom.Components {
		delete(wantRefs, component.BOMRef)
	}
	if len(wantRefs) != 0 {
		return fmt.Errorf("CycloneDX is missing component refs %v", mapKeys(wantRefs))
	}
	return nil
}

func cycloneDXHasSHA256(hashes *[]cdx.Hash, expected string) bool {
	if hashes == nil {
		return false
	}
	for _, hash := range *hashes {
		if hash.Algorithm == cdx.HashAlgoSHA256 && hash.Value == expected {
			return true
		}
	}
	return false
}

func validateSPDXContents(value []byte, manifest ReleaseManifest, artifact ManifestArtifact) error {
	var document spdx.Document
	if err := json.Unmarshal(value, &document); err != nil {
		return err
	}
	if document.SPDXVersion != spdx.Version || document.DataLicense != spdx.DataLicense {
		return fmt.Errorf("unexpected SPDX document identity")
	}
	if err := spdxlib.ValidateDocument(&document); err != nil {
		return err
	}
	for _, pkg := range document.Packages {
		if string(pkg.PackageSPDXIdentifier) != "Package-Root" {
			continue
		}
		if pkg.PackageName != artifact.Name || pkg.PackageVersion != manifest.Version {
			return fmt.Errorf("SPDX root package identity mismatch")
		}
		for _, checksum := range pkg.PackageChecksums {
			if checksum.Algorithm == spdx.SHA256 && checksum.Value == artifact.SHA256 {
				return nil
			}
		}
		return fmt.Errorf("SPDX root package SHA-256 mismatch")
	}
	return fmt.Errorf("SPDX root package is missing")
}

func verifyManifestFile(root string, file ManifestFile) ([]byte, error) {
	if file.Path == "" || file.Size < 0 || file.SHA256 == "" || filepath.IsAbs(file.Path) {
		return nil, fmt.Errorf("invalid manifest file identity")
	}
	clean := filepath.Clean(filepath.FromSlash(file.Path))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("manifest path escapes artifact directory: %s", file.Path)
	}
	path := filepath.Join(root, clean)
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(value)) != file.Size || sha256Bytes(value) != file.SHA256 {
		return nil, fmt.Errorf("size or SHA-256 mismatch for %s", file.Path)
	}
	return value, nil
}

func readPinnedFile(path, expected string) ([]byte, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if actual := sha256Bytes(value); actual != expected {
		return nil, fmt.Errorf("SHA-256 %s = %s, want %s", path, actual, expected)
	}
	return value, nil
}

func decodeStrictJSON(value []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func metadataFileNames() []string {
	names := []string{"unbound-helper-manifest.json"}
	for _, helperName := range helperNames {
		names = append(names, helperName+".cdx.json", helperName+".spdx.json")
	}
	return names
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return sortedStrings(keys)
}
