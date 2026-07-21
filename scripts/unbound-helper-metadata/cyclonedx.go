package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func renderCycloneDX(manifest ReleaseManifest, artifact ManifestArtifact) ([]byte, error) {
	rootRef := artifactBOMRef(manifest, artifact)
	root := cdx.Component{
		BOMRef:  rootRef,
		Type:    cdx.ComponentTypeApplication,
		Group:   "nodeping",
		Name:    artifact.Name,
		Version: manifest.Version,
		Scope:   cdx.ScopeRequired,
		Hashes: &[]cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: artifact.SHA256},
		},
		Licenses: licenseExpression("BSD-3-Clause"),
		Properties: &[]cdx.Property{
			{Name: "nodeping:artifact:path", Value: artifact.Path},
			{Name: "nodeping:artifact:unsigned", Value: "true"},
			{Name: "nodeping:build:source-date-epoch", Value: fmt.Sprint(manifest.SourceDateEpoch)},
			{Name: "nodeping:target:arch", Value: manifest.Target.Arch},
			{Name: "nodeping:target:os", Value: manifest.Target.OS},
		},
	}
	components := []cdx.Component{cycloneDXSourceComponent(sourceComponents[0], cdx.ScopeRequired, "source")}
	dependencyRefs := []string{"component:unbound"}
	included := map[string]bool{"unbound": true}
	for _, id := range artifact.LinkedComponents {
		component, ok := componentByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown linked component %q", id)
		}
		role := "static-link"
		if id == "protobuf-c" {
			role = "static-link-and-build-tool"
		}
		components = append(components, cycloneDXSourceComponent(component, cdx.ScopeRequired, role))
		dependencyRefs = append(dependencyRefs, "component:"+component.ID)
		included[id] = true
	}
	if !included["protobuf-c"] {
		protobufC, _ := componentByID("protobuf-c")
		components = append(components, cycloneDXSourceComponent(protobufC, cdx.ScopeExcluded, "build-tool"))
	}
	protobuf, _ := componentByID("protobuf")
	components = append(components, cycloneDXSourceComponent(protobuf, cdx.ScopeExcluded, "build-tool"))
	components = append(components, cdx.Component{
		BOMRef: "file:unbound-dnstap-patch",
		Type:   cdx.ComponentTypeFile,
		Name:   patchName,
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: patchSHA256}},
		Scope:  cdx.ScopeExcluded,
		Properties: &[]cdx.Property{
			{Name: "nodeping:dependency:role", Value: "source-patch"},
		},
	})

	tools := []cdx.Component{
		{
			BOMRef: "tool:metadata-generator", Type: cdx.ComponentTypeApplication,
			Group: "nodeping", Name: metadataToolName, Version: metadataToolVersion,
		},
		{
			BOMRef: "tool:compiler", Type: cdx.ComponentTypeApplication,
			Name: manifest.Toolchain.CompilerName, Version: manifest.Toolchain.CompilerVersion,
			Properties: &[]cdx.Property{
				{Name: "nodeping:compiler:target", Value: manifest.Toolchain.CompilerTarget},
			},
		},
		{
			BOMRef: "tool:sdk", Type: cdx.ComponentTypeOS,
			Name: manifest.Toolchain.SDKName, Version: manifest.Toolchain.SDKVersion,
		},
	}
	dependencies := []cdx.Dependency{{Ref: rootRef, Dependencies: &dependencyRefs}}
	for _, ref := range dependencyRefs {
		dependencies = append(dependencies, cdx.Dependency{Ref: ref})
	}
	bom := cdx.NewBOM()
	bom.SerialNumber = deterministicUUID(rootRef + ":" + artifact.SHA256)
	bom.Metadata = &cdx.Metadata{
		Timestamp: manifest.Created,
		Tools:     &cdx.ToolsChoice{Components: &tools},
		Component: &root,
		Properties: &[]cdx.Property{
			{Name: "nodeping:build:sdk", Value: manifest.Toolchain.SDKName + " " + manifest.Toolchain.SDKVersion},
			{Name: "nodeping:patch:sha256", Value: manifest.Patch.SHA256},
		},
	}
	bom.Components = &components
	bom.Dependencies = &dependencies
	var output bytes.Buffer
	encoder := cdx.NewBOMEncoder(&output, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)
	if err := encoder.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func cycloneDXSourceComponent(component sourceComponent, scope cdx.Scope, role string) cdx.Component {
	references := []cdx.ExternalReference{{
		Type: cdx.ERTypeDistribution, URL: component.SourceURL,
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: component.SHA256}},
	}}
	return cdx.Component{
		BOMRef:  "component:" + component.ID,
		Type:    cdx.ComponentTypeLibrary,
		Name:    component.Name,
		Version: component.Version,
		Scope:   scope,
		Hashes: &[]cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: component.SHA256},
		},
		Licenses:           licenseExpression(component.License),
		ExternalReferences: &references,
		Properties: &[]cdx.Property{
			{Name: "nodeping:dependency:role", Value: role},
			{Name: "nodeping:license-notice:path", Value: "licenses/" + component.LicenseArtifactName},
			{Name: "nodeping:source:archive-sha256", Value: component.SHA256},
		},
	}
}

func licenseExpression(expression string) *cdx.Licenses {
	licenses := cdx.Licenses{{Expression: expression}}
	return &licenses
}

func artifactBOMRef(manifest ReleaseManifest, artifact ManifestArtifact) string {
	return fmt.Sprintf("artifact:%s:%s:%s:%s", artifact.Name, manifest.Target.OS, manifest.Target.Arch, artifact.SHA256[:16])
}

func deterministicUUID(value string) string {
	digest := sha256.Sum256([]byte(value))
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	encoded := fmt.Sprintf("%x", digest[:16])
	return "urn:uuid:" + strings.Join([]string{
		encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32],
	}, "-")
}
