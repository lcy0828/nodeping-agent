package main

import (
	"fmt"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdxlib"
)

func renderSPDX(manifest ReleaseManifest, artifact ManifestArtifact, patchSHA1 string) ([]byte, error) {
	rootID := common.ElementID("Package-Root")
	unboundID := common.ElementID("Package-unbound")
	packages := []*spdx.Package{spdxArtifactPackage(manifest, artifact, rootID)}
	included := map[string]bool{}
	appendComponent := func(id string) error {
		if included[id] {
			return nil
		}
		component, ok := componentByID(id)
		if !ok {
			return fmt.Errorf("unknown SPDX component %q", id)
		}
		packages = append(packages, spdxSourcePackage(component))
		included[id] = true
		return nil
	}
	if err := appendComponent("unbound"); err != nil {
		return nil, err
	}
	for _, id := range artifact.LinkedComponents {
		if err := appendComponent(id); err != nil {
			return nil, err
		}
	}
	for _, id := range []string{"protobuf-c", "protobuf"} {
		if err := appendComponent(id); err != nil {
			return nil, err
		}
	}
	compilerID := common.ElementID("Package-Compiler")
	sdkID := common.ElementID("Package-SDK")
	packages = append(packages,
		spdxToolPackage(compilerID, manifest.Toolchain.CompilerName, manifest.Toolchain.CompilerVersion, "APPLICATION"),
		spdxToolPackage(sdkID, manifest.Toolchain.SDKName, manifest.Toolchain.SDKVersion, "OPERATING_SYSTEM"),
	)
	patchID := common.ElementID("File-Unbound-Dnstap-Patch")
	patch := &spdx.File{
		FileName:           "./patches/" + patchName,
		FileSPDXIdentifier: patchID,
		FileTypes:          []string{"SOURCE"},
		Checksums:          []common.Checksum{{Algorithm: common.SHA1, Value: patchSHA1}, {Algorithm: common.SHA256, Value: patchSHA256}},
		LicenseConcluded:   "NOASSERTION",
		LicenseInfoInFiles: []string{"NOASSERTION"},
		FileCopyrightText:  "NOASSERTION",
		FileComment:        "Pinned NodePing deterministic dnstap evidence patch.",
	}
	relationships := []*spdx.Relationship{
		spdxRelationship(common.ElementID("DOCUMENT"), rootID, spdx.RelationshipDescribes),
		spdxRelationship(rootID, unboundID, spdx.RelationshipGeneratedFrom),
		spdxRelationship(patchID, unboundID, spdx.RelationshipPatchFor),
		spdxRelationship(common.ElementID("Package-protobuf-c"), rootID, spdx.RelationshipBuildToolOf),
		spdxRelationship(common.ElementID("Package-protobuf"), rootID, spdx.RelationshipBuildToolOf),
		spdxRelationship(compilerID, rootID, spdx.RelationshipBuildToolOf),
		spdxRelationship(sdkID, rootID, spdx.RelationshipPrerequisiteFor),
	}
	for _, id := range artifact.LinkedComponents {
		relationships = append(relationships,
			spdxRelationship(rootID, common.ElementID("Package-"+id), spdx.RelationshipStaticLink),
		)
	}
	document := &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    common.ElementID("DOCUMENT"),
		DocumentName:      fmt.Sprintf("nodeping-unbound-helper-%s-%s-%s", artifact.Name, manifest.Target.OS, manifest.Target.Arch),
		DocumentNamespace: fmt.Sprintf("https://nodeping.dev/spdx/unbound-helper/%s/%s/%s/%s/%s", manifest.Version, manifest.Target.OS, manifest.Target.Arch, artifact.Name, artifact.SHA256),
		DocumentComment:   "Per-binary SPDX document for an unsigned reproducible helper candidate.",
		CreationInfo: &spdx.CreationInfo{
			Creators: []common.Creator{{CreatorType: "Tool", Creator: metadataToolName + "-" + metadataToolVersion}},
			Created:  manifest.Created,
			CreatorComment: fmt.Sprintf("compiler=%s; compilerTarget=%s; sdk=%s %s; sourceDateEpoch=%d",
				manifest.Toolchain.CompilerVersion, manifest.Toolchain.CompilerTarget,
				manifest.Toolchain.SDKName, manifest.Toolchain.SDKVersion, manifest.SourceDateEpoch),
		},
		Packages:      packages,
		Files:         []*spdx.File{patch},
		Relationships: relationships,
	}
	if err := spdxlib.ValidateDocument(document); err != nil {
		return nil, err
	}
	return encodeJSON(document)
}

func spdxArtifactPackage(manifest ReleaseManifest, artifact ManifestArtifact, id common.ElementID) *spdx.Package {
	return &spdx.Package{
		PackageName:               artifact.Name,
		PackageSPDXIdentifier:     id,
		PackageVersion:            manifest.Version,
		PackageFileName:           artifact.Path,
		PackageDownloadLocation:   "NOASSERTION",
		FilesAnalyzed:             false,
		IsFilesAnalyzedTagPresent: true,
		PackageChecksums:          []common.Checksum{{Algorithm: common.SHA256, Value: artifact.SHA256}},
		PackageLicenseConcluded:   "NOASSERTION",
		PackageLicenseDeclared:    "NOASSERTION",
		PackageCopyrightText:      "NOASSERTION",
		PackageSummary:            "NodePing patched Unbound helper executable with bounded dnstap evidence support.",
		PackageComment: fmt.Sprintf("unsigned=true; target=%s/%s; compiler=%s; sdk=%s %s; patchSHA256=%s",
			manifest.Target.OS, manifest.Target.Arch, manifest.Toolchain.CompilerVersion,
			manifest.Toolchain.SDKName, manifest.Toolchain.SDKVersion, patchSHA256),
		PrimaryPackagePurpose: "APPLICATION",
		BuiltDate:             manifest.Created,
	}
}

func spdxSourcePackage(component sourceComponent) *spdx.Package {
	return &spdx.Package{
		PackageName:               component.Name,
		PackageSPDXIdentifier:     common.ElementID("Package-" + component.ID),
		PackageVersion:            component.Version,
		PackageFileName:           filepathBaseFromURL(component.SourceURL),
		PackageDownloadLocation:   component.SourceURL,
		FilesAnalyzed:             false,
		IsFilesAnalyzedTagPresent: true,
		PackageChecksums:          []common.Checksum{{Algorithm: common.SHA256, Value: component.SHA256}},
		PackageLicenseConcluded:   component.License,
		PackageLicenseDeclared:    component.License,
		PackageLicenseComments:    "License notice: licenses/" + component.LicenseArtifactName,
		PackageCopyrightText:      "NOASSERTION",
		PackageSourceInfo:         "Pinned upstream release archive; SHA-256 verified before build.",
		PrimaryPackagePurpose:     "SOURCE",
	}
}

func spdxToolPackage(id common.ElementID, name, version, purpose string) *spdx.Package {
	return &spdx.Package{
		PackageName:               name,
		PackageSPDXIdentifier:     id,
		PackageVersion:            version,
		PackageDownloadLocation:   "NOASSERTION",
		FilesAnalyzed:             false,
		IsFilesAnalyzedTagPresent: true,
		PackageLicenseConcluded:   "NOASSERTION",
		PackageLicenseDeclared:    "NOASSERTION",
		PackageCopyrightText:      "NOASSERTION",
		PrimaryPackagePurpose:     purpose,
	}
}

func spdxRelationship(from, to common.ElementID, relationship string) *spdx.Relationship {
	return &spdx.Relationship{
		RefA:         common.MakeDocElementID("", string(from)),
		RefB:         common.MakeDocElementID("", string(to)),
		Relationship: relationship,
	}
}

func filepathBaseFromURL(value string) string {
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == '/' {
			return value[index+1:]
		}
	}
	return value
}
