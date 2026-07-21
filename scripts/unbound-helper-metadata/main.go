package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: unbound-helper-metadata <generate|validate> [options]")
	}
	switch arguments[0] {
	case "generate":
		return runGenerate(arguments[1:])
	case "validate":
		return runValidate(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func runGenerate(arguments []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	artifactDir := flags.String("artifact-dir", "", "directory containing helper binaries and receiving metadata")
	linkMapDir := flags.String("link-map-dir", "", "directory containing one linker map per helper")
	licenseSourceDir := flags.String("license-source-dir", "", "directory containing pinned license files")
	patchPath := flags.String("patch-path", "", "path to the pinned Unbound patch")
	targetOS := flags.String("target-os", runtime.GOOS, "artifact operating system")
	targetArch := flags.String("target-arch", runtime.GOARCH, "artifact architecture")
	compiler := flags.String("compiler", "cc", "native C compiler command")
	sdkName := flags.String("sdk-name", "", "build SDK or sysroot name override")
	sdkVersion := flags.String("sdk-version", "", "build SDK or sysroot version override")
	sourceDateEpoch := flags.String("source-date-epoch", "", "reproducible build timestamp")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("generate: unexpected arguments: %v", flags.Args())
	}
	epoch, err := strconv.ParseInt(*sourceDateEpoch, 10, 64)
	if err != nil || epoch <= 0 {
		return fmt.Errorf("generate: source-date-epoch must be a positive integer")
	}
	toolchain, err := detectToolchain(*compiler, *targetOS, *sdkName, *sdkVersion)
	if err != nil {
		return err
	}
	_, err = Generate(GenerateOptions{
		ArtifactDir:      *artifactDir,
		LinkMapDir:       *linkMapDir,
		LicenseSourceDir: *licenseSourceDir,
		PatchPath:        *patchPath,
		Target:           Target{OS: *targetOS, Arch: *targetArch},
		Toolchain:        toolchain,
		SourceDateEpoch:  epoch,
	})
	return err
}

func runValidate(arguments []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	artifactDir := flags.String("artifact-dir", "", "directory containing helper binaries and metadata")
	cycloneDXSchema := flags.String("cyclonedx-schema", "", "path to the CycloneDX 1.6 JSON schema")
	spdxSchema := flags.String("spdx-schema", "", "path to the SPDX 2.3 JSON schema")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("validate: unexpected arguments: %v", flags.Args())
	}
	return ValidateArtifact(*artifactDir, *cycloneDXSchema, *spdxSchema)
}
