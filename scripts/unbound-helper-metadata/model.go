package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	metadataSchemaVersion = 1
	metadataToolName      = "nodeping-unbound-helper-metadata"
	metadataToolVersion   = "1.0.0"
	unboundVersion        = "1.25.1"
	patchName             = "0001-dnstap-deterministic-evidence.patch"
	patchSHA256           = "a42affbccfa7ede0d86672258c8775a69bf02156b299bcc8d55bfc3a791557ae"
)

type sourceComponent struct {
	ID                   string
	Name                 string
	Version              string
	SourceURL            string
	SHA256               string
	License              string
	LicenseSourceName    string
	LicenseArtifactName  string
	LicenseSHA256        string
	BuildOnly            bool
	StaticLibraryMarkers []string
}

var sourceComponents = []sourceComponent{
	{
		ID: "unbound", Name: "Unbound", Version: unboundVersion,
		SourceURL: "https://nlnetlabs.nl/downloads/unbound/unbound-1.25.1.tar.gz",
		SHA256:    "0fe8b6277b0959cfd17562debac0aa5f71e0b02dc4ffa9c60271c583edab586f",
		License:   "BSD-3-Clause", LicenseSourceName: "LICENSE-BSD-3-CLAUSE.txt",
		LicenseArtifactName: "unbound-BSD-3-Clause.txt",
		LicenseSHA256:       "8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db",
	},
	{
		ID: "openssl", Name: "OpenSSL", Version: "3.5.7",
		SourceURL: "https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz",
		SHA256:    "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8",
		License:   "Apache-2.0", LicenseSourceName: "LICENSE-OPENSSL-APACHE-2.0.txt",
		LicenseArtifactName:  "openssl-Apache-2.0.txt",
		LicenseSHA256:        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
		StaticLibraryMarkers: []string{"libcrypto.a", "libssl.a"},
	},
	{
		ID: "libevent", Name: "libevent", Version: "2.1.13-stable",
		SourceURL: "https://github.com/libevent/libevent/releases/download/release-2.1.13-stable/libevent-2.1.13-stable.tar.gz",
		SHA256:    "f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c",
		License:   "BSD-3-Clause", LicenseSourceName: "LICENSE-LIBEVENT.txt",
		LicenseArtifactName:  "libevent-BSD-3-Clause.txt",
		LicenseSHA256:        "ff02effc9b331edcdac387d198691bfa3e575e7d244ad10cb826aa51ef085670",
		StaticLibraryMarkers: []string{"libevent.a", "libevent_core.a"},
	},
	{
		ID: "expat", Name: "Expat", Version: "2.8.2",
		SourceURL: "https://github.com/libexpat/libexpat/releases/download/R_2_8_2/expat-2.8.2.tar.xz",
		SHA256:    "3ad89b8588e6644bd4e49981480d48b21289eebbcd4f0a1a4afb1c29f99b6ab4",
		License:   "MIT", LicenseSourceName: "LICENSE-EXPAT-MIT.txt",
		LicenseArtifactName:  "expat-MIT.txt",
		LicenseSHA256:        "31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87",
		StaticLibraryMarkers: []string{"libexpat.a"},
	},
	{
		ID: "protobuf-c", Name: "protobuf-c", Version: "1.5.2",
		SourceURL: "https://github.com/protobuf-c/protobuf-c/releases/download/v1.5.2/protobuf-c-1.5.2.tar.gz",
		SHA256:    "e2c86271873a79c92b58fef7ebf8de1aa0df4738347a8bd5d4e65a80a16d0d24",
		License:   "BSD-2-Clause", LicenseSourceName: "LICENSE-PROTOBUF-C-BSD-2-CLAUSE.txt",
		LicenseArtifactName:  "protobuf-c-BSD-2-Clause.txt",
		LicenseSHA256:        "2d1d028bd27f8c85bc970d720519d2069ca6213fcb26b9dea444a7c39d24bbb3",
		StaticLibraryMarkers: []string{"libprotobuf-c.a"},
	},
	{
		ID: "protobuf", Name: "Protocol Buffers", Version: "21.12",
		SourceURL: "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-all-21.12.tar.gz",
		SHA256:    "2c6a36c7b5a55accae063667ef3c55f2642e67476d96d355ff0acb13dbb47f09",
		License:   "BSD-3-Clause", LicenseSourceName: "LICENSE-PROTOBUF-BSD-3-CLAUSE.txt",
		LicenseArtifactName: "protobuf-BSD-3-Clause.txt",
		LicenseSHA256:       "6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d",
		BuildOnly:           true,
	},
}

var helperNames = []string{"unbound", "unbound-checkconf", "unbound-anchor"}

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Toolchain struct {
	CompilerName    string `json:"compilerName"`
	CompilerVersion string `json:"compilerVersion"`
	CompilerTarget  string `json:"compilerTarget"`
	SDKName         string `json:"sdkName"`
	SDKVersion      string `json:"sdkVersion"`
}

type GenerateOptions struct {
	ArtifactDir      string
	LinkMapDir       string
	LicenseSourceDir string
	PatchPath        string
	Target           Target
	Toolchain        Toolchain
	SourceDateEpoch  int64
}

type ReleaseManifest struct {
	SchemaVersion   int                 `json:"schemaVersion"`
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Created         string              `json:"created"`
	SourceDateEpoch int64               `json:"sourceDateEpoch"`
	Unsigned        bool                `json:"unsigned"`
	Target          Target              `json:"target"`
	Toolchain       Toolchain           `json:"toolchain"`
	Patch           ManifestPatch       `json:"patch"`
	Components      []ManifestComponent `json:"components"`
	Licenses        []ManifestFile      `json:"licenses"`
	Notices         ManifestFile        `json:"notices"`
	Artifacts       []ManifestArtifact  `json:"artifacts"`
}

type ManifestPatch struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type ManifestComponent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	SourceURL string `json:"sourceUrl"`
	SHA256    string `json:"sha256"`
	License   string `json:"license"`
	BuildOnly bool   `json:"buildOnly"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ManifestArtifact struct {
	Name             string       `json:"name"`
	Path             string       `json:"path"`
	SHA256           string       `json:"sha256"`
	Size             int64        `json:"size"`
	LinkedComponents []string     `json:"linkedComponents"`
	CycloneDX        ManifestFile `json:"cycloneDx"`
	SPDX             ManifestFile `json:"spdx"`
}

func detectToolchain(compiler, targetOS, sdkName, sdkVersion string) (Toolchain, error) {
	if compiler == "" || strings.ContainsAny(compiler, " \t\r\n") {
		return Toolchain{}, fmt.Errorf("compiler must be one command without arguments")
	}
	versionOutput, err := exec.Command(compiler, "--version").CombinedOutput()
	if err != nil {
		return Toolchain{}, fmt.Errorf("run %s --version: %w: %s", compiler, err, bytes.TrimSpace(versionOutput))
	}
	version := firstNonemptyLine(versionOutput)
	if version == "" {
		return Toolchain{}, fmt.Errorf("%s --version returned no version", compiler)
	}
	targetOutput, err := exec.Command(compiler, "-dumpmachine").CombinedOutput()
	if err != nil {
		return Toolchain{}, fmt.Errorf("run %s -dumpmachine: %w: %s", compiler, err, bytes.TrimSpace(targetOutput))
	}
	compilerName := filepath.Base(compiler)
	switch {
	case strings.Contains(version, "Apple clang"):
		compilerName = "AppleClang"
	case strings.Contains(strings.ToLower(version), "clang"):
		compilerName = "Clang"
	case strings.Contains(strings.ToLower(version), "gcc") || strings.Contains(version, "Free Software Foundation"):
		compilerName = "GCC"
	}
	if sdkName == "" || sdkVersion == "" {
		detectedName, detectedVersion, detectErr := detectSDK(targetOS)
		if detectErr != nil {
			return Toolchain{}, detectErr
		}
		if sdkName == "" {
			sdkName = detectedName
		}
		if sdkVersion == "" {
			sdkVersion = detectedVersion
		}
	}
	toolchain := Toolchain{
		CompilerName:    compilerName,
		CompilerVersion: version,
		CompilerTarget:  strings.TrimSpace(string(targetOutput)),
		SDKName:         sdkName,
		SDKVersion:      sdkVersion,
	}
	if err := validateToolchain(toolchain); err != nil {
		return Toolchain{}, err
	}
	return toolchain, nil
}

func detectSDK(targetOS string) (string, string, error) {
	switch targetOS {
	case "darwin":
		output, err := exec.Command("xcrun", "--sdk", "macosx", "--show-sdk-version").CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("detect macOS SDK: %w: %s", err, bytes.TrimSpace(output))
		}
		return "macosx", strings.TrimSpace(string(output)), nil
	case "linux":
		values, err := readOSRelease("/etc/os-release")
		if err != nil {
			return "", "", err
		}
		name, version := values["ID"], values["VERSION_ID"]
		if name == "" || version == "" {
			return "", "", fmt.Errorf("/etc/os-release is missing ID or VERSION_ID")
		}
		libcOutput, err := exec.Command("getconf", "GNU_LIBC_VERSION").CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("detect glibc version: %w: %s", err, bytes.TrimSpace(libcOutput))
		}
		return name + "-sysroot", version + " (" + strings.TrimSpace(string(libcOutput)) + ")", nil
	case "windows":
		return "", "", fmt.Errorf("Windows builds must provide --sdk-name and --sdk-version")
	default:
		return "", "", fmt.Errorf("unsupported target OS %q", targetOS)
	}
}

func readOSRelease(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || key == "" {
			continue
		}
		if strings.HasPrefix(value, "\"") {
			decoded, decodeErr := strconv.Unquote(value)
			if decodeErr != nil {
				return nil, fmt.Errorf("parse %s key %s: %w", path, key, decodeErr)
			}
			value = decoded
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

func firstNonemptyLine(value []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			return line
		}
	}
	return ""
}

func validateToolchain(value Toolchain) error {
	fields := map[string]string{
		"compiler name": value.CompilerName, "compiler version": value.CompilerVersion,
		"compiler target": value.CompilerTarget, "SDK name": value.SDKName, "SDK version": value.SDKVersion,
	}
	for name, field := range fields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("toolchain %s is empty", name)
		}
		if strings.ContainsAny(field, "\r\n") {
			return fmt.Errorf("toolchain %s contains a newline", name)
		}
	}
	return nil
}

func helperFileName(name, targetOS string) string {
	if targetOS == "windows" {
		return name + ".exe"
	}
	return name
}

func linkedComponents(linkMapPath string) ([]string, error) {
	value, err := os.ReadFile(linkMapPath)
	if err != nil {
		return nil, fmt.Errorf("read linker map %s: %w", linkMapPath, err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("linker map is empty: %s", linkMapPath)
	}
	var ids []string
	for _, component := range sourceComponents {
		if component.BuildOnly || len(component.StaticLibraryMarkers) == 0 {
			continue
		}
		for _, marker := range component.StaticLibraryMarkers {
			if bytes.Contains(value, []byte(marker)) {
				ids = append(ids, component.ID)
				break
			}
		}
	}
	return ids, nil
}

func sha256Path(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func sha1Path(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha1.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func manifestComponents() []ManifestComponent {
	result := make([]ManifestComponent, 0, len(sourceComponents))
	for _, component := range sourceComponents {
		result = append(result, ManifestComponent{
			ID: component.ID, Name: component.Name, Version: component.Version,
			SourceURL: component.SourceURL, SHA256: component.SHA256,
			License: component.License, BuildOnly: component.BuildOnly,
		})
	}
	return result
}

func componentByID(id string) (sourceComponent, bool) {
	for _, component := range sourceComponents {
		if component.ID == id {
			return component, true
		}
	}
	return sourceComponent{}, false
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func currentRuntimeTarget() Target {
	return Target{OS: runtime.GOOS, Arch: runtime.GOARCH}
}
