package nodepingagentdeploy

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseScriptsBootstrapPinnedMinisignWithoutDowngradingSignatures(t *testing.T) {
	const (
		archiveHash = "9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
		amd64Hash   = "2c74dffcc1c9a5ee55957c60971998ace2b89f22585631594ec2152c588af8db"
		arm64Hash   = "cec9f88be8c975af76854a53b4d49c3d257feae38d916edb0d16fb55aacd3000"
	)

	var bootstrapImplementation string
	for _, name := range []string{"install-release.sh", "update-nodeping-agent.sh"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, required := range []string{
			`MINISIGN_BOOTSTRAP_VERSION="0.12"`,
			archiveHash,
			amd64Hash,
			arm64Hash,
			"https://github.com/jedisct1/minisign/releases/download/",
			"download_release_source_file",
			`actual="$(sha256_value "$destination")"`,
			`actual="$(sha256_value "$extracted")"`,
			`ensure_minisign "$tmp_dir"`,
			"release signature verification was not downgraded",
		} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s missing pinned minisign bootstrap requirement %q", name, required)
			}
		}

		ensure := shellFunctionSection(t, name, text, "ensure_minisign() {", "normalize_signature_mode() {")
		staticIndex := strings.Index(ensure, `install_bootstrap_minisign "$directory"`)
		packageIndex := strings.Index(ensure, "install_minisign_package")
		if staticIndex < 0 || packageIndex < 0 || staticIndex >= packageIndex {
			t.Fatalf("%s must try the pinned static verifier before the package manager", name)
		}

		implementation := shellFunctionSection(t, name, text, "find_minisign() {", "install_minisign_package() {")
		if bootstrapImplementation == "" {
			bootstrapImplementation = implementation
		} else if implementation != bootstrapImplementation {
			t.Fatalf("%s minisign bootstrap logic drifted from install-release.sh", name)
		}
	}
}

func TestSystemdUninstallerRemovesManagedMinisign(t *testing.T) {
	content, err := os.ReadFile("uninstall-systemd.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"$INSTALL_DIR/minisign"`) {
		t.Fatal("uninstall-systemd.sh does not remove the NodePing-managed minisign verifier")
	}
}

func shellFunctionSection(t *testing.T, name, text, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(text, startMarker)
	if start < 0 {
		t.Fatalf("%s missing %q", name, startMarker)
	}
	endOffset := strings.Index(text[start:], endMarker)
	if endOffset < 0 {
		t.Fatalf("%s missing %q after %q", name, endMarker, startMarker)
	}
	return text[start : start+endOffset]
}
