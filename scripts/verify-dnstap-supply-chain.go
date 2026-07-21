//go:build ignore

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type modulePin struct {
	Path    string
	Version string
	Sum     string
}

type moduleInfo struct {
	Path    string
	Version string
	Sum     string
	Dir     string
}

var modulePins = []modulePin{
	{Path: "github.com/dnstap/golang-dnstap", Version: "v0.4.0", Sum: "h1:KRHBoURygdGtBjDI2w4HifJfMAhhOqDuktAokaSa234="},
	{Path: "github.com/farsightsec/golang-framestream", Version: "v0.3.0", Sum: "h1:/spFQHucTle/ZIPkYqrfshQqPe2VQEzesH243TjIwqA="},
	{Path: "google.golang.org/protobuf", Version: "v1.36.11", Sum: "h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE="},
}

func main() {
	root, err := repositoryRoot()
	if err != nil {
		fail(err)
	}
	modules := make(map[string]moduleInfo, len(modulePins))
	for _, pin := range modulePins {
		info, err := loadModule(root, pin.Path)
		if err != nil {
			fail(err)
		}
		if info.Version != pin.Version || info.Sum != pin.Sum || info.Dir == "" {
			fail(fmt.Errorf("module %s = version %q sum %q dir %q, want %q %q and a local directory", pin.Path, info.Version, info.Sum, info.Dir, pin.Version, pin.Sum))
		}
		modules[pin.Path] = info
	}

	pinnedDir := filepath.Join(root, "third_party", "dnstap")
	checkHash(filepath.Join(pinnedDir, "dnstap.proto"), "078039018f8aa49d47de21139a81da576f109705b444fdb1c186e27a4282479f")
	checkHash(filepath.Join(pinnedDir, "LICENSE-APACHE-2.0.txt"), "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30")
	checkHash(filepath.Join(pinnedDir, "LICENSE-PROTOBUF-BSD-3-CLAUSE.txt"), "4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20")
	checkEqual(
		filepath.Join(pinnedDir, "dnstap.proto"),
		filepath.Join(modules["github.com/dnstap/golang-dnstap"].Dir, "dnstap.pb", "dnstap.proto"),
	)
	checkEqual(
		filepath.Join(pinnedDir, "LICENSE-APACHE-2.0.txt"),
		filepath.Join(modules["github.com/dnstap/golang-dnstap"].Dir, "LICENSE"),
	)
	checkEqual(
		filepath.Join(pinnedDir, "LICENSE-APACHE-2.0.txt"),
		filepath.Join(modules["github.com/farsightsec/golang-framestream"].Dir, "LICENSE"),
	)
	checkEqual(
		filepath.Join(pinnedDir, "LICENSE-PROTOBUF-BSD-3-CLAUSE.txt"),
		filepath.Join(modules["google.golang.org/protobuf"].Dir, "LICENSE"),
	)

	unboundDir := filepath.Join(root, "third_party", "unbound")
	checkHash(filepath.Join(unboundDir, "LICENSE-BSD-3-CLAUSE.txt"), "8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db")
	checkHash(filepath.Join(unboundDir, "LICENSE-EXPAT-MIT.txt"), "31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87")
	checkHash(filepath.Join(unboundDir, "LICENSE-LIBEVENT.txt"), "ff02effc9b331edcdac387d198691bfa3e575e7d244ad10cb826aa51ef085670")
	checkHash(filepath.Join(unboundDir, "LICENSE-OPENSSL-APACHE-2.0.txt"), "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a")
	checkHash(filepath.Join(unboundDir, "LICENSE-PROTOBUF-C-BSD-2-CLAUSE.txt"), "2d1d028bd27f8c85bc970d720519d2069ca6213fcb26b9dea444a7c39d24bbb3")
	checkHash(filepath.Join(unboundDir, "LICENSE-PROTOBUF-BSD-3-CLAUSE.txt"), "6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d")
	checkHash(filepath.Join(unboundDir, "patches", "0001-dnstap-deterministic-evidence.patch"), "a42affbccfa7ede0d86672258c8775a69bf02156b299bcc8d55bfc3a791557ae")
	fixtureDir := filepath.Join(root, "internal", "dnstapcollector", "testdata")
	fixturePath := filepath.Join(fixtureDir, "unbound-1.25.1-resolver-pair.fstrm.b64")
	checkHash(fixturePath, "433ac209b6debb835db91aea903ac26d5f43ef6d57e21959e0a3fe0e4c3feac5")
	checkHash(filepath.Join(fixtureDir, "unbound-1.25.1-resolver-pair.json"), "05fa6bb5a2009c756be24ea435788b400f7991378d7ed40570ebc9d9d142ad9b")
	checkBase64Hash(fixturePath, "1d5808f68adac8b66c2c0d51fc2bfbb29b40b62fbd5e47df1afd07db67da9dc2")

	command := exec.Command("go", "mod", "verify")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		fail(fmt.Errorf("go mod verify: %w: %s", err, bytes.TrimSpace(output)))
	}
	fmt.Println("dnstap supply-chain verification passed")
}

func checkBase64Hash(path, expected string) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		fail(fmt.Errorf("read %s: %w", path, err))
	}
	value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		fail(fmt.Errorf("decode base64 %s: %w", path, err))
	}
	digest := sha256.Sum256(value)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		fail(fmt.Errorf("decoded SHA-256 %s = %s, want %s", path, actual, expected))
	}
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil && !info.IsDir() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("go.mod was not found above the current directory")
		}
		directory = parent
	}
}

func loadModule(root, path string) (moduleInfo, error) {
	command := exec.Command("go", "list", "-m", "-json", path)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return moduleInfo{}, fmt.Errorf("load module %s: %w", path, err)
	}
	var info moduleInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return moduleInfo{}, fmt.Errorf("decode module %s metadata: %w", path, err)
	}
	return info, nil
}

func checkHash(path, expected string) {
	value, err := os.ReadFile(path)
	if err != nil {
		fail(fmt.Errorf("read %s: %w", path, err))
	}
	digest := sha256.Sum256(value)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		fail(fmt.Errorf("SHA-256 %s = %s, want %s", path, actual, expected))
	}
}

func checkEqual(pinnedPath, upstreamPath string) {
	pinned, err := os.ReadFile(pinnedPath)
	if err != nil {
		fail(fmt.Errorf("read %s: %w", pinnedPath, err))
	}
	upstream, err := os.ReadFile(upstreamPath)
	if err != nil {
		fail(fmt.Errorf("read %s: %w", upstreamPath, err))
	}
	if !bytes.Equal(pinned, upstream) {
		fail(fmt.Errorf("%s differs from pinned upstream %s", pinnedPath, upstreamPath))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
