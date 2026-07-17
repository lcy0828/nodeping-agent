package nodepingagentdeploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func installMockChown(t *testing.T, binDirectory string) {
	t.Helper()
	writeExecutable(t, filepath.Join(binDirectory, "chown"), "#!/usr/bin/env bash\nexit 0\n")
}

func writeCompleteAgentIdentity(t *testing.T, dataDirectory string) {
	t.Helper()
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"agent-id":    "agent-test\n",
		"agent-token": "token-test\n",
	} {
		if err := os.WriteFile(filepath.Join(dataDirectory, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpdateDockerFallsBackToAlternateImageSource(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		mode          string
		primaryImage  string
		fallbackImage string
	}{
		{name: "cn falls back to global", mode: "cn", primaryImage: "cn.example/nodeping-agent", fallbackImage: "global.example/nodeping-agent"},
		{name: "global falls back to cn", mode: "global", primaryImage: "global.example/nodeping-agent", fallbackImage: "cn.example/nodeping-agent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			binDirectory := filepath.Join(directory, "bin")
			if err := os.Mkdir(binDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			installMockChown(t, binDirectory)
			mockDocker := `#!/usr/bin/env bash
set -eu
if [ "${1:-}" = "compose" ]; then
	case " $* " in
		*" pull "*)
			printf 'pull:%s\n' "${NODEPING_AGENT_IMAGE:-}" >> "$MOCK_DOCKER_LOG"
			[ "${NODEPING_AGENT_IMAGE:-}" != "$MOCK_FAIL_IMAGE" ]
			exit
			;;
		*" ps -q "*)
			if [ -f "$MOCK_DOCKER_STATE" ]; then printf 'container-test\n'; fi
			exit
			;;
		*" up "*)
			touch "$MOCK_DOCKER_STATE"
			exit
			;;
		*" ps "*)
			printf 'nodeping-agent running\n'
			exit
			;;
	esac
fi
if [ "${1:-}" = "exec" ]; then
	case " $* " in
		*" -version "*) printf 'nodeping-agent version=v1.2.3 commit=test\n' ;;
	esac
	exit
fi
if [ "${1:-}" = "inspect" ]; then
	case " $* " in
		*"State.Running"*) printf 'true none\n' ;;
		*) printf 'sha256:test\n' ;;
	esac
	exit
fi
exit 0
`
			mockPath := filepath.Join(binDirectory, "docker")
			if err := os.WriteFile(mockPath, []byte(mockDocker), 0o755); err != nil {
				t.Fatal(err)
			}
			composePath := filepath.Join(directory, "compose.yml")
			if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: ${NODEPING_AGENT_IMAGE}:${NODEPING_AGENT_IMAGE_VERSION}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			envPath := filepath.Join(directory, ".env")
			envFile := strings.Join([]string{
				"NODEPING_AGENT_DISTRIBUTION_MODE=" + test.mode,
				"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
				"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
				"NODEPING_AGENT_IMAGE=" + test.primaryImage,
				"NODEPING_AGENT_IMAGE_VERSION=v1.2.3",
				"",
			}, "\n")
			if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(directory, "docker.log")
			statePath := filepath.Join(directory, "docker.state")
			command := exec.Command("bash", scriptPath)
			command.Dir = directory
			command.Env = append(os.Environ(),
				"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
				"ENV_FILE="+envPath,
				"PROJECT_DIRECTORY="+directory,
				"COMPOSE_FILE="+composePath,
				"MOCK_DOCKER_LOG="+logPath,
				"MOCK_DOCKER_STATE="+statePath,
				"MOCK_FAIL_IMAGE="+test.primaryImage,
				"NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS=5",
				"NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS=1",
				"NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS=5",
				"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("update-docker.sh failed: %v\n%s", err, output)
			}
			pulls, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			wantPulls := "pull:" + test.primaryImage + "\npull:" + test.fallbackImage + "\n"
			if string(pulls) != wantPulls {
				t.Fatalf("pull order = %q, want %q", pulls, wantPulls)
			}
			updatedEnv, err := os.ReadFile(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(updatedEnv), "NODEPING_AGENT_IMAGE="+test.fallbackImage+"\n") {
				t.Fatalf("fallback image was not persisted:\n%s", updatedEnv)
			}
		})
	}
}

func TestComposeUsesRestrictedRootForRawSockets(t *testing.T) {
	compose, err := os.ReadFile("compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	for _, required := range []string{
		"name: nodeping-agent",
		"container_name: nodeping-agent",
		"user: \"0:0\"",
		"no-new-privileges:true",
		"cap_drop:\n      - ALL",
		"cap_add:\n      - NET_RAW",
		"read_only: true",
		"NODEPING_AGENT_UPGRADE_MODE: ${NODEPING_AGENT_UPGRADE_MODE:-disabled}",
		"NODEPING_AGENT_UPGRADE_REQUEST_FILE: ${NODEPING_AGENT_UPGRADE_REQUEST_FILE:-/run/nodeping-agent/update-request.json}",
		"NODEPING_AGENT_ID_FILE: /var/lib/nodeping-agent/agent-id",
		"${NODEPING_AGENT_DOCKER_DATA_DIRECTORY:-./data}:/var/lib/nodeping-agent",
		"${NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY:-./control}:/run/nodeping-agent",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("compose.yml missing %q", required)
		}
	}
}

func TestInstallDockerConfiguresHostUpgradeWatcher(t *testing.T) {
	installer, err := os.ReadFile("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	for _, required := range []string{
		"REMOTE_UPGRADE_MODE=request_file",
		"nodeping-agent-docker-update.path",
		"NODEPING_AGENT_DOCKER_REQUEST_FILE=$CONTROL_DIRECTORY/update-request.json",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=\"%s\"",
		"NODEPING_AGENT_UPGRADE_MODE=\"%s\"",
		"NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY=\"%s\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("install-docker.sh missing %q", required)
		}
	}
}

func TestUpdateDockerConsumesRemoteUpgradeRequest(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	installMockChown(t, binDirectory)
	dataDirectory := filepath.Join(directory, "data")
	writeCompleteAgentIdentity(t, dataDirectory)
	composePath := filepath.Join(directory, "compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: ${NODEPING_AGENT_IMAGE}:${NODEPING_AGENT_IMAGE_VERSION}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(directory, ".env")
	envFile := strings.Join([]string{
		"NODEPING_AGENT_DISTRIBUTION_MODE=global",
		"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE_VERSION=latest",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(directory, "update-request.json")
	if err := os.WriteFile(requestPath, []byte("{\"version\":\"0.0.27\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "version.state")
	if err := os.WriteFile(statePath, []byte("v0.0.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mockDocker := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [ "${1:-}" = "compose" ]; then
	case " $* " in
		*" ps -q "*) printf 'container-test\n' ;;
		*" up "*) sed -n 's/^NODEPING_AGENT_IMAGE_VERSION=//p' "$MOCK_ENV_FILE" | tail -n 1 > "$MOCK_VERSION_STATE" ;;
		*" ps "*) printf 'nodeping-agent running\n' ;;
	esac
	exit 0
fi
if [ "${1:-}" = "exec" ]; then
	case " $* " in
		*" -version "*) printf 'nodeping-agent version=%s commit=test\n' "$(cat "$MOCK_VERSION_STATE")" ;;
	esac
	exit 0
fi
if [ "${1:-}" = "inspect" ]; then
	case " $* " in
		*"State.Running"*) printf 'true none\n' ;;
		*".Config.Image"*) printf 'global.example/nodeping-agent:v0.0.26\n' ;;
		*) printf 'sha256:test\n' ;;
	esac
	exit 0
fi
exit 0
`
	mockPath := filepath.Join(binDirectory, "docker")
	if err := os.WriteFile(mockPath, []byte(mockDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "docker.log")
	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"NODEPING_AGENT_DOCKER_REQUEST_FILE="+requestPath,
		"MOCK_DOCKER_LOG="+logPath,
		"MOCK_ENV_FILE="+envPath,
		"MOCK_VERSION_STATE="+statePath,
		"NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS=1",
		"NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("update-docker.sh failed: %v\n%s", err, output)
	}
	updatedEnv, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updatedEnv), "NODEPING_AGENT_IMAGE_VERSION=v0.0.27\n") {
		t.Fatalf("requested image version was not persisted:\n%s", updatedEnv)
	}
	if _, err := os.Stat(requestPath); !os.IsNotExist(err) {
		t.Fatalf("upgrade request was not consumed: %v", err)
	}
}

func TestUpdateDockerSyncsDefaultComposeBeforeRecreate(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	installMockChown(t, binDirectory)
	dataDirectory := filepath.Join(directory, "data")
	writeCompleteAgentIdentity(t, dataDirectory)
	oldCompose := "services:\n  nodeping-agent:\n    image: ${NODEPING_AGENT_IMAGE}:${NODEPING_AGENT_IMAGE_VERSION}\n"
	newCompose := "services:\n  nodeping-agent:\n    image: ${NODEPING_AGENT_IMAGE}:${NODEPING_AGENT_IMAGE_VERSION}\n    user: \"0:0\"\n"
	composePath := filepath.Join(directory, "compose.yml")
	composeSource := filepath.Join(directory, "compose.source.yml")
	if err := os.WriteFile(composePath, []byte(oldCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composeSource, []byte(newCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(directory, ".env")
	envFile := strings.Join([]string{
		"NODEPING_AGENT_DISTRIBUTION_MODE=global",
		"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE_VERSION=v1.2.3",
		"NODEPING_AGENT_DEPLOY_BASE_URL=https://deploy.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}
	mockDocker := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [ "${1:-}" = "compose" ]; then
	case " $* " in
		*" ps -q "*) printf 'container-test\n' ;;
		*" ps "*) printf 'nodeping-agent running\n' ;;
	esac
	exit 0
fi
if [ "${1:-}" = "exec" ]; then
	case " $* " in
		*" -version "*) printf 'nodeping-agent version=v1.2.3 commit=test\n' ;;
	esac
	exit 0
fi
if [ "${1:-}" = "inspect" ]; then
	case " $* " in
		*"State.Running"*) printf 'true none\n' ;;
		*".Config.Image"*) printf 'global.example/nodeping-agent:v1.2.3\n' ;;
		*) printf 'sha256:test\n' ;;
	esac
	exit 0
fi
exit 0
`
	mockCurl := `#!/usr/bin/env bash
set -eu
destination=''
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-o" ]; then
		shift
		destination="$1"
	fi
	shift
done
[ -n "$destination" ]
cp "$MOCK_COMPOSE_SOURCE" "$destination"
`
	for name, content := range map[string]string{"docker": mockDocker, "curl": mockCurl} {
		if err := os.WriteFile(filepath.Join(binDirectory, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(directory, "docker.log")
	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"MOCK_DOCKER_LOG="+logPath,
		"MOCK_COMPOSE_SOURCE="+composeSource,
		"NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS=1",
		"NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS=5",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("update-docker.sh failed: %v\n%s", err, output)
	}
	updatedCompose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(updatedCompose) != newCompose {
		t.Fatalf("compose was not synchronized:\n%s", updatedCompose)
	}
	dockerLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerLog), "config --quiet") || !strings.Contains(string(dockerLog), "up -d nodeping-agent") {
		t.Fatalf("expected Compose validation and recreate, log:\n%s", dockerLog)
	}
}

func TestUpdateDockerMigratesLegacyIdentityAndCleansSameBackendDuplicatesWithCanonicalIDs(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	installMockChown(t, binDirectory)

	dataDirectory := filepath.Join(directory, "data")
	legacyStateDirectory := filepath.Join(directory, "legacy-state")
	if err := os.Mkdir(legacyStateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyFiles := map[string]string{
		"agent-id":            "agent-legacy\n",
		"agent-token":         "token-legacy\n",
		"release-proxies.tsv": "https://proxy.example/\n",
		"latest-version":      "v0.0.28\n",
	}
	for name, value := range legacyFiles {
		if err := os.WriteFile(filepath.Join(legacyStateDirectory, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	composePath := filepath.Join(directory, "compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: ${NODEPING_AGENT_IMAGE}:${NODEPING_AGENT_IMAGE_VERSION}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(directory, ".env")
	envFile := strings.Join([]string{
		"NODEPING_SERVER_URL=https://agent.example",
		"NODEPING_AGENT_DISTRIBUTION_MODE=global",
		"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE_VERSION=v1.2.3",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}

	mockDocker := `#!/usr/bin/env bash
set -eu
current_full='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
current_short='aaaaaaaaaaaa'
duplicate_same_full='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
duplicate_same_short='bbbbbbbbbbbb'
duplicate_other_full='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
duplicate_other_short='cccccccccccc'
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [ "${1:-}" = "compose" ]; then
	case " $* " in
		*" ps -q "*)
			if [ -f "$MOCK_CURRENT_STATE" ]; then printf '%s\n' "$current_full"; fi
			;;
		*" up "*) touch "$MOCK_CURRENT_STATE" ;;
		*" ps "*) printf 'nodeping-agent running\n' ;;
	esac
	exit 0
fi
if [ "${1:-}" = "ps" ]; then
	case " $* " in
		*" -aq "*)
			if [ -f "$MOCK_CURRENT_STATE" ]; then
				printf '%s\n%s\n%s\n' "$current_short" "$duplicate_same_short" "$duplicate_other_short"
			else
				printf 'legacy-container\n'
			fi
			;;
	esac
	exit 0
fi
if [ "${1:-}" = "cp" ]; then
	filename="${2##*/}"
	cp "$MOCK_LEGACY_STATE/$filename" "$3"
	exit 0
fi
if [ "${1:-}" = "exec" ]; then
	case " $* " in
		*" -version "*) printf 'nodeping-agent version=v1.2.3 commit=test\n' ;;
	esac
	exit 0
fi
if [ "${1:-}" = "inspect" ]; then
	container="${*: -1}"
	case " $* " in
		*".Mounts"*) printf 'volume|/var/lib/docker/volumes/legacy/_data\n' ;;
		*"{{.Id}}"*)
			case "$container" in
				"$current_short"|"$current_full") printf '%s\n' "$current_full" ;;
				"$duplicate_same_short"|"$duplicate_same_full") printf '%s\n' "$duplicate_same_full" ;;
				"$duplicate_other_short"|"$duplicate_other_full") printf '%s\n' "$duplicate_other_full" ;;
			esac
			;;
		*"State.Running"*) printf 'true none\n' ;;
		*".Config.Image"*) printf 'global.example/nodeping-agent:v1.2.3\n' ;;
		*".Config.Env"*)
			case "$container" in
				legacy-container) printf 'NODEPING_SERVER_URL=https://agent.example\n' ;;
				"$duplicate_same_full") printf 'NODEPING_SERVER_URL=https://agent.example/\n' ;;
				"$duplicate_other_full") printf 'NODEPING_SERVER_URL=https://other.example\n' ;;
			esac
			;;
		*) printf 'sha256:test\n' ;;
	esac
	exit 0
fi
exit 0
`
	writeExecutable(t, filepath.Join(binDirectory, "docker"), mockDocker)

	logPath := filepath.Join(directory, "docker.log")
	currentStatePath := filepath.Join(directory, "current.state")
	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"MOCK_DOCKER_LOG="+logPath,
		"MOCK_CURRENT_STATE="+currentStatePath,
		"MOCK_LEGACY_STATE="+legacyStateDirectory,
		"NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS=1",
		"NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("update-docker.sh failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "migrated legacy Docker volume state") {
		t.Fatalf("migration was not reported:\n%s", output)
	}
	for name, want := range legacyFiles {
		content, err := os.ReadFile(filepath.Join(dataDirectory, name))
		if err != nil {
			t.Fatalf("read migrated %s: %v", name, err)
		}
		if string(content) != want {
			t.Fatalf("migrated %s = %q, want %q", name, content, want)
		}
		info, err := os.Stat(filepath.Join(dataDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("migrated %s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
	dockerLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(dockerLog)
	if !strings.Contains(logText, "rm -f bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("same-backend duplicate was not removed:\n%s", logText)
	}
	if strings.Contains(logText, "rm -f aaaaaaaaaaaa") || strings.Contains(logText, "rm -f aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("current container was removed because its full ID did not match Docker's short ID:\n%s", logText)
	}
	if strings.Contains(logText, "rm -f cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") {
		t.Fatalf("different-backend container was removed:\n%s", logText)
	}
}

func TestUpdateDockerStopsWhenLegacyIdentityIsIncomplete(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	installMockChown(t, binDirectory)
	legacyStateDirectory := filepath.Join(directory, "legacy-state")
	if err := os.Mkdir(legacyStateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyStateDirectory, "agent-id"), []byte("agent-legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDirectory := filepath.Join(directory, "data")
	composePath := filepath.Join(directory, "compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(directory, ".env")
	envFile := strings.Join([]string{
		"NODEPING_AGENT_DISTRIBUTION_MODE=global",
		"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE_VERSION=v1.2.3",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}
	mockDocker := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [ "${1:-}" = "compose" ]; then
	case " $* " in *" ps -q "*) printf 'legacy-container\n' ;; esac
	exit 0
fi
if [ "${1:-}" = "inspect" ]; then
	case " $* " in *".Mounts"*) printf 'volume|/var/lib/docker/volumes/legacy/_data\n' ;; esac
	exit 0
fi
if [ "${1:-}" = "cp" ]; then
	filename="${2##*/}"
	[ -f "$MOCK_LEGACY_STATE/$filename" ] || exit 1
	cp "$MOCK_LEGACY_STATE/$filename" "$3"
	exit 0
fi
exit 0
`
	writeExecutable(t, filepath.Join(binDirectory, "docker"), mockDocker)
	logPath := filepath.Join(directory, "docker.log")
	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"MOCK_DOCKER_LOG="+logPath,
		"MOCK_LEGACY_STATE="+legacyStateDirectory,
		"NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS=1",
		"NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS=5",
		"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("update unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "update stopped to avoid creating a duplicate node") {
		t.Fatalf("missing fail-closed error:\n%s", output)
	}
	dockerLog, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(dockerLog), " pull ") || strings.Contains(string(dockerLog), " up ") {
		t.Fatalf("container update started despite incomplete identity:\n%s", dockerLog)
	}
}
