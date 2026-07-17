package nodepingagentdeploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
		"user: \"0:0\"",
		"no-new-privileges:true",
		"cap_drop:\n      - ALL",
		"cap_add:\n      - NET_RAW",
		"read_only: true",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("compose.yml missing %q", required)
		}
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
