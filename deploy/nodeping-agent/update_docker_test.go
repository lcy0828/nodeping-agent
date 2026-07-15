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
