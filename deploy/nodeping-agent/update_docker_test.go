package nodepingagentdeploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestUpdateDockerFallsBackToAlternateImageSourceWithoutReplacingSelfUpdatedAgent(t *testing.T) {
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
			dataDirectory := filepath.Join(directory, "data")
			writeCompleteAgentIdentity(t, dataDirectory)
			runtimeDirectory := filepath.Join(directory, "runtime")
			if err := os.Mkdir(runtimeDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, filepath.Join(runtimeDirectory, "nodeping-agent"), "#!/bin/sh\necho 'nodeping-agent version=v1.2.3 commit=runtime'\n")
			if err := os.WriteFile(filepath.Join(runtimeDirectory, ".nodeping-agent-docker-runtime"), []byte("Managed by NodePing Docker installer\n"), 0o600); err != nil {
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
				"NODEPING_AGENT_IMAGE_VERSION=v9.9.9",
				"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
				"NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY=" + runtimeDirectory,
				"",
			}, "\n")
			if err := os.WriteFile(envPath, []byte(envFile), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(directory, "docker.log")
			statePath := filepath.Join(directory, "docker.state")
			if err := os.WriteFile(statePath, []byte("running\n"), 0o600); err != nil {
				t.Fatal(err)
			}
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
			if !strings.Contains(string(updatedEnv), "NODEPING_AGENT_IMAGE_VERSION=v9.9.9\n") {
				t.Fatalf("base image tag was not preserved independently of the active Agent version:\n%s", updatedEnv)
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
		"init: true",
		"user: \"0:0\"",
		"no-new-privileges:true",
		"cap_drop:\n      - ALL",
		"cap_add:\n      - NET_RAW",
		"read_only: true",
		"healthcheck:",
		"test: [CMD, /usr/local/lib/nodeping-agent/nodeping-agent, liveness]",
		"NODEPING_AGENT_UPGRADE_MODE: ${NODEPING_AGENT_UPGRADE_MODE:-container}",
		"NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE: ${NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE:-true}",
		"NODEPING_AGENT_UPGRADE_SCRIPT: /usr/local/bin/nodeping-agent-update",
		"NODEPING_AGENT_INSTALL_PATH: /opt/nodeping-agent/nodeping-agent",
		"NODEPING_AGENT_ACTIVATION_FILE: /var/lib/nodeping-agent/updates/activation.pending",
		"NODEPING_AGENT_ID_FILE: /var/lib/nodeping-agent/agent-id",
		"${NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY:-./runtime}:/opt/nodeping-agent",
		"${NODEPING_AGENT_DOCKER_DATA_DIRECTORY:-./data}:/var/lib/nodeping-agent",
		"/run/nodeping-agent:rw,noexec,nosuid,nodev,size=1m,mode=0700",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("compose.yml missing %q", required)
		}
	}
	for _, forbidden := range []string{"pids_limit:", "mem_limit:", "cpus:", "/var/run/docker.sock", "privileged:", "NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("compose.yml still contains runtime limit %q", forbidden)
		}
	}
}

func TestInstallDockerConfiguresInContainerUpgrade(t *testing.T) {
	installer, err := os.ReadFile("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	for _, required := range []string{
		"detect_supported_architecture",
		"x86_64|amd64",
		"aarch64|arm64",
		"Docker 镜像仅支持 amd64 和 arm64",
		"copy_file_with_mode",
		"validate_data_directory_ownership",
		"validate_runtime_directory_ownership",
		"refusing to take over an unmarked non-empty data directory",
		"refusing to take over an unmarked non-empty runtime directory",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=\"%s\"",
		"NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY=\"%s\"",
		"NODEPING_AGENT_UPGRADE_MODE=\"container\"",
		"NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE=\"true\"",
		"in-container Agent updater",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("install-docker.sh missing %q", required)
		}
	}
	if strings.Contains(text, "\ninstall -") {
		t.Fatal("install-docker.sh must not require the coreutils install command")
	}
	for _, forbidden := range []string{"detect_supported_init", "HOST_INIT=", "procd_set_param", "PathExists=", "watch-docker-update.sh\" \"$tmp_dir"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("install-docker.sh still configures a host watcher: %q", forbidden)
		}
	}
}

func TestDockerLifecycleScriptsValidateDirectoryLayout(t *testing.T) {
	for _, name := range []string{"install-docker.sh", "update-docker.sh", "uninstall-docker.sh"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if !strings.Contains(text, "validate_directory_layout()") || strings.Count(text, "validate_directory_layout") < 2 {
			t.Fatalf("%s does not define and invoke directory layout validation", name)
		}
		for _, required := range []string{
			"the Agent runtime directory must not equal or contain the project directory",
			"the Agent data and runtime directories must not overlap",
		} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s missing path validation %q", name, required)
			}
		}
	}
}

func TestInstallDockerRejectsOverlappingDirectoriesBeforeHostChanges(t *testing.T) {
	scriptPath, err := filepath.Abs("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		paths func(string) (string, string)
	}{
		{name: "runtime equals project", paths: func(project string) (string, string) { return filepath.Join(project, "data"), project }},
		{name: "runtime equals data", paths: func(project string) (string, string) {
			return filepath.Join(project, "state"), filepath.Join(project, "state")
		}},
		{name: "runtime contains data", paths: func(project string) (string, string) {
			return filepath.Join(project, "runtime", "data"), filepath.Join(project, "runtime")
		}},
		{name: "data contains runtime", paths: func(project string) (string, string) {
			return filepath.Join(project, "data"), filepath.Join(project, "data", "runtime")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			projectDirectory := filepath.Join(directory, "nodeping-agent")
			if err := os.Mkdir(projectDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			dataDirectory, runtimeDirectory := test.paths(projectDirectory)
			binDirectory := filepath.Join(directory, "bin")
			if err := os.Mkdir(binDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, filepath.Join(binDirectory, "id"), "#!/usr/bin/env bash\nprintf '0\\n'\n")
			dockerLog := filepath.Join(directory, "docker.log")
			writeExecutable(t, filepath.Join(binDirectory, "docker"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$MOCK_DOCKER_LOG\"\n")
			command := exec.Command("bash", scriptPath)
			command.Env = append(os.Environ(),
				"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
				"MOCK_DOCKER_LOG="+dockerLog,
				"NODEPING_SERVER_URL=https://nodeping.example",
				"NODEPING_TOKEN=np_test",
				"NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY="+projectDirectory,
				"NODEPING_AGENT_DOCKER_DATA_DIRECTORY="+dataDirectory,
				"NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY="+runtimeDirectory,
			)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("installer accepted overlapping paths:\n%s", output)
			}
			if !strings.Contains(string(output), "must not overlap") && !strings.Contains(string(output), "must not equal or contain the project directory") {
				t.Fatalf("installer returned the wrong path error:\n%s", output)
			}
			if _, err := os.Stat(dockerLog); !os.IsNotExist(err) {
				t.Fatalf("installer invoked Docker before rejecting paths: %v", err)
			}
		})
	}
}

func TestInstallDockerValidatesSignatureConfigurationBeforeHostChanges(t *testing.T) {
	scriptPath, err := filepath.Abs("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		mode      string
		publicKey string
		from      string
	}{
		{name: "invalid mode", mode: "sometimes"},
		{name: "control character", mode: "auto\nNODEPING_TOKEN=changed"},
		{name: "invalid public key", mode: "auto", publicKey: "RWinvalid"},
		{name: "invalid threshold", mode: "auto", from: "1.2"},
		{name: "required without key", mode: "required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			projectDirectory := filepath.Join(directory, "nodeping-agent")
			binDirectory := filepath.Join(directory, "bin")
			if err := os.MkdirAll(binDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, filepath.Join(binDirectory, "id"), "#!/usr/bin/env bash\nprintf '0\\n'\n")
			dockerLog := filepath.Join(directory, "docker.log")
			writeExecutable(t, filepath.Join(binDirectory, "docker"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$MOCK_DOCKER_LOG\"\n")
			command := exec.Command("bash", scriptPath)
			command.Env = append(os.Environ(),
				"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
				"MOCK_DOCKER_LOG="+dockerLog,
				"NODEPING_SERVER_URL=https://nodeping.example",
				"NODEPING_TOKEN=np_test",
				"NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY="+projectDirectory,
				"NODEPING_AGENT_REQUIRE_SIGNATURE="+test.mode,
				"NODEPING_AGENT_MINISIGN_PUBLIC_KEY="+test.publicKey,
				"NODEPING_AGENT_SIGNATURE_REQUIRED_FROM="+test.from,
			)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("installer accepted invalid signature configuration:\n%s", output)
			}
			if _, err := os.Stat(dockerLog); !os.IsNotExist(err) {
				t.Fatalf("installer invoked Docker before rejecting signature configuration: %v", err)
			}
		})
	}

	installer, err := os.ReadFile("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	for _, required := range []string{
		"REQUIRE_SIGNATURE=\"$(normalize_signature_mode \"$REQUIRE_SIGNATURE\")\"",
		"SIGNATURE_REQUIRED_FROM=\"$(normalize_release_version \"$SIGNATURE_REQUIRED_FROM\")\"",
		"validate_minisign_public_key \"$SIGNING_PUBLIC_KEY\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("install-docker.sh missing signature normalization %q", required)
		}
	}
}

func TestDevelopmentHTTPOptInIsWiredAcrossDeploymentScripts(t *testing.T) {
	for _, name := range []string{"install-release.sh", "install-docker.sh", "update-nodeping-agent.sh", "update-docker.sh"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, required := range []string{
			"NODEPING_AGENT_ALLOW_INSECURE_HTTP",
			"normalize_allow_insecure_http",
			"validate_secure_url \"$SERVER_URL\" \"NODEPING_SERVER_URL\" \"$ALLOW_INSECURE_HTTP\"",
		} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s missing %q", name, required)
			}
		}
	}

	for _, name := range []string{"install-release.sh", "install-docker.sh"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "printf 'NODEPING_AGENT_ALLOW_INSECURE_HTTP=\"%s\"\\n'") {
			t.Fatalf("%s does not persist the development HTTP opt-in", name)
		}
	}
}

func TestInstallDockerRejectsUnsupportedArchitectureBeforeHostChanges(t *testing.T) {
	scriptPath, err := filepath.Abs("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(binDirectory, "id"), "#!/usr/bin/env bash\n[ \"${1:-}\" = \"-u\" ] && printf '0\\n'\n")
	writeExecutable(t, filepath.Join(binDirectory, "uname"), "#!/usr/bin/env bash\n[ \"${1:-}\" = \"-m\" ] && printf 'mipsel\\n'\n")
	markerPath := filepath.Join(directory, "persistent-command-ran")
	for _, name := range []string{"docker", "mkdir", "cp", "chmod", "mv", "mktemp", "curl", "wget"} {
		writeExecutable(t, filepath.Join(binDirectory, name), "#!/usr/bin/env bash\nprintf '%s\\n' \"$0\" >> \"$MUTATION_MARKER\"\nexit 99\n")
	}
	command := exec.Command("bash", scriptPath)
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MUTATION_MARKER="+markerPath,
		"NODEPING_SERVER_URL=https://agent.example",
		"NODEPING_TOKEN=np_test",
		"NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY="+filepath.Join(directory, "project"),
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY="+filepath.Join(directory, "project", "data"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("installer unexpectedly accepted mipsel:\n%s", output)
	}
	if !strings.Contains(string(output), "Docker images support only amd64 and arm64") {
		t.Fatalf("missing architecture guidance:\n%s", output)
	}
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatalf("a download or persistent command ran before architecture rejection: %v", statErr)
	}
}

func TestInstallDockerCompatibilityChecksPrecedeTemporaryAndPersistentWork(t *testing.T) {
	installer, err := os.ReadFile("install-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	archCheck := strings.LastIndex(text, "detect_supported_architecture >/dev/null")
	temporaryWork := strings.Index(text, "tmp_dir=\"$(mktemp -d)\"")
	persistentWork := strings.Index(text, "ensure_private_directory \"$PROJECT_DIRECTORY\"")
	if archCheck < 0 || temporaryWork < 0 || persistentWork < 0 {
		t.Fatalf("installer is missing compatibility or work markers")
	}
	if archCheck >= temporaryWork || archCheck >= persistentWork {
		t.Fatalf("compatibility checks must run before mktemp, downloads, or persistent installation")
	}
}

func TestInstallReleaseRejectsUnsupportedSystemBeforeDownloadsOrWrites(t *testing.T) {
	installer, err := os.ReadFile("install-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	for _, required := range []string{
		"detect_os >/dev/null",
		"detect_arch >/dev/null",
		"[ ! -d /run/systemd/system ]",
		"systemctl list-unit-files",
		"nothing was downloaded or installed",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("install-release.sh missing early compatibility check %q", required)
		}
	}
	preflightCall := strings.Index(text, "\npreflight\n")
	allowInsecureNormalization := strings.Index(text, "ALLOW_INSECURE_HTTP=\"$(normalize_allow_insecure_http")
	temporaryWork := strings.Index(text, "tmp_dir=\"$(mktemp -d)\"")
	persistentWork := strings.Index(text, "install -d -m 0755 \"$ETC_DIR\"")
	if preflightCall < 0 || allowInsecureNormalization < 0 || temporaryWork < 0 || persistentWork < 0 {
		t.Fatal("install-release.sh is missing preflight or work markers")
	}
	if preflightCall >= allowInsecureNormalization || allowInsecureNormalization >= temporaryWork || preflightCall >= persistentWork {
		t.Fatal("systemd compatibility preflight must run before downloads and persistent writes")
	}
}

func TestUpdateDockerUsesBusyBoxCompatibleDirectorySetup(t *testing.T) {
	updater, err := os.ReadFile("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(updater)
	if !strings.Contains(text, "mkdir -p \"$DATA_DIRECTORY\"") || !strings.Contains(text, "chmod 0700 \"$DATA_DIRECTORY\"") {
		t.Fatal("update-docker.sh must prepare the data directory with BusyBox-compatible commands")
	}
	if !strings.Contains(text, "grep -Fqx \"Managed by NodePing Docker installer\" \"$marker\"") {
		t.Fatal("update-docker.sh must verify the runtime directory ownership marker")
	}
	if strings.Contains(text, "install -d -m 0700 \"$DATA_DIRECTORY\"") {
		t.Fatal("update-docker.sh must not require coreutils install")
	}
	if !strings.Contains(text, "mkdir \"$UPDATE_LOCK_DIRECTORY\"") || strings.Contains(text, "flock") {
		t.Fatal("update-docker.sh must use a BusyBox-compatible mkdir lock without flock")
	}
}

func TestUninstallDockerIsExplicitAndPreservesStateByDefault(t *testing.T) {
	uninstaller, err := os.ReadFile("uninstall-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(uninstaller)
	for _, required := range []string{
		"REMOVE_CONFIG=\"${REMOVE_CONFIG:-0}\"",
		"REMOVE_DATA=\"${REMOVE_DATA:-0}\"",
		"$PROJECT_DIRECTORY/nodeping-agent.env",
		"validate_managed_directory",
		".nodeping-agent-docker-data",
		"refusing to delete an unmarked NodePing data directory",
		"docker compose --env-file \"$ENV_FILE\" -f \"$COMPOSE_FILE\" down --remove-orphans",
		"nodeping-agent-docker-update.path",
		"/etc/init.d/nodeping-agent-docker-update",
		"Managed by NodePing Docker installer",
		"kept Docker configuration",
		"kept Agent data directory",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("uninstall-docker.sh missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"down --volumes",
		"down -v",
		"rm -rf \"$PROJECT_DIRECTORY\"",
		"/var/run/docker.sock",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("uninstall-docker.sh contains unsafe operation %q", forbidden)
		}
	}
}

func TestUninstallDockerStopsComposeAndKeepsConfigAndData(t *testing.T) {
	scriptPath, err := filepath.Abs("uninstall-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	projectDirectory := filepath.Join(directory, "nodeping-agent")
	dataDirectory := filepath.Join(projectDirectory, "data")
	controlDirectory := filepath.Join(projectDirectory, "control")
	binDirectory := filepath.Join(directory, "bin")
	for _, path := range []string{projectDirectory, dataDirectory, controlDirectory, binDirectory} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	envPath := filepath.Join(projectDirectory, ".env")
	composePath := filepath.Join(projectDirectory, "compose.yml")
	envContent := strings.Join([]string{
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY=" + controlDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, ".nodeping-agent-docker-data"), []byte("Managed by NodePing Docker installer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"update-docker.sh", "watch-docker-update.sh", "uninstall-docker.sh"} {
		writeExecutable(t, filepath.Join(projectDirectory, name), "#!/usr/bin/env bash\n")
	}
	logPath := filepath.Join(directory, "docker.log")
	writeExecutable(t, filepath.Join(binDirectory, "id"), "#!/usr/bin/env bash\n[ \"${1:-}\" = \"-u\" ] && printf '0\\n'\n")
	writeExecutable(t, filepath.Join(binDirectory, "docker"), `#!/usr/bin/env bash
set -eu
if [ "${1:-}" = "compose" ] && [ "${2:-}" = "version" ]; then
	exit 0
fi
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
`)
	writeExecutable(t, filepath.Join(binDirectory, "systemctl"), "#!/usr/bin/env bash\nexit 0\n")
	command := exec.Command("bash", scriptPath)
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MOCK_DOCKER_LOG="+logPath,
		"NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY="+projectDirectory,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("uninstall-docker.sh failed: %v\n%s", err, output)
	}
	for _, path := range []string{envPath, composePath, dataDirectory} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("default uninstall did not preserve %s: %v", path, err)
		}
	}
	for _, name := range []string{"update-docker.sh", "watch-docker-update.sh", "uninstall-docker.sh"} {
		if _, err := os.Stat(filepath.Join(projectDirectory, name)); !os.IsNotExist(err) {
			t.Fatalf("host helper %s was not removed: %v", name, err)
		}
	}
	dockerLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerLog), "down --remove-orphans") || strings.Contains(string(dockerLog), "--volumes") {
		t.Fatalf("unexpected compose teardown:\n%s", dockerLog)
	}
}

func TestDockerLifecycleScriptsParseWithBash(t *testing.T) {
	for _, script := range []string{"install-docker.sh", "update-docker.sh", "uninstall-docker.sh"} {
		command := exec.Command("bash", "-n", script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s does not parse: %v\n%s", script, err, output)
		}
	}
}

func TestContainerEntrypointRollsBackFailedCandidate(t *testing.T) {
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(runtimeDirectory, "nodeping-agent")
	backupPath := filepath.Join(runtimeDirectory, "nodeping-agent.previous")
	fallbackPath := filepath.Join(runtimeDirectory, "fallback")
	activationPath := filepath.Join(stateDirectory, "activation.pending")
	logPath := filepath.Join(directory, "supervisor.log")
	writeExecutable(t, activePath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v2.0.0'; exit 0; fi\necho candidate >> \"$SUPERVISOR_LOG\"\nexit 1\n")
	writeExecutable(t, backupPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v1.0.0'; exit 0; fi\necho previous >> \"$SUPERVISOR_LOG\"\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	writeExecutable(t, fallbackPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v0.9.0'; exit 0; fi\nexit 1\n")
	if err := os.WriteFile(activationPath, []byte("nodeping-agent/v2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("sh", "container-entrypoint.sh")
	command.Env = append(os.Environ(),
		"NODEPING_AGENT_INSTALL_PATH="+activePath,
		"NODEPING_AGENT_BACKUP_PATH="+backupPath,
		"NODEPING_AGENT_FALLBACK_PATH="+fallbackPath,
		"NODEPING_AGENT_ACTIVATION_FILE="+activationPath,
		"NODEPING_AGENT_ACTIVATION_STABLE_SECONDS=5",
		"SUPERVISOR_LOG="+logPath,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			_, _ = command.Process.Wait()
		}
	})
	waitForFileText(t, logPath, "previous", 5*time.Second)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("entrypoint did not stop cleanly: %v", err)
	}
	command.Process = nil
	if _, err := os.Stat(activationPath); !os.IsNotExist(err) {
		t.Fatalf("failed activation marker remains: %v", err)
	}
	output, err := exec.Command(activePath, "-version").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "v1.0.0") {
		t.Fatalf("active binary was not rolled back: %v %s", err, output)
	}
}

func TestContainerEntrypointPromotesLegacyDockerUpgradeMode(t *testing.T) {
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	fallbackPath := filepath.Join(runtimeDirectory, "fallback")
	upgradeScript := filepath.Join(runtimeDirectory, "update")
	activationPath := filepath.Join(stateDirectory, "activation.pending")
	logPath := filepath.Join(directory, "mode.log")
	writeExecutable(t, fallbackPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v0.1.0'; exit 0; fi\nprintf '%s\\n' \"${NODEPING_AGENT_UPGRADE_MODE:-}\" > \"$SUPERVISOR_LOG\"\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	writeExecutable(t, upgradeScript, "#!/bin/sh\nexit 0\n")

	command := exec.Command("sh", "container-entrypoint.sh")
	command.Env = append(os.Environ(),
		"NODEPING_INSTALL_MODE=docker",
		"NODEPING_AGENT_UPGRADE_MODE=request_file",
		"NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE=true",
		"NODEPING_AGENT_UPGRADE_SCRIPT="+upgradeScript,
		"NODEPING_AGENT_INSTALL_PATH="+filepath.Join(runtimeDirectory, "nodeping-agent"),
		"NODEPING_AGENT_BACKUP_PATH="+filepath.Join(runtimeDirectory, "nodeping-agent.previous"),
		"NODEPING_AGENT_FALLBACK_PATH="+fallbackPath,
		"NODEPING_AGENT_ACTIVATION_FILE="+activationPath,
		"NODEPING_AGENT_ACTIVATION_STABLE_SECONDS=5",
		"SUPERVISOR_LOG="+logPath,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			_, _ = command.Process.Wait()
		}
	})
	waitForFileText(t, logPath, "container", 5*time.Second)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("entrypoint did not stop cleanly: %v", err)
	}
	command.Process = nil
}

func TestContainerEntrypointDoesNotPromoteWithoutBridgeFlag(t *testing.T) {
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	fallbackPath := filepath.Join(runtimeDirectory, "fallback")
	upgradeScript := filepath.Join(runtimeDirectory, "update")
	activationPath := filepath.Join(stateDirectory, "activation.pending")
	logPath := filepath.Join(directory, "mode.log")
	writeExecutable(t, fallbackPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v0.1.0'; exit 0; fi\nprintf '%s\\n' \"${NODEPING_AGENT_UPGRADE_MODE:-}\" > \"$SUPERVISOR_LOG\"\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	writeExecutable(t, upgradeScript, "#!/bin/sh\nexit 0\n")

	command := exec.Command("sh", "container-entrypoint.sh")
	command.Env = append(os.Environ(),
		"NODEPING_INSTALL_MODE=docker",
		"NODEPING_AGENT_UPGRADE_MODE=request_file",
		"NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE=false",
		"NODEPING_AGENT_UPGRADE_SCRIPT="+upgradeScript,
		"NODEPING_AGENT_INSTALL_PATH="+filepath.Join(runtimeDirectory, "nodeping-agent"),
		"NODEPING_AGENT_BACKUP_PATH="+filepath.Join(runtimeDirectory, "nodeping-agent.previous"),
		"NODEPING_AGENT_FALLBACK_PATH="+fallbackPath,
		"NODEPING_AGENT_ACTIVATION_FILE="+activationPath,
		"NODEPING_AGENT_ACTIVATION_STABLE_SECONDS=5",
		"SUPERVISOR_LOG="+logPath,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			_, _ = command.Process.Wait()
		}
	})
	waitForFileText(t, logPath, "request_file", 5*time.Second)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("entrypoint did not stop cleanly: %v", err)
	}
	command.Process = nil
}

func TestContainerEntrypointRollsBackInvalidCandidateBeforeFallback(t *testing.T) {
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(runtimeDirectory, "nodeping-agent")
	backupPath := filepath.Join(runtimeDirectory, "nodeping-agent.previous")
	fallbackPath := filepath.Join(runtimeDirectory, "fallback")
	activationPath := filepath.Join(stateDirectory, "activation.pending")
	logPath := filepath.Join(directory, "supervisor.log")
	writeExecutable(t, activePath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then exit 1; fi\necho invalid >> \"$SUPERVISOR_LOG\"\nexit 1\n")
	writeExecutable(t, backupPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v1.0.0'; exit 0; fi\necho previous >> \"$SUPERVISOR_LOG\"\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	writeExecutable(t, fallbackPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v0.9.0'; exit 0; fi\necho fallback >> \"$SUPERVISOR_LOG\"\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	if err := os.WriteFile(activationPath, []byte("nodeping-agent/v2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("sh", "container-entrypoint.sh")
	command.Env = append(os.Environ(),
		"NODEPING_AGENT_INSTALL_PATH="+activePath,
		"NODEPING_AGENT_BACKUP_PATH="+backupPath,
		"NODEPING_AGENT_FALLBACK_PATH="+fallbackPath,
		"NODEPING_AGENT_ACTIVATION_FILE="+activationPath,
		"NODEPING_AGENT_ACTIVATION_STABLE_SECONDS=5",
		"SUPERVISOR_LOG="+logPath,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			_, _ = command.Process.Wait()
		}
	})
	waitForFileText(t, logPath, "previous", 5*time.Second)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("entrypoint did not stop cleanly: %v", err)
	}
	command.Process = nil
	if _, err := os.Stat(activationPath); !os.IsNotExist(err) {
		t.Fatalf("invalid activation marker remains: %v", err)
	}
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logContent), "fallback") || strings.Contains(string(logContent), "invalid") {
		t.Fatalf("entrypoint launched an invalid or fallback binary before rollback:\n%s", logContent)
	}
}

func TestContainerEntrypointConfirmsStableCandidate(t *testing.T) {
	directory := t.TempDir()
	runtimeDirectory := filepath.Join(directory, "runtime")
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(runtimeDirectory, "nodeping-agent")
	backupPath := filepath.Join(runtimeDirectory, "nodeping-agent.previous")
	fallbackPath := filepath.Join(runtimeDirectory, "fallback")
	activationPath := filepath.Join(stateDirectory, "activation.pending")
	writeExecutable(t, activePath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v2.0.0'; exit 0; fi\ntrap 'exit 0' TERM INT HUP\nwhile :; do sleep 1; done\n")
	writeExecutable(t, backupPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v1.0.0'; exit 0; fi\nexit 1\n")
	writeExecutable(t, fallbackPath, "#!/bin/sh\nif [ \"${1:-}\" = -version ]; then echo 'nodeping-agent version=v0.9.0'; exit 0; fi\nexit 1\n")
	if err := os.WriteFile(activationPath, []byte("nodeping-agent/v2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "container-entrypoint.sh")
	command.Env = append(os.Environ(),
		"NODEPING_AGENT_INSTALL_PATH="+activePath,
		"NODEPING_AGENT_BACKUP_PATH="+backupPath,
		"NODEPING_AGENT_FALLBACK_PATH="+fallbackPath,
		"NODEPING_AGENT_ACTIVATION_FILE="+activationPath,
		"NODEPING_AGENT_ACTIVATION_STABLE_SECONDS=1",
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFileRemoval(t, activationPath, 5*time.Second)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("entrypoint did not stop cleanly: %v", err)
	}
}

func waitForFileText(t *testing.T, path, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		content, _ := os.ReadFile(path)
		if strings.Contains(string(content), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not contain %q before timeout", path, want)
}

func waitForFileRemoval(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s was not removed before timeout", path)
}

func TestAgentReleaseArchiveIncludesDockerLifecycleHelpers(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-nodeping-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(buildScript)
	for _, name := range []string{"container-entrypoint.sh", "uninstall-docker.sh"} {
		if !strings.Contains(text, "cp \"$ROOT_DIR/deploy/nodeping-agent/"+name+"\"") {
			t.Fatalf("release build does not copy %s", name)
		}
		if !strings.Contains(text, "\"$package_dir/nodeping-agent/"+name+"\"") {
			t.Fatalf("release build does not mark %s executable", name)
		}
	}
	for _, name := range []string{
		"watch-docker-update.sh",
		"nodeping-agent-docker-update.env.example",
		"nodeping-agent-docker-update.service",
		"nodeping-agent-docker-update.timer",
	} {
		if strings.Contains(text, "cp \"$ROOT_DIR/deploy/nodeping-agent/"+name+"\"") {
			t.Fatalf("release build still copies obsolete host watcher file %s", name)
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
	for _, suffix := range []string{".processing", ".failed"} {
		if _, err := os.Stat(requestPath + suffix); !os.IsNotExist(err) {
			t.Fatalf("successful upgrade left request artifact %s: %v", suffix, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, ".nodeping-agent-update.lock")); !os.IsNotExist(err) {
		t.Fatalf("successful upgrade left update lock behind: %v", err)
	}
}

func TestUpdateDockerPreservesFailedRemoteUpgradeRequest(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	dataDirectory := filepath.Join(directory, "data")
	composePath := filepath.Join(directory, "compose.yml")
	envPath := filepath.Join(directory, ".env")
	requestPath := filepath.Join(directory, "update-request.json")
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	requestContent := []byte("{\"version\":\"../../invalid\"}\n")
	if err := os.WriteFile(requestPath, requestContent, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"NODEPING_AGENT_DOCKER_REQUEST_FILE="+requestPath,
		"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
	)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("update-docker.sh accepted an invalid request:\n%s", output)
	}
	if _, err := os.Stat(requestPath); !os.IsNotExist(err) {
		t.Fatalf("failed request was not claimed atomically: %v", err)
	}
	if _, err := os.Stat(requestPath + ".processing"); !os.IsNotExist(err) {
		t.Fatalf("processing request was not finalized: %v", err)
	}
	failedContent, err := os.ReadFile(requestPath + ".failed")
	if err != nil {
		t.Fatalf("failed request was not preserved: %v", err)
	}
	if string(failedContent) != string(requestContent) {
		t.Fatalf("failed request changed:\n%s", failedContent)
	}
}

func TestUpdateDockerLeavesRequestUntouchedWhenAnotherUpdateHoldsLock(t *testing.T) {
	scriptPath, err := filepath.Abs("update-docker.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "docker.log")
	writeExecutable(t, filepath.Join(binDirectory, "docker"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$MOCK_DOCKER_LOG\"\n")
	composePath := filepath.Join(directory, "compose.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  nodeping-agent:\n    image: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDirectory := filepath.Join(directory, "data")
	envPath := filepath.Join(directory, ".env")
	envContent := strings.Join([]string{
		"NODEPING_AGENT_DISTRIBUTION_MODE=global",
		"NODEPING_AGENT_DOCKER_IMAGE_CN=cn.example/nodeping-agent",
		"NODEPING_AGENT_DOCKER_IMAGE_GLOBAL=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE=global.example/nodeping-agent",
		"NODEPING_AGENT_IMAGE_VERSION=latest",
		"NODEPING_AGENT_DOCKER_DATA_DIRECTORY=" + dataDirectory,
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(directory, "update-request.json")
	requestContent := []byte("{\"version\":\"1.2.3\"}\n")
	if err := os.WriteFile(requestPath, requestContent, 0o600); err != nil {
		t.Fatal(err)
	}
	lockDirectory := filepath.Join(directory, ".nodeping-agent-update.lock")
	if err := os.Mkdir(lockDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockDirectory, "pid"), []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("bash", scriptPath)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ENV_FILE="+envPath,
		"PROJECT_DIRECTORY="+directory,
		"COMPOSE_FILE="+composePath,
		"NODEPING_AGENT_DOCKER_REQUEST_FILE="+requestPath,
		"NODEPING_AGENT_DOCKER_UPDATE_LOCK_DIRECTORY="+lockDirectory,
		"NODEPING_AGENT_DOCKER_LOCK_WAIT_SECONDS=0",
		"NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT=0",
		"MOCK_DOCKER_LOG="+logPath,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("update unexpectedly ignored the held lock:\n%s", output)
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 75 {
		t.Fatalf("lock conflict exit = %v, want 75; output:\n%s", err, output)
	}
	if !strings.Contains(string(output), "upgrade request was left untouched") {
		t.Fatalf("missing lock conflict guidance:\n%s", output)
	}
	unchangedRequest, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchangedRequest) != string(requestContent) {
		t.Fatalf("request changed while lock was held:\n%s", unchangedRequest)
	}
	for _, suffix := range []string{".processing", ".failed"} {
		if _, err := os.Stat(requestPath + suffix); !os.IsNotExist(err) {
			t.Fatalf("lock conflict created request artifact %s: %v", suffix, err)
		}
	}
	unchangedEnv, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchangedEnv) != envContent {
		t.Fatalf("env changed while lock was held:\n%s", unchangedEnv)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("Docker was invoked while lock was held: %v", err)
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

func TestUpdateDockerMigratesLegacyIdentityAndOnlyCleansManagedProjectDuplicates(t *testing.T) {
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
other_project_full='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
other_project_short='dddddddddddd'
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
				printf '%s\n%s\n%s\n%s\n' "$current_short" "$duplicate_same_short" "$duplicate_other_short" "$other_project_short"
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
				"$other_project_short"|"$other_project_full") printf '%s\n' "$other_project_full" ;;
			esac
			;;
		*"com.docker.compose.project"*)
			case "$container" in
				"$other_project_short"|"$other_project_full") printf 'another-agent\n' ;;
				*) printf 'nodeping-agent\n' ;;
			esac
			;;
		*"com.docker.compose.service"*) printf 'nodeping-agent\n' ;;
		*"State.Running"*) printf 'true none\n' ;;
		*".Config.Image"*) printf 'global.example/nodeping-agent:v1.2.3\n' ;;
		*".Config.Env"*)
			case "$container" in
				legacy-container) printf 'NODEPING_SERVER_URL=https://agent.example\n' ;;
				"$duplicate_same_full") printf 'NODEPING_SERVER_URL=https://agent.example/\n' ;;
				"$duplicate_other_full") printf 'NODEPING_SERVER_URL=https://other.example\n' ;;
				"$other_project_full") printf 'NODEPING_SERVER_URL=https://agent.example\n' ;;
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
	if strings.Contains(logText, "rm -f dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd") {
		t.Fatalf("same-backend container from another Compose project was removed:\n%s", logText)
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
