#!/usr/bin/env bash
set -euo pipefail

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

if [ "$(id -u)" -ne 0 ]; then
	say_err "请以 root 运行 Docker 安装器" "run the Docker installer as root"
	exit 1
fi

SERVER_URL="${NODEPING_SERVER_URL:-}"
BINDING_TOKEN="${NODEPING_TOKEN:-}"
ALLOW_INSECURE_HTTP="${NODEPING_AGENT_ALLOW_INSECURE_HTTP:-false}"
DISTRIBUTION_MODE="${NODEPING_AGENT_DISTRIBUTION_MODE:-cn}"
DEPLOY_BASE_URL="${NODEPING_AGENT_DEPLOY_BASE_URL:-https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent}"
DOCKER_IMAGE_CN="${NODEPING_AGENT_DOCKER_IMAGE_CN:-hub.ilatency.com/ghcr.io/lcy0828/nodeping-agent}"
DOCKER_IMAGE_GLOBAL="${NODEPING_AGENT_DOCKER_IMAGE_GLOBAL:-ghcr.io/lcy0828/nodeping-agent}"
IMAGE_VERSION="${NODEPING_AGENT_IMAGE_VERSION:-latest}"
PROJECT_DIRECTORY="${NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY:-/opt/nodeping-agent}"
DATA_DIRECTORY="${NODEPING_AGENT_DOCKER_DATA_DIRECTORY:-$PROJECT_DIRECTORY/data}"
RUNTIME_DIRECTORY="${NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY:-$PROJECT_DIRECTORY/runtime}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
AGENT_NAME="${NODEPING_AGENT_NAME:-NodePing Docker Agent}"
SIGNING_PUBLIC_KEY="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
REQUIRE_SIGNATURE="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
SIGNATURE_REQUIRED_FROM="${NODEPING_AGENT_SIGNATURE_REQUIRED_FROM:-}"
LEGACY_CONTROL_DIRECTORY="$PROJECT_DIRECTORY/control"
MANAGED_MARKER="Managed by NodePing Docker installer"

is_loopback_http_url() {
	local value="$1"
	[[ "$value" =~ ^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

validate_secure_url() {
	local value="$1" name="$2" allow_insecure_http="${3:-false}"
	if [[ "$value" =~ [[:space:]@] ]]; then
		say_err "$name 不是安全的 URL" "$name is not a safe URL"
		return 1
	fi
	if [[ "$value" == https://* ]] || is_loopback_http_url "$value"; then return 0; fi
	if [ "$allow_insecure_http" = "true" ] && [[ "$value" == http://* ]]; then return 0; fi
	say_err "$name 必须使用 HTTPS（开发环境 HTTP 需显式设置 NODEPING_AGENT_ALLOW_INSECURE_HTTP=true）" "$name must use HTTPS (development HTTP requires NODEPING_AGENT_ALLOW_INSECURE_HTTP=true)"
	return 1
}

normalize_allow_insecure_http() {
	local value
	value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	case "$value" in
		1|true) printf 'true' ;;
		0|false|'') printf 'false' ;;
		*) say_err "NODEPING_AGENT_ALLOW_INSECURE_HTTP 必须为 true/false 或 1/0" "NODEPING_AGENT_ALLOW_INSECURE_HTTP must be true/false or 1/0"; return 1 ;;
	esac
}

normalize_signature_mode() {
	case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
		1|true|yes|on|required) printf 'required' ;;
		auto|'') printf 'auto' ;;
		0|false|no|off|disabled) printf 'disabled' ;;
		*) return 1 ;;
	esac
}

normalize_release_version() {
	local value="${1#nodeping-agent/}"
	case "$value" in
		v*) printf '%s' "$value" ;;
		[0-9]*) printf 'v%s' "$value" ;;
		*) printf '%s' "$value" ;;
	esac
}

valid_release_version() {
	local value="${1#v}"
	local without_build prerelease="" build="" identifier
	local -a identifiers
	[[ "$value" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || return 1
	without_build="$value"
	if [[ "$without_build" == *+* ]]; then
		build="${without_build#*+}"
		without_build="${without_build%%+*}"
		case "$build" in ''|.*|*.|*..*) return 1 ;; esac
	fi
	if [[ "$without_build" == *-* ]]; then
		prerelease="${without_build#*-}"
		case "$prerelease" in ''|.*|*.|*..*) return 1 ;; esac
		IFS=. read -r -a identifiers <<< "$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ "$identifier" =~ ^[0-9]+$ ]] && [[ "$identifier" == 0* ]] && [ "$identifier" != "0" ]; then
				return 1
			fi
		done
	fi
}

validate_env_value() {
	local name="$1" value="$2"
	if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
		say_err "$name 包含不允许的控制字符" "$name contains disallowed control characters"
		return 1
	fi
}

validate_image() {
	local name="$1" value="$2"
	if [ -z "$value" ] || [[ "$value" =~ [[:space:]@] ]] || [[ "$value" == -* ]] || [[ ! "$value" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
		say_err "$name 不是有效的容器镜像名称" "$name is not a valid container image name"
		return 1
	fi
}

validate_minisign_public_key() {
	local value="$1"
	[ -z "$value" ] && return 0
	if [[ ! "$value" =~ ^RW[A-Za-z0-9+/]{54}$ ]]; then
		say_err "NODEPING_AGENT_MINISIGN_PUBLIC_KEY 不是有效的 minisign 公钥" "NODEPING_AGENT_MINISIGN_PUBLIC_KEY is not a valid minisign public key"
		return 1
	fi
}

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		return 1
	fi
}

ensure_private_directory() {
	local path="$1"
	mkdir -p "$path"
	chmod 0700 "$path"
}

copy_file_with_mode() {
	local source="$1" target="$2" mode="$3" target_directory temporary
	target_directory="${target%/*}"
	temporary="$(mktemp "$target_directory/.nodeping-install.XXXXXX")"
	if ! cp "$source" "$temporary"; then
		rm -f "$temporary"
		return 1
	fi
	if ! chmod "$mode" "$temporary" || ! mv -f "$temporary" "$target"; then
		rm -f "$temporary"
		return 1
	fi
}

validate_data_directory_ownership() {
	local marker="$DATA_DIRECTORY/.nodeping-agent-docker-data" existing
	if [ ! -e "$DATA_DIRECTORY" ]; then
		return 0
	fi
	if [ ! -d "$DATA_DIRECTORY" ] || [ -L "$DATA_DIRECTORY" ]; then
		say_err "Agent 数据目录必须是普通目录：$DATA_DIRECTORY" "Agent data directory must be a regular directory: $DATA_DIRECTORY"
		return 1
	fi
	if [ -f "$marker" ] && [ ! -L "$marker" ] && grep -Fqx "$MANAGED_MARKER" "$marker"; then
		return 0
	fi
	for existing in "$DATA_DIRECTORY"/* "$DATA_DIRECTORY"/.[!.]* "$DATA_DIRECTORY"/..?*; do
		if [ -e "$existing" ] || [ -L "$existing" ]; then
			say_err "拒绝接管未标记的非空数据目录：$DATA_DIRECTORY；当前系统不会进行任何安装" "refusing to take over an unmarked non-empty data directory: $DATA_DIRECTORY; nothing was installed"
			return 1
		fi
	done
}

validate_runtime_directory_ownership() {
	local marker="$RUNTIME_DIRECTORY/.nodeping-agent-docker-runtime" existing
	if [ ! -e "$RUNTIME_DIRECTORY" ]; then
		return 0
	fi
	if [ ! -d "$RUNTIME_DIRECTORY" ] || [ -L "$RUNTIME_DIRECTORY" ]; then
		say_err "Agent 运行目录必须是普通目录：$RUNTIME_DIRECTORY" "Agent runtime directory must be a regular directory: $RUNTIME_DIRECTORY"
		return 1
	fi
	if [ -f "$marker" ] && [ ! -L "$marker" ] && grep -Fqx "$MANAGED_MARKER" "$marker"; then
		return 0
	fi
	for existing in "$RUNTIME_DIRECTORY"/* "$RUNTIME_DIRECTORY"/.[!.]* "$RUNTIME_DIRECTORY"/..?*; do
		if [ -e "$existing" ] || [ -L "$existing" ]; then
			say_err "拒绝接管未标记的非空运行目录：$RUNTIME_DIRECTORY；当前系统不会进行任何安装" "refusing to take over an unmarked non-empty runtime directory: $RUNTIME_DIRECTORY; nothing was installed"
			return 1
		fi
	done
}

remove_legacy_host_upgrade_watcher() {
	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		for unit in nodeping-agent-docker-update.path nodeping-agent-docker-update.timer nodeping-agent-docker-update.service; do
			systemctl disable --now "$unit" >/dev/null 2>&1 || true
		done
		for unit_file in \
			/etc/systemd/system/nodeping-agent-docker-update.path \
			/etc/systemd/system/nodeping-agent-docker-update.timer \
			/etc/systemd/system/nodeping-agent-docker-update.service; do
			if [ -f "$unit_file" ] && grep -Fq "$MANAGED_MARKER" "$unit_file"; then
				rm -f "$unit_file"
			fi
		done
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	if [ -f /etc/init.d/nodeping-agent-docker-update ] && grep -Fq "$MANAGED_MARKER" /etc/init.d/nodeping-agent-docker-update; then
		/etc/init.d/nodeping-agent-docker-update stop >/dev/null 2>&1 || true
		/etc/init.d/nodeping-agent-docker-update disable >/dev/null 2>&1 || true
		rm -f /etc/init.d/nodeping-agent-docker-update
	fi
}

validate_managed_directory() {
	local name="$1" value="$2"
	case "$value" in
		/*) ;;
		*) say_err "$name 必须是绝对路径" "$name must be an absolute path"; return 1 ;;
	esac
	if [[ ! "$value" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
		say_err "$name 只能包含字母、数字、点、下划线、横线和斜线" "$name contains unsupported characters"
		return 1
	fi
	case "$value" in
		*/../*|*/..|*/./*|*/.|*//*)
			say_err "$name 不能包含点路径或重复斜线" "$name must not contain dot components or repeated slashes"
			return 1
			;;
		/|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
			say_err "$name 不能指向系统顶层目录" "$name must not point to a top-level system directory"
			return 1
			;;
	esac
	if [ -L "$value" ]; then
		say_err "$name 不能是符号链接" "$name must not be a symbolic link"
		return 1
	fi
}

validate_directory_layout() {
	case "$PROJECT_DIRECTORY" in
		"$DATA_DIRECTORY"|"$DATA_DIRECTORY"/*)
			say_err "Agent 数据目录不能等于或包含安装目录" "the Agent data directory must not equal or contain the project directory"
			return 1
			;;
		"$RUNTIME_DIRECTORY"|"$RUNTIME_DIRECTORY"/*)
			say_err "Agent 运行目录不能等于或包含安装目录" "the Agent runtime directory must not equal or contain the project directory"
			return 1
			;;
	esac
	case "$DATA_DIRECTORY" in
		"$RUNTIME_DIRECTORY"|"$RUNTIME_DIRECTORY"/*)
			say_err "Agent 数据目录与运行目录不能重叠" "the Agent data and runtime directories must not overlap"
			return 1
			;;
	esac
	case "$RUNTIME_DIRECTORY" in
		"$DATA_DIRECTORY"/*)
			say_err "Agent 数据目录与运行目录不能重叠" "the Agent data and runtime directories must not overlap"
			return 1
			;;
	esac
}

detect_supported_architecture() {
	local machine
	machine="$(uname -m)"
	case "$machine" in
		x86_64|amd64) printf 'amd64\n' ;;
		aarch64|arm64) printf 'arm64\n' ;;
		*)
			say_err "NodePing Docker 镜像仅支持 amd64 和 arm64，当前架构为 ${machine}；手动 Compose 同样不可用，请返回页面查看原生 Agent 兼容性说明" "NodePing Docker images support only amd64 and arm64; manual Compose is unavailable on this architecture too; return to the page for native Agent compatibility guidance"
			return 1
			;;
	esac
}

download_file() {
	local source_url="$1" destination="$2"
	if command -v curl >/dev/null 2>&1; then
		if [[ "$source_url" == https://* ]]; then
			curl -fsSL --connect-timeout 8 --max-time 60 --proto '=https' --proto-redir '=https' "$source_url" -o "$destination"
		else
			curl -fsSL --connect-timeout 8 --max-time 60 --proto '=http,https' --proto-redir '=https' "$source_url" -o "$destination"
		fi
	else
		if [[ "$source_url" == https://* ]]; then
			wget --https-only --timeout=60 --tries=1 -qO "$destination" "$source_url"
		else
			wget --max-redirect=0 --timeout=60 --tries=1 -qO "$destination" "$source_url"
		fi
	fi
	[ -s "$destination" ] && ! LC_ALL=C head -c 512 "$destination" | LC_ALL=C grep -aEiq '^[[:space:]]*(<!DOCTYPE html|<html)'
}

env_quote() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g; s/[$`]/\\&/g'
}

if [ -z "$SERVER_URL" ] || [ -z "$BINDING_TOKEN" ]; then
	say_err "必须提供 NODEPING_SERVER_URL 和 NODEPING_TOKEN" "NODEPING_SERVER_URL and NODEPING_TOKEN are required"
	exit 2
fi

DISTRIBUTION_MODE="$(printf '%s' "$DISTRIBUTION_MODE" | tr '[:upper:]' '[:lower:]')"
ALLOW_INSECURE_HTTP="$(normalize_allow_insecure_http "$ALLOW_INSECURE_HTTP")"
case "$DISTRIBUTION_MODE" in
	cn) selected_image="$DOCKER_IMAGE_CN" ;;
	global) selected_image="$DOCKER_IMAGE_GLOBAL" ;;
	*) say_err "NODEPING_AGENT_DISTRIBUTION_MODE 必须为 cn 或 global" "NODEPING_AGENT_DISTRIBUTION_MODE must be cn or global"; exit 2 ;;
esac

case "$IMAGE_VERSION" in
	''|*[!A-Za-z0-9._-]*) say_err "NODEPING_AGENT_IMAGE_VERSION 无效" "invalid NODEPING_AGENT_IMAGE_VERSION"; exit 2 ;;
esac
validate_managed_directory "安装目录" "$PROJECT_DIRECTORY"
validate_managed_directory "Agent 数据目录" "$DATA_DIRECTORY"
validate_managed_directory "Agent 运行目录" "$RUNTIME_DIRECTORY"
validate_directory_layout

validate_secure_url "$SERVER_URL" "NODEPING_SERVER_URL" "$ALLOW_INSECURE_HTTP"
validate_secure_url "$DEPLOY_BASE_URL" "NODEPING_AGENT_DEPLOY_BASE_URL"
validate_image "NODEPING_AGENT_DOCKER_IMAGE_CN" "$DOCKER_IMAGE_CN"
validate_image "NODEPING_AGENT_DOCKER_IMAGE_GLOBAL" "$DOCKER_IMAGE_GLOBAL"
for item in \
	"NODEPING_TOKEN:$BINDING_TOKEN" \
	"NODEPING_AGENT_ID:$AGENT_ID" \
	"NODEPING_AGENT_NAME:$AGENT_NAME" \
	"NODEPING_AGENT_MINISIGN_PUBLIC_KEY:$SIGNING_PUBLIC_KEY" \
	"NODEPING_AGENT_REQUIRE_SIGNATURE:$REQUIRE_SIGNATURE" \
	"NODEPING_AGENT_SIGNATURE_REQUIRED_FROM:$SIGNATURE_REQUIRED_FROM"; do
	validate_env_value "${item%%:*}" "${item#*:}"
done
if ! REQUIRE_SIGNATURE="$(normalize_signature_mode "$REQUIRE_SIGNATURE")"; then
	say_err "NODEPING_AGENT_REQUIRE_SIGNATURE 配置无效" "invalid NODEPING_AGENT_REQUIRE_SIGNATURE; use required, auto, or disabled"
	exit 2
fi
validate_minisign_public_key "$SIGNING_PUBLIC_KEY"
if [ -n "$SIGNATURE_REQUIRED_FROM" ]; then
	SIGNATURE_REQUIRED_FROM="$(normalize_release_version "$SIGNATURE_REQUIRED_FROM")"
	if ! valid_release_version "$SIGNATURE_REQUIRED_FROM"; then
		say_err "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM 不是有效 SemVer" "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM is not valid SemVer"
		exit 2
	fi
fi
if { [ "$REQUIRE_SIGNATURE" = "required" ] || [ -n "$SIGNATURE_REQUIRED_FROM" ]; } && [ -z "$SIGNING_PUBLIC_KEY" ]; then
	say_err "签名策略需要 NODEPING_AGENT_MINISIGN_PUBLIC_KEY" "the signature policy requires NODEPING_AGENT_MINISIGN_PUBLIC_KEY"
	exit 2
fi
detect_supported_architecture >/dev/null
require_command docker
if ! docker compose version >/dev/null 2>&1; then
	say_err "需要 Docker Compose v2 插件；OpenWrt 请确认已安装兼容当前架构的 Compose v2" "Docker Compose v2 is required; on OpenWrt, install a Compose v2 plugin compatible with this architecture"
	exit 1
fi
for command_name in mkdir cp chmod mv rm mktemp sed grep head tr; do
	require_command "$command_name"
done
validate_data_directory_ownership
validate_runtime_directory_ownership
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
	say_err "需要安装 curl 或 wget" "curl or wget is required"
	exit 1
fi
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
download_file "${DEPLOY_BASE_URL%/}/compose.yml" "$tmp_dir/compose.yml"
download_file "${DEPLOY_BASE_URL%/}/update-docker.sh" "$tmp_dir/update-docker.sh"
download_file "${DEPLOY_BASE_URL%/}/uninstall-docker.sh" "$tmp_dir/uninstall-docker.sh"
bash -n "$tmp_dir/update-docker.sh"
bash -n "$tmp_dir/uninstall-docker.sh"

ensure_private_directory "$PROJECT_DIRECTORY"
ensure_private_directory "$DATA_DIRECTORY"
ensure_private_directory "$RUNTIME_DIRECTORY"
copy_file_with_mode "$tmp_dir/compose.yml" "$PROJECT_DIRECTORY/compose.yml" 0644
copy_file_with_mode "$tmp_dir/update-docker.sh" "$PROJECT_DIRECTORY/update-docker.sh" 0755
copy_file_with_mode "$tmp_dir/uninstall-docker.sh" "$PROJECT_DIRECTORY/uninstall-docker.sh" 0755
printf '%s\n' "$MANAGED_MARKER" > "$tmp_dir/data-marker"
copy_file_with_mode "$tmp_dir/data-marker" "$DATA_DIRECTORY/.nodeping-agent-docker-data" 0600
copy_file_with_mode "$tmp_dir/data-marker" "$RUNTIME_DIRECTORY/.nodeping-agent-docker-runtime" 0600
remove_legacy_host_upgrade_watcher
rm -f "$PROJECT_DIRECTORY/watch-docker-update.sh"
rm -f "$LEGACY_CONTROL_DIRECTORY/update-request.json" "$LEGACY_CONTROL_DIRECTORY/update-request.json.processing" "$LEGACY_CONTROL_DIRECTORY/update-request.json.failed"

{
	printf 'NODEPING_SERVER_URL="%s"\n' "$(env_quote "$SERVER_URL")"
	printf 'NODEPING_AGENT_ALLOW_INSECURE_HTTP="%s"\n' "$(env_quote "$ALLOW_INSECURE_HTTP")"
	printf 'NODEPING_TOKEN="%s"\n' "$(env_quote "$BINDING_TOKEN")"
	printf 'NODEPING_AGENT_ID="%s"\n' "$(env_quote "$AGENT_ID")"
	printf 'NODEPING_AGENT_NAME="%s"\n' "$(env_quote "$AGENT_NAME")"
	printf 'NODEPING_AGENT_DISTRIBUTION_MODE="%s"\n' "$(env_quote "$DISTRIBUTION_MODE")"
	printf 'NODEPING_AGENT_DOCKER_IMAGE_CN="%s"\n' "$(env_quote "$DOCKER_IMAGE_CN")"
	printf 'NODEPING_AGENT_DOCKER_IMAGE_GLOBAL="%s"\n' "$(env_quote "$DOCKER_IMAGE_GLOBAL")"
	printf 'NODEPING_AGENT_IMAGE="%s"\n' "$(env_quote "$selected_image")"
	printf 'NODEPING_AGENT_IMAGE_VERSION="%s"\n' "$(env_quote "$IMAGE_VERSION")"
	printf 'NODEPING_AGENT_DEPLOY_BASE_URL="%s"\n' "$(env_quote "$DEPLOY_BASE_URL")"
	printf 'NODEPING_AGENT_DOCKER_DATA_DIRECTORY="%s"\n' "$(env_quote "$DATA_DIRECTORY")"
	printf 'NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY="%s"\n' "$(env_quote "$RUNTIME_DIRECTORY")"
	printf 'NODEPING_AGENT_UPGRADE_MODE="container"\n'
	printf 'NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE="true"\n'
	printf 'NODEPING_AGENT_ACTIVATION_STABLE_SECONDS="20"\n'
	printf 'NODEPING_AGENT_MINISIGN_PUBLIC_KEY="%s"\n' "$(env_quote "$SIGNING_PUBLIC_KEY")"
	printf 'NODEPING_AGENT_REQUIRE_SIGNATURE="%s"\n' "$(env_quote "$REQUIRE_SIGNATURE")"
	printf 'NODEPING_AGENT_SIGNATURE_REQUIRED_FROM="%s"\n' "$(env_quote "$SIGNATURE_REQUIRED_FROM")"
} > "$tmp_dir/nodeping-agent.env"
copy_file_with_mode "$tmp_dir/nodeping-agent.env" "$PROJECT_DIRECTORY/.env" 0600

ENV_FILE="$PROJECT_DIRECTORY/.env" PROJECT_DIRECTORY="$PROJECT_DIRECTORY" "$PROJECT_DIRECTORY/update-docker.sh"
say "控制台远程升级已启用：容器内 Agent 更新器" "control-panel upgrades enabled: in-container Agent updater"
say "nodeping-agent Docker 部署已安装（${DISTRIBUTION_MODE}）" "nodeping-agent Docker deployment installed ($DISTRIBUTION_MODE)"
