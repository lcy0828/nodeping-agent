#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NODEPING_AGENT_RELEASE_BASE_URL:-}"
REQUESTED_VERSION="${NODEPING_AGENT_VERSION:-latest}"
GITHUB_REPOSITORY="${NODEPING_AGENT_GITHUB_REPOSITORY:-lcy0828/nodeping-agent}"
GITHUB_API_BASE_URL="${NODEPING_AGENT_GITHUB_API_BASE_URL:-https://api.github.com}"
INSTALL_PATH="${NODEPING_AGENT_INSTALL_PATH:-/opt/nodeping-agent/nodeping-agent}"
SERVICE_NAME="${NODEPING_AGENT_SERVICE:-nodeping-agent.service}"
RESTART_SERVICE="${NODEPING_AGENT_RESTART:-1}"
BACKUP_PATH="${NODEPING_AGENT_BACKUP_PATH:-$INSTALL_PATH.previous}"
SIGNING_PUBLIC_KEY="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
REQUIRE_SIGNATURE="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
START_TIMEOUT_SECONDS="${NODEPING_AGENT_START_TIMEOUT_SECONDS:-20}"
SERVER_URL="${NODEPING_SERVER_URL:-}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
AGENT_TOKEN="${NODEPING_AGENT_TOKEN:-}"
AGENT_TOKEN_FILE="${NODEPING_AGENT_TOKEN_FILE:-/var/lib/nodeping-agent/agent-token}"
UPDATE_REQUEST_FILE="${NODEPING_AGENT_UPDATE_REQUEST_FILE:-${NODEPING_AGENT_UPGRADE_REQUEST_FILE:-/var/lib/nodeping-agent/update-request.json}}"

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

download() {
	local url="$1"
	local dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$dest"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$dest" "$url"
	else
		say_err "需要安装 curl 或 wget" "curl or wget is required"
		return 1
	fi
}

download_quiet() {
	local url="$1"
	local dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$dest" 2>/dev/null
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$dest" "$url" 2>/dev/null
	else
		return 1
	fi
}

current_agent_version() {
	if [ -x "$INSTALL_PATH" ]; then
		"$INSTALL_PATH" -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/nodeping-agent\/\1/p' | head -n 1
	fi
}

agent_token() {
	if [ -n "$AGENT_TOKEN" ]; then
		printf '%s' "$AGENT_TOKEN"
		return 0
	fi
	if [ -r "$AGENT_TOKEN_FILE" ]; then
		tr -d '[:space:]' < "$AGENT_TOKEN_FILE"
	fi
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r//g; s/\n/ /g'
}

emit_upgrade_event() {
	local event="$1"
	local from_version="${2:-}"
	local to_version="${3:-}"
	local message="${4:-}"
	local token
	token="$(agent_token || true)"
	if [ -z "$SERVER_URL" ] || [ -z "$token" ] || [ -z "$AGENT_ID" ]; then
		return 0
	fi
	local payload
	payload="{\"agent_id\":\"$(json_escape "$AGENT_ID")\",\"event\":\"$(json_escape "$event")\",\"from_version\":\"$(json_escape "$from_version")\",\"to_version\":\"$(json_escape "$to_version")\",\"message\":\"$(json_escape "$message")\"}"
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -m 8 -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
	fi
}

verify_signature() {
	local artifact_path="$1"
	local signature_path="$2"
	if [ -z "$SIGNING_PUBLIC_KEY" ]; then
		if signature_required; then
			say_err "已要求签名校验，但 NODEPING_AGENT_MINISIGN_PUBLIC_KEY 为空" "NODEPING_AGENT_REQUIRE_SIGNATURE=1 but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty"
			return 1
		fi
		return 0
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		say_err "配置 NODEPING_AGENT_MINISIGN_PUBLIC_KEY 时需要安装 minisign" "minisign is required when NODEPING_AGENT_MINISIGN_PUBLIC_KEY is configured"
		return 1
	fi
	minisign -Vm "$artifact_path" -x "$signature_path" -P "$SIGNING_PUBLIC_KEY"
}

signature_required() {
	case "$(printf '%s' "$REQUIRE_SIGNATURE" | tr '[:upper:]' '[:lower:]')" in
		1|true|yes|on) return 0 ;;
		auto) [ -n "$SIGNING_PUBLIC_KEY" ] && return 0 || return 1 ;;
		*) return 1 ;;
	esac
}

wait_service_active() {
	local service="$1"
	local timeout="$2"
	local deadline=$((SECONDS + timeout))
	while [ "$SECONDS" -le "$deadline" ]; do
		if systemctl is-active --quiet "$service"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

restart_with_rollback() {
	if [ "$RESTART_SERVICE" != "1" ] || ! command -v systemctl >/dev/null 2>&1; then
		return 0
	fi
	systemctl restart "$SERVICE_NAME"
	if wait_service_active "$SERVICE_NAME" "$START_TIMEOUT_SECONDS"; then
		say "已重启 $SERVICE_NAME" "restarted $SERVICE_NAME"
		return 0
	fi
	say_err "$SERVICE_NAME 升级后未变为 active，正在回滚" "$SERVICE_NAME did not become active after update; rolling back"
	emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "service did not become active after update"
	emit_upgrade_event "rollback_started" "$CURRENT_VERSION" "$TARGET_VERSION" "service did not become active"
	if [ -x "$BACKUP_PATH" ]; then
		install -m 0755 "$BACKUP_PATH" "$INSTALL_PATH.rollback"
		mv -f "$INSTALL_PATH.rollback" "$INSTALL_PATH"
		systemctl restart "$SERVICE_NAME" || true
		if wait_service_active "$SERVICE_NAME" "$START_TIMEOUT_SECONDS"; then
			emit_upgrade_event "rollback_succeeded" "$TARGET_VERSION" "$CURRENT_VERSION" "service restored previous binary"
		else
			emit_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "rollback restart failed"
		fi
	fi
	return 1
}

sha256_value() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

detect_os() {
	case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
		linux) echo linux ;;
		darwin) echo darwin ;;
		*) say_err "不支持当前系统：$(uname -s)" "unsupported OS: $(uname -s)"; return 1 ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64) echo amd64 ;;
		aarch64|arm64) echo arm64 ;;
		armv7l|armv7*) echo armv7 ;;
		*) say_err "不支持当前架构：$(uname -m)" "unsupported arch: $(uname -m)"; return 1 ;;
	esac
}

normalize_version() {
	local raw="${1#nodeping-agent/}"
	case "$raw" in
		latest|v*) printf '%s' "$raw" ;;
		[0-9]*) printf 'v%s' "$raw" ;;
		*) printf '%s' "$raw" ;;
	esac
}

default_release_base_url() {
	local version="$1"
	local repository="${GITHUB_REPOSITORY#/}"
	printf 'https://github.com/%s/releases/download/%s' "$repository" "$version"
}

latest_redirect_version() {
	local repository="${GITHUB_REPOSITORY#/}"
	local latest_url="https://github.com/$repository/releases/latest"
	local effective tag
	if command -v curl >/dev/null 2>&1; then
		effective="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null || true)"
	elif command -v wget >/dev/null 2>&1; then
		effective="$(wget -qS --max-redirect=10 --spider "$latest_url" 2>&1 | awk '/^  Location: / { value=$2 } END { print value }' || true)"
	fi
	tag="${effective##*/}"
	tag="$(normalize_version "$tag")"
	if [ -n "$tag" ] && [ "$tag" != "latest" ]; then
		printf '%s' "$tag"
		return 0
	fi
	return 1
}

latest_release_version() {
	local dest="$1/latest-release.json"
	local repository="${GITHUB_REPOSITORY#/}"
	local api_base="${GITHUB_API_BASE_URL%/}"
	local tag
	if download_quiet "$api_base/repos/$repository/releases/latest" "$dest"; then
		tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dest" | head -n 1)"
		tag="$(normalize_version "$tag")"
		if [ -n "$tag" ] && [ "$tag" != "latest" ]; then
			printf '%s' "$tag"
			return 0
		fi
	fi
	if tag="$(latest_redirect_version)"; then
		printf '%s' "$tag"
		return 0
	fi
	say_err "无法从 GitHub API 或 latest 跳转解析最新版本：$repository" "failed to resolve latest release from GitHub API or latest redirect for $repository"
	return 1
}

json_file_value() {
	local file="$1"
	local key="$2"
	sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

consume_update_request() {
	if [ ! -r "$UPDATE_REQUEST_FILE" ]; then
		return 0
	fi
	local requested requested_base
	requested="$(json_file_value "$UPDATE_REQUEST_FILE" version || true)"
	requested_base="$(json_file_value "$UPDATE_REQUEST_FILE" release_base_url || true)"
	rm -f "$UPDATE_REQUEST_FILE"
	if [ -n "$requested" ]; then
		REQUESTED_VERSION="$requested"
	fi
	if [ -n "$requested_base" ]; then
		BASE_URL="$requested_base"
	fi
}

consume_update_request

REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

version="$REQUESTED_VERSION"
if [ "$version" = "latest" ]; then
	version="$(latest_release_version "$tmp_dir")"
fi

if [ -z "$version" ]; then
	say_err "发布版本为空" "empty release version"
	exit 2
fi

if [ -z "$BASE_URL" ]; then
	BASE_URL="$(default_release_base_url "$version")"
fi
BASE_URL="${BASE_URL%/}"

TARGET_VERSION="nodeping-agent/$version"
CURRENT_VERSION="$(current_agent_version || true)"

os="$(detect_os)"
arch="$(detect_arch)"
artifact="nodeping-agent_${version}_${os}_${arch}.tar.gz"
checksums="nodeping-agent_${version}_checksums.txt"

download "$BASE_URL/$artifact" "$tmp_dir/$artifact"
download "$BASE_URL/$checksums" "$tmp_dir/$checksums"
if [ -n "$SIGNING_PUBLIC_KEY" ] || signature_required; then
	download "$BASE_URL/$artifact.minisig" "$tmp_dir/$artifact.minisig"
	verify_signature "$tmp_dir/$artifact" "$tmp_dir/$artifact.minisig"
fi

expected="$(awk -v file="$artifact" '$2 == file { print $1 }' "$tmp_dir/$checksums")"
if [ -z "$expected" ]; then
	say_err "校验和文件 $checksums 中找不到 $artifact" "checksum for $artifact not found in $checksums"
	exit 1
fi

actual="$(sha256_value "$tmp_dir/$artifact")"
if [ "$actual" != "$expected" ]; then
	say_err "$artifact 校验和不匹配" "checksum mismatch for $artifact"
	exit 1
fi

mkdir -p "$tmp_dir/extract"
tar -xzf "$tmp_dir/$artifact" -C "$tmp_dir/extract"
new_bin="$(find "$tmp_dir/extract" -type f -name nodeping-agent -perm -111 | head -n 1)"
if [ -z "$new_bin" ]; then
	say_err "$artifact 中未找到 nodeping-agent 二进制" "nodeping-agent binary not found in $artifact"
	exit 1
fi

if [ -x "$INSTALL_PATH" ] && cmp -s "$new_bin" "$INSTALL_PATH"; then
	say "nodeping-agent 已是最新版本：$version" "nodeping-agent is already up to date: $version"
	emit_upgrade_event "up_to_date" "$CURRENT_VERSION" "$TARGET_VERSION" "binary already matches requested version"
	exit 0
fi

emit_upgrade_event "update_started" "$CURRENT_VERSION" "$TARGET_VERSION" "installing release $version"

if [ -x "$INSTALL_PATH" ]; then
	install -m 0755 "$INSTALL_PATH" "$BACKUP_PATH"
	say "已备份旧版 nodeping-agent 到 $BACKUP_PATH" "backed up previous nodeping-agent to $BACKUP_PATH"
fi

install -m 0755 "$new_bin" "$INSTALL_PATH.new"
mv -f "$INSTALL_PATH.new" "$INSTALL_PATH"
if command -v setcap >/dev/null 2>&1; then
	setcap cap_net_raw+ep "$INSTALL_PATH" >/dev/null 2>&1 || true
fi
say "已安装 nodeping-agent $version 到 $INSTALL_PATH" "installed nodeping-agent $version to $INSTALL_PATH"

if restart_with_rollback; then
	emit_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$TARGET_VERSION" "update completed"
else
	exit 1
fi
