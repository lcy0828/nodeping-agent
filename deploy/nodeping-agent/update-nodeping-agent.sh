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
AGENT_ID="${NODEPING_AGENT_ID:-$(hostname | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-')}"
AGENT_TOKEN="${NODEPING_AGENT_TOKEN:-}"
AGENT_TOKEN_FILE="${NODEPING_AGENT_TOKEN_FILE:-/var/lib/nodeping-agent/agent-token}"
UPDATE_REQUEST_FILE="${NODEPING_AGENT_UPDATE_REQUEST_FILE:-${NODEPING_AGENT_UPGRADE_REQUEST_FILE:-/var/lib/nodeping-agent/update-request.json}}"

download() {
	local url="$1"
	local dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$dest"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$dest" "$url"
	else
		echo "curl or wget is required" >&2
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
	if [ -z "$SERVER_URL" ] || [ -z "$token" ]; then
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
			echo "NODEPING_AGENT_REQUIRE_SIGNATURE=1 but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty" >&2
			return 1
		fi
		return 0
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		echo "minisign is required when NODEPING_AGENT_MINISIGN_PUBLIC_KEY is configured" >&2
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
		echo "restarted $SERVICE_NAME"
		return 0
	fi
	echo "$SERVICE_NAME did not become active after update; rolling back" >&2
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
		*) echo "unsupported OS: $(uname -s)" >&2; return 1 ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64) echo amd64 ;;
		aarch64|arm64) echo arm64 ;;
		armv7l|armv7*) echo armv7 ;;
		*) echo "unsupported arch: $(uname -m)" >&2; return 1 ;;
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
	if tag="$(latest_redirect_version)"; then
		printf '%s' "$tag"
		return 0
	fi
	download "$api_base/repos/$repository/releases/latest" "$dest"
	local tag
	tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dest" | head -n 1)"
	tag="$(normalize_version "$tag")"
	if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
		echo "failed to resolve latest release from GitHub API for $repository" >&2
		return 1
	fi
	printf '%s' "$tag"
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
	echo "empty release version" >&2
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
	echo "checksum for $artifact not found in $checksums" >&2
	exit 1
fi

actual="$(sha256_value "$tmp_dir/$artifact")"
if [ "$actual" != "$expected" ]; then
	echo "checksum mismatch for $artifact" >&2
	exit 1
fi

mkdir -p "$tmp_dir/extract"
tar -xzf "$tmp_dir/$artifact" -C "$tmp_dir/extract"
new_bin="$(find "$tmp_dir/extract" -type f -name nodeping-agent -perm -111 | head -n 1)"
if [ -z "$new_bin" ]; then
	echo "nodeping-agent binary not found in $artifact" >&2
	exit 1
fi

if [ -x "$INSTALL_PATH" ] && cmp -s "$new_bin" "$INSTALL_PATH"; then
	echo "nodeping-agent is already up to date: $version"
	emit_upgrade_event "up_to_date" "$CURRENT_VERSION" "$TARGET_VERSION" "binary already matches requested version"
	exit 0
fi

emit_upgrade_event "update_started" "$CURRENT_VERSION" "$TARGET_VERSION" "installing release $version"

if [ -x "$INSTALL_PATH" ]; then
	install -m 0755 "$INSTALL_PATH" "$BACKUP_PATH"
	echo "backed up previous nodeping-agent to $BACKUP_PATH"
fi

install -m 0755 "$new_bin" "$INSTALL_PATH.new"
mv -f "$INSTALL_PATH.new" "$INSTALL_PATH"
echo "installed nodeping-agent $version to $INSTALL_PATH"

if restart_with_rollback; then
	emit_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$TARGET_VERSION" "update completed"
else
	exit 1
fi
