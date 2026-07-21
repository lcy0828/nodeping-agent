#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NODEPING_AGENT_RELEASE_BASE_URL:-}"
REQUESTED_VERSION="${NODEPING_AGENT_VERSION:-latest}"
GITHUB_REPOSITORY="${NODEPING_AGENT_GITHUB_REPOSITORY:-lcy0828/nodeping-agent}"
GITHUB_API_BASE_URL="${NODEPING_AGENT_GITHUB_API_BASE_URL:-https://api.github.com}"
INSTALL_PATH="${NODEPING_AGENT_INSTALL_PATH:-/opt/nodeping-agent/nodeping-agent}"
ACTIVE_BINARY="${NODEPING_AGENT_ACTIVE_BINARY:-$INSTALL_PATH}"
SERVICE_NAME="${NODEPING_AGENT_SERVICE:-nodeping-agent.service}"
RESTART_SERVICE="${NODEPING_AGENT_RESTART:-1}"
BACKUP_PATH="${NODEPING_AGENT_BACKUP_PATH:-$INSTALL_PATH.previous}"
ACTIVATION_FILE="${NODEPING_AGENT_ACTIVATION_FILE:-}"
UPDATE_LOCK_DIRECTORY="${NODEPING_AGENT_UPDATE_LOCK_DIRECTORY:-$(dirname "$INSTALL_PATH")/.nodeping-agent-update.lock}"
SIGNING_PUBLIC_KEY="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
REQUIRE_SIGNATURE="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
SIGNATURE_REQUIRED_FROM="${NODEPING_AGENT_SIGNATURE_REQUIRED_FROM:-}"
DISTRIBUTION_MODE="${NODEPING_AGENT_DISTRIBUTION_MODE:-cn}"
ALLOW_DOWNGRADE="${NODEPING_AGENT_ALLOW_DOWNGRADE:-0}"
START_TIMEOUT_SECONDS="${NODEPING_AGENT_START_TIMEOUT_SECONDS:-20}"
READINESS_STABLE_SECONDS="${NODEPING_AGENT_READINESS_STABLE_SECONDS:-5}"
SERVER_URL="${NODEPING_SERVER_URL:-}"
ALLOW_INSECURE_HTTP="${NODEPING_AGENT_ALLOW_INSECURE_HTTP:-false}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
AGENT_TOKEN="${NODEPING_AGENT_TOKEN:-}"
AGENT_TOKEN_FILE="${NODEPING_AGENT_TOKEN_FILE:-/var/lib/nodeping-agent/agent-token}"
RELEASE_PROXY_FILE="${NODEPING_AGENT_RELEASE_PROXY_FILE:-/var/lib/nodeping-agent/release-proxies.tsv}"
LATEST_VERSION_FILE="${NODEPING_AGENT_LATEST_VERSION_FILE:-/var/lib/nodeping-agent/latest-version}"
UPDATE_REQUEST_FILE="${NODEPING_AGENT_UPDATE_REQUEST_FILE:-${NODEPING_AGENT_UPGRADE_REQUEST_FILE:-/var/lib/nodeping-agent/update-request.json}}"
CURRENT_VERSION=""
TARGET_VERSION=""
UPGRADE_STEP="starting updater"
UPGRADE_EVENT_FINALIZED=0
UPDATE_LOCK_OWNED=0
tmp_dir=""

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		return 1
	fi
}

preflight() {
	if [ "$(id -u)" -ne 0 ]; then
		say_err "更新器需要 root 权限" "the updater must run as root"
		return 1
	fi
	for command in tar awk grep sed install mktemp; do
		require_command "$command"
	done
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		say_err "需要安装 curl 或 wget" "curl or wget is required"
		return 1
	fi
	if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
		say_err "需要安装 sha256sum 或 shasum" "sha256sum or shasum is required"
		return 1
	fi
}

acquire_update_lock() {
	local owner=""
	mkdir -p "$(dirname "$INSTALL_PATH")" "$(dirname "$UPDATE_LOCK_DIRECTORY")"
	if mkdir "$UPDATE_LOCK_DIRECTORY" 2>/dev/null; then
		UPDATE_LOCK_OWNED=1
		printf '%s\n' "$$" > "$UPDATE_LOCK_DIRECTORY/pid"
		return 0
	fi
	if [ -f "$UPDATE_LOCK_DIRECTORY/pid" ] && [ ! -L "$UPDATE_LOCK_DIRECTORY/pid" ]; then
		IFS= read -r owner < "$UPDATE_LOCK_DIRECTORY/pid" || true
	fi
	case "$owner" in
		''|*[!0-9]*) ;;
		*)
			if kill -0 "$owner" 2>/dev/null; then
				say_err "已有 Agent 更新正在执行" "another Agent update is already running"
				return 1
			fi
			;;
	esac
	rm -f "$UPDATE_LOCK_DIRECTORY/pid"
	rmdir "$UPDATE_LOCK_DIRECTORY" 2>/dev/null || true
	if ! mkdir "$UPDATE_LOCK_DIRECTORY" 2>/dev/null; then
		say_err "无法获取 Agent 更新锁" "could not acquire the Agent update lock"
		return 1
	fi
	UPDATE_LOCK_OWNED=1
	printf '%s\n' "$$" > "$UPDATE_LOCK_DIRECTORY/pid"
}

release_update_lock() {
	[ "$UPDATE_LOCK_OWNED" = "1" ] || return 0
	local owner=""
	if [ -f "$UPDATE_LOCK_DIRECTORY/pid" ] && [ ! -L "$UPDATE_LOCK_DIRECTORY/pid" ]; then
		IFS= read -r owner < "$UPDATE_LOCK_DIRECTORY/pid" || true
	fi
	if [ "$owner" = "$$" ]; then
		rm -f "$UPDATE_LOCK_DIRECTORY/pid"
		rmdir "$UPDATE_LOCK_DIRECTORY" 2>/dev/null || true
	fi
	UPDATE_LOCK_OWNED=0
}

is_loopback_http_url() {
	local url="$1"
	[[ "$url" =~ ^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

validate_secure_url() {
	local url="$1"
	local name="$2"
	local allow_insecure_http="${3:-false}"
	if [[ "$url" =~ [[:space:]@] ]]; then
		say_err "$name 不是安全的 URL" "$name is not a safe URL"
		return 1
	fi
	if [[ "$url" == https://* ]] || is_loopback_http_url "$url"; then return 0; fi
	if [ "$allow_insecure_http" = "true" ] && [[ "$url" == http://* ]]; then return 0; fi
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

download_with_curl() {
	local url="$1"
	local dest="$2"
	local timeout_seconds="${3:-60}"
	if [[ "$url" == https://* ]]; then
		curl -fsSL --connect-timeout 8 --max-time "$timeout_seconds" --proto '=https' --proto-redir '=https' "$url" -o "$dest"
	else
		curl -fsSL --connect-timeout 8 --max-time "$timeout_seconds" --proto '=http,https' --proto-redir '=https' "$url" -o "$dest"
	fi
}

normalize_release_proxy_redirect_url() {
	local base_url="${1%/}/" location="$2" origin authority next_url
	case "$location" in
		https://*) next_url="$location" ;;
		/*)
			authority="${base_url#https://}"
			authority="${authority%%/*}"
			[ -n "$authority" ] || return 1
			origin="https://$authority"
			next_url="$origin$location"
			;;
		*) return 1 ;;
	esac
	case "$next_url" in *%*|*\\*|*..*) return 1 ;; esac
	if [ "$next_url" != "${base_url%/}" ] && [[ "$next_url" != "$base_url"* ]]; then
		return 1
	fi
	validate_secure_url "$next_url" "release proxy redirect URL" >/dev/null 2>&1 || return 1
	printf '%s' "$next_url"
}

download_proxy_with_curl() {
	local source_url="$1" base_url="$2" destination="$3" timeout_seconds="$4"
	local current_url="$source_url" headers="$destination.headers" status location next_url remaining redirects=0
	local deadline=$((SECONDS + timeout_seconds))
	while [ "$redirects" -le 3 ]; do
		remaining=$((deadline - SECONDS))
		[ "$remaining" -gt 0 ] || { rm -f "$headers"; return 1; }
		rm -f "$headers" "$destination"
		status="$(curl -sS --connect-timeout 8 --max-time "$remaining" --max-redirs 0 --proto '=https' -D "$headers" -o "$destination" -w '%{http_code}' "$current_url")" || {
			rm -f "$headers"
			return 1
		}
		case "$status" in
			2[0-9][0-9]) rm -f "$headers"; return 0 ;;
			301|302|303|307|308)
				[ "$redirects" -lt 3 ] || { rm -f "$headers"; return 1; }
				location="$(LC_ALL=C awk 'tolower(substr($0, 1, 9)) == "location:" { line=substr($0, 10); sub(/^[[:space:]]+/, "", line); sub(/\r$/, "", line); print line; exit }' "$headers")"
				[ -n "$location" ] || { rm -f "$headers"; return 1; }
				next_url="$(normalize_release_proxy_redirect_url "$base_url" "$location" 2>/dev/null || true)"
				[ -n "$next_url" ] || { rm -f "$headers"; return 1; }
				current_url="$next_url"
				redirects=$((redirects + 1))
				;;
			*) rm -f "$headers"; return 1 ;;
		esac
	done
	rm -f "$headers"
	return 1
}

download_with_wget() {
	local url="$1"
	local dest="$2"
	local timeout_seconds="${3:-60}"
	if [[ "$url" == https://* ]]; then
		if command -v timeout >/dev/null 2>&1; then
			timeout "$timeout_seconds" wget --https-only --timeout="$timeout_seconds" --tries=1 -qO "$dest" "$url"
		else
			wget --https-only --timeout="$timeout_seconds" --tries=1 -qO "$dest" "$url"
		fi
	else
		if command -v timeout >/dev/null 2>&1; then
			timeout "$timeout_seconds" wget --max-redirect=0 --timeout="$timeout_seconds" --tries=1 -qO "$dest" "$url"
		else
			wget --max-redirect=0 --timeout="$timeout_seconds" --tries=1 -qO "$dest" "$url"
		fi
	fi
}

download_proxy_with_wget() {
	local source_url="$1" destination="$2" timeout_seconds="$3"
	command -v timeout >/dev/null 2>&1 || return 1
	timeout "$timeout_seconds" wget --https-only --max-redirect=0 --timeout="$timeout_seconds" --tries=1 -qO "$destination" "$source_url"
}

default_release_proxy_catalog() {
	printf '%s\t%s\t%s\t%s\n' \
		1 full_url https://hub.ilatency.com/ '' \
		2 host_path https://git.yylx.win/ '' \
		3 query https://ghfast.top/ q \
		4 full_url https://gh.llkk.cc/ '' \
		5 full_url https://fastgit.cc/ '' \
		6 host_path https://gh-proxy.com/ ''
}

release_proxy_catalog() {
	if [ -r "$RELEASE_PROXY_FILE" ]; then
		sed -n '1,32p' "$RELEASE_PROXY_FILE"
	else
		default_release_proxy_catalog
	fi
}

proxy_eligible_release_url() {
	local url="$1"
	[[ "$url" == "https://github.com/${GITHUB_REPOSITORY#/}/releases/"* ]]
}

url_encode_query_value() {
	local value="$1" char hex index
	local LC_ALL=C
	for ((index = 0; index < ${#value}; index++)); do
		char="${value:index:1}"
		case "$char" in
			[A-Za-z0-9.~_-]) printf '%s' "$char" ;;
			*)
				printf -v hex '%02X' "'$char"
				printf '%%%s' "$hex"
				;;
		esac
	done
}

render_release_proxy_url() {
	local mode="$1" base_url="${2%/}" query_param="$3" origin_url="$4"
	case "$mode" in
		host_path) printf '%s/%s' "$base_url" "${origin_url#https://}" ;;
		full_url) printf '%s/%s' "$base_url" "$origin_url" ;;
		query)
			[[ "$query_param" =~ ^[A-Za-z][A-Za-z0-9_.-]{0,63}$ ]] || return 1
			printf '%s/?%s=' "$base_url" "$query_param"
			url_encode_query_value "$origin_url"
			;;
		*) return 1 ;;
	esac
}

download_raw() {
	local url="$1" dest="$2" timeout_seconds="${3:-60}"
	if command -v curl >/dev/null 2>&1; then
		download_with_curl "$url" "$dest" "$timeout_seconds"
	elif command -v wget >/dev/null 2>&1; then
		download_with_wget "$url" "$dest" "$timeout_seconds"
	else
		return 1
	fi
}

download_file_is_usable() {
	local dest="$1"
	[ -s "$dest" ] && ! LC_ALL=C head -c 512 "$dest" | LC_ALL=C grep -aEiq '^[[:space:]]*(<!DOCTYPE html|<html)'
}

download_quiet() {
	local url="$1"
	local dest="$2"
	validate_secure_url "$url" "download URL" >/dev/null 2>&1 || return 1
	download_raw "$url" "$dest" 30 2>/dev/null && download_file_is_usable "$dest"
}

release_download_sources() {
	if [ "$DISTRIBUTION_MODE" = "global" ]; then
		printf 'direct\tdirect\t-\t-\n'
		release_proxy_catalog
	else
		release_proxy_catalog
		printf 'direct\tdirect\t-\t-\n'
	fi
}

render_release_source_url() {
	local mode="$1" base_url="$2" query_param="$3" origin_url="$4"
	if [ "$mode" = "direct" ]; then
		printf '%s' "$origin_url"
	else
		render_release_proxy_url "$mode" "$base_url" "$query_param" "$origin_url"
	fi
}

download_release_source_file() {
	local mode="$1" base_url="$2" query_param="$3" origin_url="$4" destination="$5"
	local timeout_seconds="${6:-60}" deadline="${7:-0}" candidate remaining
	if [ "$deadline" -gt 0 ]; then
		remaining=$((deadline - SECONDS))
		[ "$remaining" -gt 0 ] || return 1
		if [ "$remaining" -lt "$timeout_seconds" ]; then
			timeout_seconds="$remaining"
		fi
	fi
	candidate="$(render_release_source_url "$mode" "$base_url" "$query_param" "$origin_url" 2>/dev/null || true)"
	[ -n "$candidate" ] || return 1
	if [ "$mode" != "direct" ] && [[ "$candidate" != https://* ]]; then
		return 1
	fi
	validate_secure_url "$candidate" "release download URL" >/dev/null 2>&1 || return 1
	rm -f "$destination"
	if [ "$mode" = "direct" ]; then
		download_raw "$candidate" "$destination" "$timeout_seconds" >/dev/null 2>&1 || return 1
	elif command -v curl >/dev/null 2>&1; then
		download_proxy_with_curl "$candidate" "$base_url" "$destination" "$timeout_seconds" >/dev/null 2>&1 || return 1
	else
		download_proxy_with_wget "$candidate" "$destination" "$timeout_seconds" >/dev/null 2>&1 || return 1
	fi
	download_file_is_usable "$destination"
}

clear_release_downloads() {
	local directory="$1" artifact="$2" checksums="$3" manifest="$4"
	rm -f \
		"$directory/$artifact" "$directory/$checksums" "$directory/$manifest" \
		"$directory/$artifact.minisig" "$directory/$checksums.minisig" "$directory/$manifest.minisig"
}

download_verified_release_set() {
	local release_base_url="$1" directory="$2" artifact="$3" checksums="$4" manifest="$5"
	local release_version="$6" artifact_os="$7" artifact_arch="$8" signature_required="$9"
	local source_id source_mode source_base source_query extra origin expected actual manifest_available signed_file
	local metadata_timeout artifact_timeout source_deadline proxy_deadline=$((SECONDS + 300))
	RELEASE_MANIFEST_AVAILABLE=0
	while IFS=$'\t' read -r source_id source_mode source_base source_query extra || [ -n "${source_id:-}" ]; do
		[ -n "${source_id:-}" ] || continue
		if [ "$source_mode" = "direct" ]; then
			[ "$source_id" = "direct" ] || continue
			metadata_timeout=60
			artifact_timeout=300
			source_deadline=0
		else
			[[ "$source_id" =~ ^[0-9]+$ ]] || continue
			[ "$signature_required" = "1" ] || continue
			[ "$SECONDS" -lt "$proxy_deadline" ] || continue
			metadata_timeout=30
			artifact_timeout=240
			source_deadline="$proxy_deadline"
		fi
		origin="$release_base_url/$artifact"
		if [ "$source_mode" != "direct" ] && ! proxy_eligible_release_url "$origin"; then
			continue
		fi
		clear_release_downloads "$directory" "$artifact" "$checksums" "$manifest"
		download_release_source_file "$source_mode" "$source_base" "$source_query" "$release_base_url/$checksums" "$directory/$checksums" "$metadata_timeout" "$source_deadline" || continue
		manifest_available=0
		if [ "$signature_required" = "1" ]; then
			download_release_source_file "$source_mode" "$source_base" "$source_query" "$release_base_url/$manifest" "$directory/$manifest" "$metadata_timeout" "$source_deadline" || continue
			manifest_available=1
			for signed_file in "$checksums" "$manifest"; do
				download_release_source_file "$source_mode" "$source_base" "$source_query" "$release_base_url/$signed_file.minisig" "$directory/$signed_file.minisig" "$metadata_timeout" "$source_deadline" || break
			done
			[ -s "$directory/$manifest.minisig" ] || continue
			verify_signature "$directory/$checksums" "$directory/$checksums.minisig" >/dev/null 2>&1 || continue
			verify_signature "$directory/$manifest" "$directory/$manifest.minisig" >/dev/null 2>&1 || continue
		elif download_release_source_file "$source_mode" "$source_base" "$source_query" "$release_base_url/$manifest" "$directory/$manifest" "$metadata_timeout" "$source_deadline"; then
			manifest_available=1
		else
			rm -f "$directory/$manifest"
		fi
		expected="$(awk -v file="$artifact" '$2 == file { print $1 }' "$directory/$checksums")"
		[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || continue
		download_release_source_file "$source_mode" "$source_base" "$source_query" "$origin" "$directory/$artifact" "$artifact_timeout" "$source_deadline" || continue
		if [ "$signature_required" = "1" ]; then
			download_release_source_file "$source_mode" "$source_base" "$source_query" "$release_base_url/$artifact.minisig" "$directory/$artifact.minisig" "$metadata_timeout" "$source_deadline" || continue
			verify_signature "$directory/$artifact" "$directory/$artifact.minisig" >/dev/null 2>&1 || continue
		fi
		actual="$(sha256_value "$directory/$artifact")"
		[ "$actual" = "$expected" ] || continue
		if [ "$manifest_available" = "1" ]; then
			validate_release_manifest "$directory/$manifest" "$release_version" "$artifact" "$artifact_os" "$artifact_arch" "$actual" >/dev/null 2>&1 || continue
		fi
		validate_archive "$directory/$artifact" >/dev/null 2>&1 || continue
		RELEASE_MANIFEST_AVAILABLE="$manifest_available"
		if [ "$source_mode" = "direct" ]; then
			say "已通过发布源直连下载并验证发布文件" "downloaded and verified release files directly from the release source"
		else
			say "已通过发布代理 $source_id 下载并验证发布文件" "downloaded and verified release files through release proxy $source_id"
		fi
		return 0
	done < <(release_download_sources)
	clear_release_downloads "$directory" "$artifact" "$checksums" "$manifest"
	say_err "所有发布代理及发布源直连均未返回可验证的完整发布文件" "no release proxy or direct release-source download returned a complete verifiable release set"
	return 1
}

current_agent_version() {
	local path="$ACTIVE_BINARY"
	if [ ! -x "$path" ]; then
		path="$INSTALL_PATH"
	fi
	if [ -x "$path" ]; then
		"$path" -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/nodeping-agent\/\1/p' | head -n 1
	fi
}

agent_binary_release_version() {
	local path="$1"
	if [ -x "$path" ]; then
		"$path" -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/\1/p' | head -n 1
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
	local progress="${5:-}"
	local token
	token="$(agent_token || true)"
	if [ -z "$SERVER_URL" ] || [ -z "$token" ] || [ -z "$AGENT_ID" ]; then
		return 0
	fi
	local payload
	payload="{\"agent_id\":\"$(json_escape "$AGENT_ID")\",\"event\":\"$(json_escape "$event")\",\"from_version\":\"$(json_escape "$from_version")\",\"to_version\":\"$(json_escape "$to_version")\",\"message\":\"$(json_escape "$message")\""
	if [ -n "$progress" ]; then
		payload="$payload,\"progress\":$progress"
	fi
	payload="$payload}"
	if command -v curl >/dev/null 2>&1; then
		if [[ "$SERVER_URL" == https://* ]]; then
			curl -fsS -m 8 --proto '=https' --proto-redir '=https' -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
		else
			curl -fsS -m 8 --proto '=http,https' --proto-redir '=https' -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ "$SERVER_URL" == https://* ]]; then
			wget --https-only -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
		else
			wget --max-redirect=0 -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
		fi
	fi
}

emit_upgrade_progress() {
	local progress="$1"
	local message="$2"
	emit_upgrade_event "update_started" "${CURRENT_VERSION:-}" "${TARGET_VERSION:-}" "$message" "$progress"
}

emit_terminal_upgrade_event() {
	local event="$1"
	local from_version="${2:-}"
	local to_version="${3:-}"
	local message="${4:-}"
	local progress="${5:-100}"
	UPGRADE_EVENT_FINALIZED=1
	emit_upgrade_event "$event" "$from_version" "$to_version" "$message" "$progress"
}

cleanup_and_report_failure() {
	local code=$?
	if [ -n "${tmp_dir:-}" ]; then
		rm -rf "$tmp_dir"
	fi
	if [ "$code" -ne 0 ] && [ "${UPGRADE_EVENT_FINALIZED:-0}" != "1" ]; then
		emit_terminal_upgrade_event "update_failed" "${CURRENT_VERSION:-}" "${TARGET_VERSION:-}" "${UPGRADE_STEP:-updater failed} (exit $code)"
	fi
	release_update_lock || true
	exit "$code"
}

verify_signature() {
	local artifact_path="$1"
	local signature_path="$2"
	if [ -z "$SIGNING_PUBLIC_KEY" ]; then
		say_err "签名校验需要 NODEPING_AGENT_MINISIGN_PUBLIC_KEY" "signature verification requires NODEPING_AGENT_MINISIGN_PUBLIC_KEY"
		return 1
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		say_err "配置 NODEPING_AGENT_MINISIGN_PUBLIC_KEY 时需要安装 minisign" "minisign is required when NODEPING_AGENT_MINISIGN_PUBLIC_KEY is configured"
		return 1
	fi
	minisign -Vm "$artifact_path" -x "$signature_path" -P "$SIGNING_PUBLIC_KEY"
}

ensure_minisign() {
	if command -v minisign >/dev/null 2>&1; then
		return 0
	fi
	say "签名校验需要 minisign，正在尝试通过系统包管理器安装" "minisign is required for signature verification; attempting installation through the system package manager"
	if command -v apt-get >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y minisign || true
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y minisign || true
	elif command -v yum >/dev/null 2>&1; then
		yum install -y minisign || true
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache minisign || true
	elif command -v pacman >/dev/null 2>&1; then
		pacman -S --noconfirm --needed minisign || true
	fi
	if command -v minisign >/dev/null 2>&1; then
		return 0
	fi
	say_err "无法自动安装 minisign；请先用系统包管理器安装后重试" "failed to install minisign automatically; install it with the system package manager and retry"
	return 1
}

normalize_signature_mode() {
	case "$(printf '%s' "$REQUIRE_SIGNATURE" | tr '[:upper:]' '[:lower:]')" in
		1|true|yes|on|required) printf 'required' ;;
		auto|'') printf 'auto' ;;
		0|false|no|off|disabled) printf 'disabled' ;;
		*) return 1 ;;
	esac
}

signature_required_for_version() {
	local release_version="$1"
	local mode
	if ! mode="$(normalize_signature_mode)"; then
		say_err "NODEPING_AGENT_REQUIRE_SIGNATURE 配置无效" "invalid NODEPING_AGENT_REQUIRE_SIGNATURE; use required, auto, or disabled"
		return 2
	fi
	case "$mode" in
		required) return 0 ;;
		disabled) return 1 ;;
	esac
	if [ -n "$SIGNING_PUBLIC_KEY" ]; then
		return 0
	fi
	if [ -n "$SIGNATURE_REQUIRED_FROM" ] && [ "$(semver_compare "$release_version" "$SIGNATURE_REQUIRED_FROM")" -ge 0 ]; then
		return 0
	fi
	return 1
}

wait_service_ready() {
	local service="$1"
	local timeout="$2"
	local expected_version="${3:-}"
	local deadline=$((SECONDS + timeout))
	local stable_since=0
	while [ "$SECONDS" -le "$deadline" ]; do
		if systemctl is-active --quiet "$service" && { [ -z "$expected_version" ] || [ "$(current_agent_version || true)" = "$expected_version" ]; }; then
			if [ "$stable_since" -eq 0 ]; then
				stable_since=$SECONDS
			fi
			if [ $((SECONDS - stable_since)) -ge "$READINESS_STABLE_SECONDS" ]; then
				return 0
			fi
		else
			stable_since=0
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
	if wait_service_ready "$SERVICE_NAME" "$START_TIMEOUT_SECONDS" "$TARGET_VERSION"; then
		say "已重启 $SERVICE_NAME" "restarted $SERVICE_NAME"
		return 0
	fi
	say_err "$SERVICE_NAME 升级后未变为 active，正在回滚" "$SERVICE_NAME did not become active after update; rolling back"
	emit_terminal_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "service did not become active after update"
	emit_upgrade_event "rollback_started" "$CURRENT_VERSION" "$TARGET_VERSION" "service did not become active"
	if [ -x "$BACKUP_PATH" ]; then
		install -m 0755 "$BACKUP_PATH" "$INSTALL_PATH.rollback"
		mv -f "$INSTALL_PATH.rollback" "$INSTALL_PATH"
		if command -v setcap >/dev/null 2>&1; then
			setcap cap_net_raw+ep "$INSTALL_PATH" >/dev/null 2>&1 || true
		fi
		systemctl restart "$SERVICE_NAME" || true
		if wait_service_ready "$SERVICE_NAME" "$START_TIMEOUT_SECONDS" "$CURRENT_VERSION"; then
			emit_terminal_upgrade_event "rollback_succeeded" "$TARGET_VERSION" "$CURRENT_VERSION" "service restored previous binary"
		else
			emit_terminal_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "rollback restart failed"
		fi
	else
		emit_terminal_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "previous binary backup missing"
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

valid_release_version() {
	local value="${1#nodeping-agent/}"
	value="${value#v}"
	[[ "$value" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || return 1
	local without_build="$value" prerelease="" build="" identifier
	local -a identifiers
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
	return 0
}

semver_compare() {
	local left="${1#nodeping-agent/}"
	local right="${2#nodeping-agent/}"
	left="${left#v}"
	right="${right#v}"
	left="${left%%+*}"
	right="${right%%+*}"
	if [[ ! "$left" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then
		return 2
	fi
	local left_major="${BASH_REMATCH[1]}" left_minor="${BASH_REMATCH[2]}" left_patch="${BASH_REMATCH[3]}" left_pre="${BASH_REMATCH[5]:-}"
	if [[ ! "$right" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then
		return 2
	fi
	local right_major="${BASH_REMATCH[1]}" right_minor="${BASH_REMATCH[2]}" right_patch="${BASH_REMATCH[3]}" right_pre="${BASH_REMATCH[5]:-}"
	local left_part right_part index
	for index in major minor patch; do
		case "$index" in
			major) left_part="$left_major"; right_part="$right_major" ;;
			minor) left_part="$left_minor"; right_part="$right_minor" ;;
			patch) left_part="$left_patch"; right_part="$right_patch" ;;
		esac
		if ((10#$left_part < 10#$right_part)); then printf '%s\n' -1; return 0; fi
		if ((10#$left_part > 10#$right_part)); then printf '%s\n' 1; return 0; fi
	done
	if [ -z "$left_pre" ] && [ -z "$right_pre" ]; then printf '%s\n' 0; return 0; fi
	if [ -z "$left_pre" ]; then printf '%s\n' 1; return 0; fi
	if [ -z "$right_pre" ]; then printf '%s\n' -1; return 0; fi
	local -a left_ids right_ids
	IFS=. read -r -a left_ids <<< "$left_pre"
	IFS=. read -r -a right_ids <<< "$right_pre"
	local max_ids="${#left_ids[@]}"
	if [ "${#right_ids[@]}" -gt "$max_ids" ]; then max_ids="${#right_ids[@]}"; fi
	for ((index = 0; index < max_ids; index++)); do
		if [ "$index" -ge "${#left_ids[@]}" ]; then printf '%s\n' -1; return 0; fi
		if [ "$index" -ge "${#right_ids[@]}" ]; then printf '%s\n' 1; return 0; fi
		left_part="${left_ids[$index]}"
		right_part="${right_ids[$index]}"
		[ "$left_part" = "$right_part" ] && continue
		if [[ "$left_part" =~ ^[0-9]+$ ]] && [[ "$right_part" =~ ^[0-9]+$ ]]; then
			if ((10#$left_part < 10#$right_part)); then printf '%s\n' -1; else printf '%s\n' 1; fi
			return 0
		fi
		if [[ "$left_part" =~ ^[0-9]+$ ]]; then printf '%s\n' -1; return 0; fi
		if [[ "$right_part" =~ ^[0-9]+$ ]]; then printf '%s\n' 1; return 0; fi
		if [[ "$left_part" < "$right_part" ]]; then printf '%s\n' -1; else printf '%s\n' 1; fi
		return 0
	done
	printf '%s\n' 0
}

validate_repository() {
	[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] && [[ "$GITHUB_REPOSITORY" != -* ]] && [[ "$GITHUB_REPOSITORY" != */-* ]]
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
		effective="$(curl -fsSLI --connect-timeout 8 --max-time 30 --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null || true)"
	elif command -v wget >/dev/null 2>&1; then
		effective="$(wget --https-only --timeout=30 --tries=1 -qS --max-redirect=10 --spider "$latest_url" 2>&1 | awk '/^  Location: / { value=$2 } END { print value }' || true)"
	fi
	tag="${effective##*/}"
	tag="$(normalize_version "$tag")"
	if [ -n "$tag" ] && [ "$tag" != "latest" ]; then
		printf '%s' "$tag"
		return 0
	fi
	return 1
}

cached_latest_release_version() {
	[ "${GITHUB_REPOSITORY#/}" = "lcy0828/nodeping-agent" ] || return 1
	[ -r "$LATEST_VERSION_FILE" ] || return 1
	local cached
	cached="$(LC_ALL=C head -c 256 "$LATEST_VERSION_FILE" 2>/dev/null || true)"
	[ -n "$cached" ] && [ "${#cached}" -le 128 ] || return 1
	[[ "$cached" != *$'\n'* && "$cached" != *$'\r'* ]] || return 1
	cached="$(normalize_version "$cached")"
	if valid_release_version "$cached" && [ "$cached" != "latest" ]; then
		printf '%s' "$cached"
		return 0
	fi
	return 1
}

latest_release_api_urls() {
	local origin="${GITHUB_API_BASE_URL%/}/repos/${GITHUB_REPOSITORY#/}/releases/latest"
	if [[ "$origin" == https://api.github.com/* ]]; then
		if [ "$DISTRIBUTION_MODE" = "cn" ]; then
			printf 'https://hub.ilatency.com/%s\n%s\n' "$origin" "$origin"
		else
			printf '%s\nhttps://hub.ilatency.com/%s\n' "$origin" "$origin"
		fi
	else
		printf '%s\n' "$origin"
	fi
}

latest_release_version() {
	local dest="$1/latest-release.json"
	local repository="${GITHUB_REPOSITORY#/}"
	local tag api_url
	if tag="$(cached_latest_release_version)"; then
		printf '%s' "$tag"
		return 0
	fi
	while IFS= read -r api_url; do
		if download_quiet "$api_url" "$dest"; then
			tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dest" | head -n 1)"
			tag="$(normalize_version "$tag")"
			if [ -n "$tag" ] && [ "$tag" != "latest" ]; then
				printf '%s' "$tag"
				return 0
			fi
		fi
	done < <(latest_release_api_urls)
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

manifest_artifact_field() {
	local file="$1"
	local artifact_name="$2"
	local field="$3"
	grep -F "\"name\": \"$artifact_name\"" "$file" | sed -n "s/.*\"$field\": \"\([^\"]*\)\".*/\1/p" | head -n 1
}

validate_release_manifest() {
	local file="$1"
	local release_version="$2"
	local artifact_name="$3"
	local artifact_os="$4"
	local artifact_arch="$5"
	local artifact_sha256="$6"
	local manifest_version manifest_os manifest_arch manifest_sha256 manifest_name
	manifest_version="$(json_file_value "$file" version || true)"
	manifest_name="$(manifest_artifact_field "$file" "$artifact_name" name || true)"
	manifest_os="$(manifest_artifact_field "$file" "$artifact_name" os || true)"
	manifest_arch="$(manifest_artifact_field "$file" "$artifact_name" arch || true)"
	manifest_sha256="$(manifest_artifact_field "$file" "$artifact_name" sha256 || true)"
	if [ "$manifest_version" != "$release_version" ] || [ "$manifest_name" != "$artifact_name" ] || \
		[ "$manifest_os" != "$artifact_os" ] || [ "$manifest_arch" != "$artifact_arch" ] || \
		[ "$manifest_sha256" != "$artifact_sha256" ]; then
		say_err "发布 manifest 与请求版本、平台或制品摘要不匹配" "release manifest does not match requested version, platform, or artifact digest"
		return 1
	fi
}

validate_archive() {
	local archive="$1"
	local entry line type binary_count=0
	while IFS= read -r entry; do
		case "$entry" in
			nodeping-agent|nodeping-agent/) ;;
			nodeping-agent/*)
				case "$entry" in *\\*|*/../*|*/..)
					say_err "归档包含不安全路径：$entry" "archive contains unsafe path: $entry"
					return 1
				;; esac
				;;
			*)
				say_err "归档包含不安全路径：$entry" "archive contains unsafe path: $entry"
				return 1
				;;
		esac
		if [ "$entry" = "nodeping-agent/nodeping-agent" ]; then
			binary_count=$((binary_count + 1))
		fi
	done < <(tar -tzf "$archive")
	if [ "$binary_count" -ne 1 ]; then
		say_err "归档必须且只能包含一个 nodeping-agent 二进制" "archive must contain exactly one nodeping-agent binary"
		return 1
	fi
	while IFS= read -r line; do
		type="${line:0:1}"
		case "$type" in
			-|d) ;;
			*)
				say_err "归档不允许包含符号链接、硬链接或设备文件" "archive must not contain symlinks, hard links, or device files"
				return 1
				;;
		esac
	done < <(LC_ALL=C tar -tvzf "$archive")
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

preflight
consume_update_request

ALLOW_INSECURE_HTTP="$(normalize_allow_insecure_http "$ALLOW_INSECURE_HTTP")"
DISTRIBUTION_MODE="$(printf '%s' "$DISTRIBUTION_MODE" | tr '[:upper:]' '[:lower:]')"
case "$DISTRIBUTION_MODE" in
	cn|global) ;;
	*) say_err "NODEPING_AGENT_DISTRIBUTION_MODE 必须为 cn 或 global" "NODEPING_AGENT_DISTRIBUTION_MODE must be cn or global"; exit 2 ;;
esac
REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"
if [ "$REQUESTED_VERSION" != "latest" ] && ! valid_release_version "$REQUESTED_VERSION"; then
	say_err "请求的版本不是有效 SemVer：$REQUESTED_VERSION" "requested version is not valid SemVer: $REQUESTED_VERSION"
	exit 2
fi
if ! validate_repository; then
	say_err "NODEPING_AGENT_GITHUB_REPOSITORY 格式无效" "invalid NODEPING_AGENT_GITHUB_REPOSITORY"
	exit 2
fi
validate_secure_url "$GITHUB_API_BASE_URL" "NODEPING_AGENT_GITHUB_API_BASE_URL"
if [ -n "$BASE_URL" ]; then
	validate_secure_url "$BASE_URL" "NODEPING_AGENT_RELEASE_BASE_URL"
fi
if [ -n "$SERVER_URL" ]; then
	validate_secure_url "$SERVER_URL" "NODEPING_SERVER_URL" "$ALLOW_INSECURE_HTTP"
fi
if ! normalize_signature_mode >/dev/null; then
	say_err "NODEPING_AGENT_REQUIRE_SIGNATURE 配置无效" "invalid NODEPING_AGENT_REQUIRE_SIGNATURE; use required, auto, or disabled"
	exit 2
fi
if [ -n "$SIGNATURE_REQUIRED_FROM" ]; then
	SIGNATURE_REQUIRED_FROM="$(normalize_version "$SIGNATURE_REQUIRED_FROM")"
	if ! valid_release_version "$SIGNATURE_REQUIRED_FROM"; then
		say_err "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM 不是有效 SemVer" "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM is not valid SemVer"
		exit 2
	fi
fi
case "$ALLOW_DOWNGRADE" in 0|1) ;; *) say_err "NODEPING_AGENT_ALLOW_DOWNGRADE 必须为 0 或 1" "NODEPING_AGENT_ALLOW_DOWNGRADE must be 0 or 1"; exit 2 ;; esac
case "$START_TIMEOUT_SECONDS" in ''|*[!0-9]*|0) say_err "启动超时必须为正整数" "start timeout must be a positive integer"; exit 2 ;; esac
case "$READINESS_STABLE_SECONDS" in ''|*[!0-9]*|0) say_err "readiness 稳定窗口必须为正整数" "readiness stable window must be a positive integer"; exit 2 ;; esac
if ! acquire_update_lock; then
	exit 75
fi
trap cleanup_and_report_failure EXIT
CURRENT_VERSION="$(current_agent_version || true)"
TARGET_VERSION="nodeping-agent/$REQUESTED_VERSION"
tmp_dir="$(mktemp -d)"

version="$REQUESTED_VERSION"
if [ "$version" = "latest" ]; then
	UPGRADE_STEP="resolving latest release for $GITHUB_REPOSITORY"
	emit_upgrade_progress 25 "$UPGRADE_STEP"
	version="$(latest_release_version "$tmp_dir")"
fi

if [ -z "$version" ]; then
	UPGRADE_STEP="checking requested release version"
	say_err "发布版本为空" "empty release version"
	exit 2
fi
if ! valid_release_version "$version"; then
	UPGRADE_STEP="validating resolved release version"
	say_err "解析出的发布版本不是有效 SemVer：$version" "resolved release version is not valid SemVer: $version"
	exit 2
fi

if [ -n "$CURRENT_VERSION" ] && valid_release_version "$CURRENT_VERSION"; then
	version_order="$(semver_compare "$version" "$CURRENT_VERSION")"
	if [ "$version_order" -lt 0 ] && [ "$ALLOW_DOWNGRADE" != "1" ]; then
		UPGRADE_STEP="preventing downgrade from $CURRENT_VERSION to nodeping-agent/$version"
		say_err "默认禁止从 $CURRENT_VERSION 降级到 nodeping-agent/$version" "downgrade from $CURRENT_VERSION to nodeping-agent/$version is blocked; set NODEPING_AGENT_ALLOW_DOWNGRADE=1 for an explicit rollback"
		exit 1
	fi
fi

SIGNATURE_REQUIRED=0
if signature_required_for_version "$version"; then
	SIGNATURE_REQUIRED=1
elif [ "$?" -eq 2 ]; then
	exit 2
fi
if [ "$SIGNATURE_REQUIRED" = "1" ] && [ -z "$SIGNING_PUBLIC_KEY" ]; then
	UPGRADE_STEP="enforcing release signatures for $version"
	say_err "此版本要求签名，但未配置 NODEPING_AGENT_MINISIGN_PUBLIC_KEY" "this release requires signatures but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty"
	exit 1
fi
if [ "$SIGNATURE_REQUIRED" = "1" ]; then
	UPGRADE_STEP="enforcing release signatures for $version"
	ensure_minisign || exit 1
fi

TARGET_VERSION="nodeping-agent/$version"

if [ -z "$BASE_URL" ]; then
	BASE_URL="$(default_release_base_url "$version")"
fi
BASE_URL="${BASE_URL%/}"

UPGRADE_STEP="detecting system platform"
emit_upgrade_progress 30 "$UPGRADE_STEP"
os="$(detect_os)"
arch="$(detect_arch)"
artifact="nodeping-agent_${version}_${os}_${arch}.tar.gz"
checksums="nodeping-agent_${version}_checksums.txt"
manifest="nodeping-agent_${version}_manifest.json"

UPGRADE_STEP="downloading and verifying release files for $artifact"
emit_upgrade_progress 40 "$UPGRADE_STEP"
download_verified_release_set "$BASE_URL" "$tmp_dir" "$artifact" "$checksums" "$manifest" "$version" "$os" "$arch" "$SIGNATURE_REQUIRED"
manifest_available="$RELEASE_MANIFEST_AVAILABLE"
if [ "$SIGNATURE_REQUIRED" = "1" ]; then
	UPGRADE_STEP="verifying signed release metadata and $artifact"
	emit_upgrade_progress 55 "$UPGRADE_STEP"
	verify_signature "$tmp_dir/$artifact" "$tmp_dir/$artifact.minisig"
	verify_signature "$tmp_dir/$checksums" "$tmp_dir/$checksums.minisig"
	verify_signature "$tmp_dir/$manifest" "$tmp_dir/$manifest.minisig"
fi

UPGRADE_STEP="checking checksum for $artifact"
emit_upgrade_progress 60 "$UPGRADE_STEP"
expected="$(awk -v file="$artifact" '$2 == file { print $1 }' "$tmp_dir/$checksums")"
if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
	say_err "校验和文件 $checksums 中找不到 $artifact" "checksum for $artifact not found in $checksums"
	exit 1
fi

actual="$(sha256_value "$tmp_dir/$artifact")"
if [ "$actual" != "$expected" ]; then
	say_err "$artifact 校验和不匹配" "checksum mismatch for $artifact"
	exit 1
fi
if [ "$manifest_available" = "1" ]; then
	validate_release_manifest "$tmp_dir/$manifest" "$version" "$artifact" "$os" "$arch" "$actual"
elif [ "$SIGNATURE_REQUIRED" = "1" ]; then
	say_err "签名模式要求发布 manifest" "signed mode requires a release manifest"
	exit 1
fi

UPGRADE_STEP="extracting $artifact"
emit_upgrade_progress 70 "$UPGRADE_STEP"
mkdir -p "$tmp_dir/extract"
validate_archive "$tmp_dir/$artifact"
tar -xzf "$tmp_dir/$artifact" -C "$tmp_dir/extract"
new_bin="$tmp_dir/extract/nodeping-agent/nodeping-agent"
version_file="$tmp_dir/extract/nodeping-agent/VERSION"
if [ ! -f "$new_bin" ] || [ -L "$new_bin" ] || [ ! -x "$new_bin" ]; then
	say_err "$artifact 中未找到 nodeping-agent 二进制" "nodeping-agent binary not found in $artifact"
	exit 1
fi
if [ ! -f "$version_file" ] || [ -L "$version_file" ]; then
	say_err "$artifact 中未找到 VERSION" "VERSION file not found in $artifact"
	exit 1
fi
archive_version="$(normalize_version "$(head -n 1 "$version_file" | tr -d '[:space:]')")"
binary_version="$(normalize_version "$(agent_binary_release_version "$new_bin" || true)")"
if [ "$archive_version" != "$version" ] || [ "$binary_version" != "$version" ]; then
	say_err "请求版本、归档 VERSION 与二进制版本不一致" "requested version, archive VERSION, and binary version do not match"
	exit 1
fi

if [ -x "$ACTIVE_BINARY" ] && cmp -s "$new_bin" "$ACTIVE_BINARY"; then
	say "nodeping-agent 已是最新版本：$version" "nodeping-agent is already up to date: $version"
	emit_terminal_upgrade_event "up_to_date" "$CURRENT_VERSION" "$TARGET_VERSION" "binary already matches requested version"
	exit 0
fi

UPGRADE_STEP="installing release $version"
emit_upgrade_progress 80 "$UPGRADE_STEP"

backup_source="$ACTIVE_BINARY"
if [ ! -x "$backup_source" ]; then
	backup_source="$INSTALL_PATH"
fi
if [ -x "$backup_source" ]; then
	install -m 0755 "$backup_source" "$BACKUP_PATH"
	say "已备份旧版 nodeping-agent 到 $BACKUP_PATH" "backed up previous nodeping-agent to $BACKUP_PATH"
fi

install -m 0755 "$new_bin" "$INSTALL_PATH.new"
mv -f "$INSTALL_PATH.new" "$INSTALL_PATH"
if command -v setcap >/dev/null 2>&1; then
	setcap cap_net_raw+ep "$INSTALL_PATH" >/dev/null 2>&1 || true
fi
say "已安装 nodeping-agent $version 到 $INSTALL_PATH" "installed nodeping-agent $version to $INSTALL_PATH"

if [ -n "$ACTIVATION_FILE" ]; then
	mkdir -p "$(dirname "$ACTIVATION_FILE")"
	activation_tmp="${ACTIVATION_FILE}.new.$$"
	printf '%s\n' "$TARGET_VERSION" > "$activation_tmp"
	chmod 0600 "$activation_tmp"
	mv -f "$activation_tmp" "$ACTIVATION_FILE"
	say "已写入容器激活标记：$ACTIVATION_FILE" "wrote container activation marker: $ACTIVATION_FILE"
fi

UPGRADE_STEP="restarting $SERVICE_NAME"
emit_upgrade_progress 90 "$UPGRADE_STEP"
if restart_with_rollback; then
	if [ -n "$ACTIVATION_FILE" ]; then
		emit_terminal_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$TARGET_VERSION" "update staged; container restart pending"
	else
		emit_terminal_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$TARGET_VERSION" "update completed"
	fi
else
	exit 1
fi
