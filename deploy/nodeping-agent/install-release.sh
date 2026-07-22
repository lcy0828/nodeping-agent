#!/usr/bin/env bash
set -euo pipefail

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

if [ "$(id -u)" -ne 0 ]; then
	say_err "请以 root 运行安装器，例如：curl ... | sudo env NODEPING_SERVER_URL=... NODEPING_TOKEN=... bash" "run this installer as root, for example: curl ... | sudo env NODEPING_SERVER_URL=... NODEPING_TOKEN=... bash"
	exit 1
fi

SERVER_URL="${NODEPING_SERVER_URL:-}"
BINDING_TOKEN="${NODEPING_TOKEN:-}"
ALLOW_INSECURE_HTTP="${NODEPING_AGENT_ALLOW_INSECURE_HTTP:-false}"
CUSTOM_RELEASE_BASE_URL="${NODEPING_AGENT_RELEASE_BASE_URL:-}"
RELEASE_BASE_URL="$CUSTOM_RELEASE_BASE_URL"
REQUESTED_VERSION="${NODEPING_AGENT_VERSION:-latest}"
GITHUB_REPOSITORY="${NODEPING_AGENT_GITHUB_REPOSITORY:-lcy0828/nodeping-agent}"
GITHUB_API_BASE_URL="${NODEPING_AGENT_GITHUB_API_BASE_URL:-https://api.github.com}"
SIGNING_PUBLIC_KEY="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
REQUIRE_SIGNATURE="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
SIGNATURE_REQUIRED_FROM="${NODEPING_AGENT_SIGNATURE_REQUIRED_FROM:-}"
MINISIGN_BIN="${NODEPING_AGENT_MINISIGN_BIN:-/opt/nodeping-agent/minisign}"
# Upstream 0.12 Linux archive, verified against the public release key documented by jedisct1/minisign.
MINISIGN_BOOTSTRAP_VERSION="0.12"
MINISIGN_BOOTSTRAP_ARCHIVE_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
DISTRIBUTION_MODE="${NODEPING_AGENT_DISTRIBUTION_MODE:-cn}"
ETC_DIR="${ETC_DIR:-/etc/nodeping-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/nodeping-agent}"
RELEASE_PROXY_FILE="${NODEPING_AGENT_RELEASE_PROXY_FILE:-$STATE_DIR/release-proxies.tsv}"
LATEST_VERSION_FILE="${NODEPING_AGENT_LATEST_VERSION_FILE:-$STATE_DIR/latest-version}"

existing_env_value() {
	local key="$1"
	local file="$ETC_DIR/nodeping-agent.env"
	if [ ! -f "$file" ]; then
		return 0
	fi
	awk -F= -v key="$key" '$1 == key { value=$0; sub(/^[^=]*=/, "", value); gsub(/^["'\'']|["'\'']$/, "", value); print value; exit }' "$file"
}

default_agent_id() {
	if [ -r "$STATE_DIR/agent-id" ]; then
		local existing
		existing="$(tr -d '[:space:]' < "$STATE_DIR/agent-id")"
		case "$existing" in
			agent-*) printf '%s\n' "$existing"; return 0 ;;
		esac
	fi
	if command -v uuidgen >/dev/null 2>&1; then
		printf 'agent-%s\n' "$(uuidgen | tr '[:upper:]' '[:lower:]')"
		return 0
	fi
	if [ -r /proc/sys/kernel/random/uuid ]; then
		printf 'agent-%s\n' "$(tr -d '[:space:]' < /proc/sys/kernel/random/uuid)"
		return 0
	fi
	if command -v openssl >/dev/null 2>&1; then
		local hex
		hex="$(openssl rand -hex 16)"
		printf 'agent-%s-%s-4%s-%s%s-%s\n' \
			"$(printf '%s' "$hex" | cut -c1-8)" \
			"$(printf '%s' "$hex" | cut -c9-12)" \
			"$(printf '%s' "$hex" | cut -c14-16)" \
			"$(printf '%x' $(((0x$(printf '%s' "$hex" | cut -c17-17) & 3) | 8)))" \
			"$(printf '%s' "$hex" | cut -c18-20)" \
			"$(printf '%s' "$hex" | cut -c21-32)"
		return 0
	fi
	say_err "无法生成安全的 Agent ID；请安装 uuidgen 或 openssl" "cannot generate a secure agent ID; install uuidgen or openssl"
	return 1
}

AGENT_ID="${NODEPING_AGENT_ID:-$(existing_env_value NODEPING_AGENT_ID)}"
if [ -z "$AGENT_ID" ]; then
	AGENT_ID="$(default_agent_id)"
fi
AGENT_NAME="${NODEPING_AGENT_NAME:-$(hostname)}"

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		exit 1
	fi
}

preflight() {
	detect_os >/dev/null
	detect_arch >/dev/null
	for command in tar awk grep sed install mktemp systemctl; do
		require_command "$command"
	done
	if [ "$(uname -s | tr '[:upper:]' '[:lower:]')" != "linux" ] || [ ! -d /run/systemd/system ] || ! systemctl list-unit-files >/dev/null 2>&1; then
		say_err "systemd 安装脚本仅支持正在运行 systemd 的 Linux；当前系统不会进行下载或安装，请返回页面选择 Docker Compose 指引" "the systemd installer requires Linux with systemd running; nothing was downloaded or installed; return to the Docker Compose guide"
		exit 1
	fi
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		say_err "需要安装 curl 或 wget" "curl or wget is required"
		exit 1
	fi
	if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
		say_err "需要安装 sha256sum 或 shasum" "sha256sum or shasum is required"
		exit 1
	fi
	if ! command -v ping >/dev/null 2>&1; then
		say_err "未找到 ping 命令；运行 ICMP 检测前请安装 iputils-ping/iputils" "ping command not found; install iputils-ping/iputils before running ICMP checks"
		exit 1
	fi
}

is_loopback_http_url() {
	local value="$1"
	[[ "$value" =~ ^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

validate_secure_url() {
	local value="$1"
	local name="$2"
	local allow_insecure_http="${3:-false}"
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

download_with_curl() {
	local source_url="$1"
	local destination="$2"
	local timeout_seconds="${3:-60}"
	if [[ "$source_url" == https://* ]]; then
		curl -fsSL --connect-timeout 8 --max-time "$timeout_seconds" --proto '=https' --proto-redir '=https' "$source_url" -o "$destination"
	else
		curl -fsSL --connect-timeout 8 --max-time "$timeout_seconds" --proto '=http,https' --proto-redir '=https' "$source_url" -o "$destination"
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
	local source_url="$1"
	local destination="$2"
	local timeout_seconds="${3:-60}"
	if [[ "$source_url" == https://* ]]; then
		if command -v timeout >/dev/null 2>&1; then
			timeout "$timeout_seconds" wget --https-only --timeout="$timeout_seconds" --tries=1 -qO "$destination" "$source_url"
		else
			wget --https-only --timeout="$timeout_seconds" --tries=1 -qO "$destination" "$source_url"
		fi
	else
		if command -v timeout >/dev/null 2>&1; then
			timeout "$timeout_seconds" wget --max-redirect=0 --timeout="$timeout_seconds" --tries=1 -qO "$destination" "$source_url"
		else
			wget --max-redirect=0 --timeout="$timeout_seconds" --tries=1 -qO "$destination" "$source_url"
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
	local source_url="$1"
	[[ "$source_url" == "https://github.com/${GITHUB_REPOSITORY#/}/releases/"* ]]
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
	local source_url="$1" destination="$2" timeout_seconds="${3:-60}"
	if command -v curl >/dev/null 2>&1; then
		download_with_curl "$source_url" "$destination" "$timeout_seconds"
	else
		download_with_wget "$source_url" "$destination" "$timeout_seconds"
	fi
}

download_file_is_usable() {
	local destination="$1"
	[ -s "$destination" ] && ! LC_ALL=C head -c 512 "$destination" | LC_ALL=C grep -aEiq '^[[:space:]]*(<!DOCTYPE html|<html)'
}

download_quiet() {
	local source_url="$1"
	local destination="$2"
	validate_secure_url "$source_url" "download URL" >/dev/null 2>&1 || return 1
	download_raw "$source_url" "$destination" 30 2>/dev/null && download_file_is_usable "$destination"
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
	local source_id source_mode source_base source_query _extra origin expected actual manifest_available signed_file
	local metadata_timeout artifact_timeout source_deadline proxy_deadline=$((SECONDS + 300))
	RELEASE_MANIFEST_AVAILABLE=0
	while IFS=$'\t' read -r source_id source_mode source_base source_query _extra || [ -n "${source_id:-}" ]; do
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

sha256_value() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

verify_signature() {
	local artifact_path="$1"
	local signature_path="$2"
	local verifier
	if [ -z "$SIGNING_PUBLIC_KEY" ]; then
		say_err "签名校验需要 NODEPING_AGENT_MINISIGN_PUBLIC_KEY" "signature verification requires NODEPING_AGENT_MINISIGN_PUBLIC_KEY"
		return 1
	fi
	if ! verifier="$(find_minisign)"; then
		say_err "找不到可用的 minisign 验证器" "no usable minisign verifier was found"
		return 1
	fi
	"$verifier" -Vm "$artifact_path" -x "$signature_path" -P "$SIGNING_PUBLIC_KEY"
}

find_minisign() {
	local candidate
	if [ -x "$MINISIGN_BIN" ] && [ ! -d "$MINISIGN_BIN" ]; then
		candidate="$MINISIGN_BIN"
	elif command -v minisign >/dev/null 2>&1; then
		candidate="$(command -v minisign)"
	else
		return 1
	fi
	"$candidate" -v >/dev/null 2>&1 || return 1
	printf '%s\n' "$candidate"
}

download_bootstrap_minisign() {
	local directory="$1"
	local destination="$directory/minisign-${MINISIGN_BOOTSTRAP_VERSION}-linux.tar.gz"
	local origin="https://github.com/jedisct1/minisign/releases/download/${MINISIGN_BOOTSTRAP_VERSION}/minisign-${MINISIGN_BOOTSTRAP_VERSION}-linux.tar.gz"
	local source_id source_mode source_base source_query _extra actual timeout_seconds source_deadline
	local proxy_deadline=$((SECONDS + 120))
	while IFS=$'\t' read -r source_id source_mode source_base source_query _extra || [ -n "${source_id:-}" ]; do
		[ -n "${source_id:-}" ] || continue
		if [ "$source_mode" = "direct" ]; then
			timeout_seconds=30
			source_deadline=0
		else
			[[ "$source_id" =~ ^[0-9]+$ ]] || continue
			[ "$SECONDS" -lt "$proxy_deadline" ] || continue
			timeout_seconds=20
			source_deadline="$proxy_deadline"
		fi
		if download_release_source_file "$source_mode" "$source_base" "$source_query" "$origin" "$destination" "$timeout_seconds" "$source_deadline"; then
			actual="$(sha256_value "$destination")"
			if [ "$actual" = "$MINISIGN_BOOTSTRAP_ARCHIVE_SHA256" ]; then
				return 0
			fi
		fi
	done < <(release_download_sources)
	rm -f "$destination"
	return 1
}

install_bootstrap_minisign() {
	local directory="$1"
	local upstream_arch member expected_binary_sha256 archive extracted target_tmp actual
	case "$(uname -m)" in
		x86_64|amd64)
			upstream_arch="x86_64"
			expected_binary_sha256="2c74dffcc1c9a5ee55957c60971998ace2b89f22585631594ec2152c588af8db"
			;;
		aarch64|arm64)
			upstream_arch="aarch64"
			expected_binary_sha256="cec9f88be8c975af76854a53b4d49c3d257feae38d916edb0d16fb55aacd3000"
			;;
		*) return 1 ;;
	esac
	say "本机未安装 minisign，正在获取经过固定哈希校验的官方验证器" "minisign is not installed; fetching the official verifier protected by pinned hashes"
	download_bootstrap_minisign "$directory" || return 1
	archive="$directory/minisign-${MINISIGN_BOOTSTRAP_VERSION}-linux.tar.gz"
	member="minisign-linux/$upstream_arch/minisign"
	extracted="$directory/minisign-${MINISIGN_BOOTSTRAP_VERSION}-$upstream_arch"
	tar -xOzf "$archive" "$member" > "$extracted" || return 1
	actual="$(sha256_value "$extracted")"
	[ "$actual" = "$expected_binary_sha256" ] || return 1
	chmod 0755 "$extracted"
	"$extracted" -v >/dev/null 2>&1 || return 1
	install -d -m 0755 "$(dirname "$MINISIGN_BIN")"
	target_tmp="${MINISIGN_BIN}.new.$$"
	install -m 0755 "$extracted" "$target_tmp"
	"$target_tmp" -v >/dev/null 2>&1 || { rm -f "$target_tmp"; return 1; }
	mv -f "$target_tmp" "$MINISIGN_BIN"
	say "已安装 NodePing 管理的 minisign 验证器" "installed the NodePing-managed minisign verifier"
}

install_minisign_package() {
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
}

ensure_minisign() {
	local directory="$1"
	if find_minisign >/dev/null; then
		return 0
	fi
	if install_bootstrap_minisign "$directory" && find_minisign >/dev/null; then
		return 0
	fi
	say "无法使用固定哈希的静态验证器，正在尝试系统包管理器" "the pinned static verifier is unavailable; trying the system package manager"
	install_minisign_package
	if find_minisign >/dev/null; then
		return 0
	fi
	say_err "无法准备 minisign 验证器；发布签名校验未降级" "failed to prepare a minisign verifier; release signature verification was not downgraded"
	return 1
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
	if [[ ! "$left" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then return 2; fi
	local left_major="${BASH_REMATCH[1]}" left_minor="${BASH_REMATCH[2]}" left_patch="${BASH_REMATCH[3]}" left_pre="${BASH_REMATCH[5]:-}"
	if [[ ! "$right" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then return 2; fi
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
	if ! mode="$(normalize_signature_mode)"; then return 2; fi
	case "$mode" in
		required) return 0 ;;
		disabled) return 1 ;;
	esac
	if [ -n "$SIGNING_PUBLIC_KEY" ]; then return 0; fi
	if [ -n "$SIGNATURE_REQUIRED_FROM" ] && [ "$(semver_compare "$release_version" "$SIGNATURE_REQUIRED_FROM")" -ge 0 ]; then return 0; fi
	return 1
}

validate_repository() {
	[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] && [[ "$GITHUB_REPOSITORY" != -* ]] && [[ "$GITHUB_REPOSITORY" != */-* ]]
}

default_release_base_url() {
	local version="$1"
	printf 'https://github.com/%s/releases/download/%s' "${GITHUB_REPOSITORY#/}" "$version"
}

latest_redirect_version() {
	local latest_url="https://github.com/${GITHUB_REPOSITORY#/}/releases/latest"
	local effective tag
	if command -v curl >/dev/null 2>&1; then
		effective="$(curl -fsSLI --connect-timeout 8 --max-time 30 --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null || true)"
	else
		effective="$(wget --https-only --timeout=30 --tries=1 -qS --max-redirect=10 --spider "$latest_url" 2>&1 | awk '/^  Location: / { value=$2 } END { print value }' || true)"
	fi
	tag="$(normalize_version "${effective##*/}")"
	if [ -n "$tag" ] && [ "$tag" != "latest" ]; then printf '%s' "$tag"; return 0; fi
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
	local destination="$1/latest-release.json"
	local tag api_url
	while IFS= read -r api_url; do
		if download_quiet "$api_url" "$destination"; then
			tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$destination" | head -n 1)"
			tag="$(normalize_version "$tag")"
			if [ -n "$tag" ] && [ "$tag" != "latest" ]; then printf '%s' "$tag"; return 0; fi
		fi
	done < <(latest_release_api_urls)
	if tag="$(latest_redirect_version)"; then printf '%s' "$tag"; return 0; fi
	say_err "无法从 GitHub API 或 latest 跳转解析最新版本：$GITHUB_REPOSITORY" "failed to resolve latest release from GitHub API or latest redirect for $GITHUB_REPOSITORY"
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
	grep -F "\"name\": \"$artifact_name\"" "$file" | sed -n "s/.*\"$field\": \"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

validate_release_manifest() {
	local file="$1" release_version="$2" artifact_name="$3" artifact_os="$4" artifact_arch="$5" artifact_sha256="$6"
	local manifest_version manifest_name manifest_os manifest_arch manifest_sha256
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
				say_err "归档包含预期目录以外的路径：$entry" "archive contains a path outside the expected directory: $entry"
				return 1
				;;
		esac
		if [ "$entry" = "nodeping-agent/nodeping-agent" ]; then binary_count=$((binary_count + 1)); fi
	done < <(tar -tzf "$archive")
	if [ "$binary_count" -ne 1 ]; then
		say_err "归档必须且只能包含一个 nodeping-agent 二进制" "archive must contain exactly one nodeping-agent binary"
		return 1
	fi
	while IFS= read -r line; do
		type="${line:0:1}"
		case "$type" in -|d) ;; *)
			say_err "归档不允许包含符号链接、硬链接或设备文件" "archive must not contain symlinks, hard links, or device files"
			return 1
		;; esac
	done < <(LC_ALL=C tar -tvzf "$archive")
}

detect_os() {
	case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
		linux) echo linux ;;
		*) say_err "systemd 安装器不支持当前系统：$(uname -s)" "unsupported OS for systemd installer: $(uname -s)"; return 1 ;;
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

agent_binary_release_version() {
	local path="$1"
	"$path" -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/\1/p' | head -n 1
}

validate_env_value() {
	local name="$1" value="$2"
	if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
		say_err "$name 包含不允许的控制字符" "$name contains disallowed control characters"
		return 1
	fi
}

env_quote() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g; s/[$`]/\\&/g'
}

if [ -z "$SERVER_URL" ] || [ -z "$BINDING_TOKEN" ]; then
	say_err "必须提供 NODEPING_SERVER_URL 和 NODEPING_TOKEN" "NODEPING_SERVER_URL and NODEPING_TOKEN are required"
	exit 2
fi

preflight
ALLOW_INSECURE_HTTP="$(normalize_allow_insecure_http "$ALLOW_INSECURE_HTTP")"
DISTRIBUTION_MODE="$(printf '%s' "$DISTRIBUTION_MODE" | tr '[:upper:]' '[:lower:]')"
case "$DISTRIBUTION_MODE" in
	cn|global) ;;
	*) say_err "NODEPING_AGENT_DISTRIBUTION_MODE 必须为 cn 或 global" "NODEPING_AGENT_DISTRIBUTION_MODE must be cn or global"; exit 2 ;;
esac
validate_secure_url "$SERVER_URL" "NODEPING_SERVER_URL" "$ALLOW_INSECURE_HTTP"
validate_secure_url "$GITHUB_API_BASE_URL" "NODEPING_AGENT_GITHUB_API_BASE_URL"
if [ -n "$RELEASE_BASE_URL" ]; then validate_secure_url "$RELEASE_BASE_URL" "NODEPING_AGENT_RELEASE_BASE_URL"; fi
if ! validate_repository; then say_err "NODEPING_AGENT_GITHUB_REPOSITORY 格式无效" "invalid NODEPING_AGENT_GITHUB_REPOSITORY"; exit 2; fi
if ! normalize_signature_mode >/dev/null; then say_err "NODEPING_AGENT_REQUIRE_SIGNATURE 配置无效" "invalid NODEPING_AGENT_REQUIRE_SIGNATURE; use required, auto, or disabled"; exit 2; fi
for item in "NODEPING_TOKEN:$BINDING_TOKEN" "NODEPING_AGENT_ID:$AGENT_ID" "NODEPING_AGENT_NAME:$AGENT_NAME"; do
	validate_env_value "${item%%:*}" "${item#*:}"
done
validate_env_value "NODEPING_AGENT_RELEASE_PROXY_FILE" "$RELEASE_PROXY_FILE"
validate_env_value "NODEPING_AGENT_LATEST_VERSION_FILE" "$LATEST_VERSION_FILE"

REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"
if [ "$REQUESTED_VERSION" != "latest" ] && ! valid_release_version "$REQUESTED_VERSION"; then
	say_err "请求的版本不是有效 SemVer：$REQUESTED_VERSION" "requested version is not valid SemVer: $REQUESTED_VERSION"
	exit 2
fi
if [ -n "$SIGNATURE_REQUIRED_FROM" ]; then
	SIGNATURE_REQUIRED_FROM="$(normalize_version "$SIGNATURE_REQUIRED_FROM")"
	if ! valid_release_version "$SIGNATURE_REQUIRED_FROM"; then
		say_err "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM 不是有效 SemVer" "NODEPING_AGENT_SIGNATURE_REQUIRED_FROM is not valid SemVer"
		exit 2
	fi
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
version="$REQUESTED_VERSION"
if [ "$version" = "latest" ]; then version="$(latest_release_version "$tmp_dir")"; fi
if ! valid_release_version "$version"; then
	say_err "解析出的发布版本不是有效 SemVer：$version" "resolved release version is not valid SemVer: $version"
	exit 2
fi

SIGNATURE_REQUIRED=0
if signature_required_for_version "$version"; then
	SIGNATURE_REQUIRED=1
elif [ "$?" -eq 2 ]; then
	exit 2
fi
if [ "$SIGNATURE_REQUIRED" = "1" ] && [ -z "$SIGNING_PUBLIC_KEY" ]; then
	say_err "此版本要求签名，但未配置 NODEPING_AGENT_MINISIGN_PUBLIC_KEY" "this release requires signatures but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty"
	exit 1
fi
if [ "$SIGNATURE_REQUIRED" = "1" ]; then
	ensure_minisign "$tmp_dir" || exit 1
fi

if [ -z "$RELEASE_BASE_URL" ]; then RELEASE_BASE_URL="$(default_release_base_url "$version")"; fi
RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"
os="$(detect_os)"
arch="$(detect_arch)"
artifact="nodeping-agent_${version}_${os}_${arch}.tar.gz"
checksums="nodeping-agent_${version}_checksums.txt"
manifest="nodeping-agent_${version}_manifest.json"

download_verified_release_set "$RELEASE_BASE_URL" "$tmp_dir" "$artifact" "$checksums" "$manifest" "$version" "$os" "$arch" "$SIGNATURE_REQUIRED"
manifest_available="$RELEASE_MANIFEST_AVAILABLE"
if [ "$SIGNATURE_REQUIRED" = "1" ]; then
	for signed_file in "$artifact" "$checksums" "$manifest"; do
		verify_signature "$tmp_dir/$signed_file" "$tmp_dir/$signed_file.minisig"
	done
fi

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
fi

validate_archive "$tmp_dir/$artifact"
mkdir -p "$tmp_dir/extract"
tar -xzf "$tmp_dir/$artifact" -C "$tmp_dir/extract"
package_dir="$tmp_dir/extract/nodeping-agent"
source_bin="$package_dir/nodeping-agent"
version_file="$package_dir/VERSION"
if [ ! -f "$source_bin" ] || [ -L "$source_bin" ] || [ ! -x "$source_bin" ] || [ ! -f "$version_file" ] || [ -L "$version_file" ]; then
	say_err "发布归档缺少有效的二进制或 VERSION 文件" "release archive is missing a valid binary or VERSION file"
	exit 1
fi
archive_version="$(normalize_version "$(head -n 1 "$version_file" | tr -d '[:space:]')")"
binary_version="$(normalize_version "$(agent_binary_release_version "$source_bin" || true)")"
if [ "$archive_version" != "$version" ] || [ "$binary_version" != "$version" ]; then
	say_err "请求版本、归档 VERSION 与二进制版本不一致" "requested version, archive VERSION, and binary version do not match"
	exit 1
fi

install -d -m 0755 "$ETC_DIR"
install -m 0600 /dev/null "$ETC_DIR/nodeping-agent.env"
{
	printf 'NODEPING_SERVER_URL="%s"\n' "$(env_quote "$SERVER_URL")"
	printf 'NODEPING_AGENT_ALLOW_INSECURE_HTTP="%s"\n' "$(env_quote "$ALLOW_INSECURE_HTTP")"
	printf 'NODEPING_TOKEN="%s"\n' "$(env_quote "$BINDING_TOKEN")"
	printf 'NODEPING_AGENT_ID="%s"\n' "$(env_quote "$AGENT_ID")"
	printf 'NODEPING_AGENT_NAME="%s"\n' "$(env_quote "$AGENT_NAME")"
	printf 'NODEPING_AGENT_DISTRIBUTION_MODE="%s"\n' "$(env_quote "$DISTRIBUTION_MODE")"
	printf 'NODEPING_INSTALL_MODE="binary"\n'
	printf 'NODEPING_AGENT_TOKEN_FILE="%s/agent-token"\n' "$(env_quote "$STATE_DIR")"
	printf 'NODEPING_AGENT_RELEASE_PROXY_FILE="%s"\n' "$(env_quote "$RELEASE_PROXY_FILE")"
	printf 'NODEPING_AGENT_LATEST_VERSION_FILE="%s"\n' "$(env_quote "$LATEST_VERSION_FILE")"
	printf 'NODEPING_HEARTBEAT_INTERVAL="%s"\n' "$(env_quote "${NODEPING_HEARTBEAT_INTERVAL:-20s}")"
	printf 'NODEPING_PUBLIC_IP_INTERVAL="%s"\n' "$(env_quote "${NODEPING_PUBLIC_IP_INTERVAL:-10m}")"
	printf 'NODEPING_CONCURRENCY="%s"\n' "$(env_quote "${NODEPING_CONCURRENCY:-10}")"
	printf 'NODEPING_SHUTDOWN_DRAIN_TIMEOUT="%s"\n' "$(env_quote "${NODEPING_SHUTDOWN_DRAIN_TIMEOUT:-15s}")"
	printf 'NODEPING_AGENT_UPGRADE_MODE="request_file"\n'
	printf 'NODEPING_AGENT_UPGRADE_REQUEST_FILE="%s/update-request.json"\n' "$(env_quote "$STATE_DIR")"
} > "$ETC_DIR/nodeping-agent.env"
chmod 0600 "$ETC_DIR/nodeping-agent.env"

{
	printf 'NODEPING_AGENT_GITHUB_REPOSITORY="%s"\n' "$(env_quote "$GITHUB_REPOSITORY")"
	printf 'NODEPING_AGENT_GITHUB_API_BASE_URL="%s"\n' "$(env_quote "$GITHUB_API_BASE_URL")"
	printf 'NODEPING_AGENT_DISTRIBUTION_MODE="%s"\n' "$(env_quote "$DISTRIBUTION_MODE")"
	printf 'NODEPING_AGENT_RELEASE_BASE_URL="%s"\n' "$(env_quote "$CUSTOM_RELEASE_BASE_URL")"
	printf 'NODEPING_AGENT_VERSION="latest"\n'
	printf 'NODEPING_AGENT_LATEST_VERSION_FILE="%s"\n' "$(env_quote "$LATEST_VERSION_FILE")"
	printf 'NODEPING_AGENT_INSTALL_PATH="/opt/nodeping-agent/nodeping-agent"\n'
	printf 'NODEPING_AGENT_SERVICE="nodeping-agent.service"\n'
	printf 'NODEPING_AGENT_RESTART="1"\n'
	printf 'NODEPING_AGENT_MINISIGN_PUBLIC_KEY="%s"\n' "$(env_quote "$SIGNING_PUBLIC_KEY")"
	printf 'NODEPING_AGENT_REQUIRE_SIGNATURE="%s"\n' "$(env_quote "$REQUIRE_SIGNATURE")"
	printf 'NODEPING_AGENT_SIGNATURE_REQUIRED_FROM="%s"\n' "$(env_quote "$SIGNATURE_REQUIRED_FROM")"
	printf 'NODEPING_AGENT_ALLOW_DOWNGRADE="0"\n'
	printf 'NODEPING_AGENT_READINESS_STABLE_SECONDS="5"\n'
	printf 'NODEPING_AGENT_UPDATE_REQUEST_FILE="%s/update-request.json"\n' "$(env_quote "$STATE_DIR")"
} > "$ETC_DIR/nodeping-agent-update.env"
chmod 0600 "$ETC_DIR/nodeping-agent-update.env"

ENABLE_UPDATER=1 "$package_dir/install-systemd.sh" "$source_bin"
if [ -x /opt/nodeping-agent/nodeping-agent ]; then
	say "正在执行 Agent 环境自检" "running agent dependency doctor"
	doctor_dir="$(mktemp -d)"
	if NODEPING_INSTALL_MODE=binary /opt/nodeping-agent/nodeping-agent --doctor --json >"$doctor_dir/result.json" 2>"$doctor_dir/error.log"; then
		NODEPING_INSTALL_MODE=binary /opt/nodeping-agent/nodeping-agent doctor || true
	else
		cat "$doctor_dir/error.log" >&2 || true
		say_err "Agent 自检存在失败项，请根据上方提示修复依赖" "agent doctor reported failures; fix dependencies shown above"
	fi
	rm -rf "$doctor_dir"
fi
say "nodeping-agent 已安装，自动升级已启用" "nodeping-agent installed and auto update timer enabled"
