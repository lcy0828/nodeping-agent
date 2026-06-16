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
CUSTOM_RELEASE_BASE_URL="${NODEPING_AGENT_RELEASE_BASE_URL:-}"
RELEASE_BASE_URL="$CUSTOM_RELEASE_BASE_URL"
REQUESTED_VERSION="${NODEPING_AGENT_VERSION:-latest}"
GITHUB_REPOSITORY="${NODEPING_AGENT_GITHUB_REPOSITORY:-lcy0828/nodeping-agent}"
GITHUB_API_BASE_URL="${NODEPING_AGENT_GITHUB_API_BASE_URL:-https://api.github.com}"
default_agent_id() {
	hostname | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-' | sed 's/^-*//; s/-*$//' | awk 'NF { print; exit } END { if (NR == 0) print "nodeping-agent" }'
}

AGENT_ID="${NODEPING_AGENT_ID:-$(default_agent_id)}"
AGENT_NAME="${NODEPING_AGENT_NAME:-$(hostname)}"
ETC_DIR="${ETC_DIR:-/etc/nodeping-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/nodeping-agent}"

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		exit 1
	fi
}

preflight() {
	require_command tar
	require_command awk
	require_command systemctl
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		say_err "需要安装 curl 或 wget" "curl or wget is required"
		exit 1
	fi
	if ! command -v ping >/dev/null 2>&1; then
		say_err "未找到 ping 命令；运行 ICMP 检测前请安装 iputils-ping/iputils" "ping command not found; install iputils-ping/iputils before running ICMP checks"
		exit 1
	fi
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
	local public_key="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
	local require_signature="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
	if [ -z "$public_key" ]; then
		case "$(printf '%s' "$require_signature" | tr '[:upper:]' '[:lower:]')" in
			1|true|yes|on)
			say_err "已要求签名校验，但 NODEPING_AGENT_MINISIGN_PUBLIC_KEY 为空" "NODEPING_AGENT_REQUIRE_SIGNATURE=1 but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty"
			return 1
			;;
		esac
		return 0
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		say_err "配置 NODEPING_AGENT_MINISIGN_PUBLIC_KEY 时需要安装 minisign" "minisign is required when NODEPING_AGENT_MINISIGN_PUBLIC_KEY is configured"
		return 1
	fi
	minisign -Vm "$artifact_path" -x "$signature_path" -P "$public_key"
}

signature_required() {
	local public_key="${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}"
	local require_signature="${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}"
	case "$(printf '%s' "$require_signature" | tr '[:upper:]' '[:lower:]')" in
		1|true|yes|on) return 0 ;;
		auto) [ -n "$public_key" ] && return 0 || return 1 ;;
		*) return 1 ;;
	esac
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

env_quote() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g'
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

if [ -z "$SERVER_URL" ] || [ -z "$BINDING_TOKEN" ]; then
	say_err "必须提供 NODEPING_SERVER_URL 和 NODEPING_TOKEN" "NODEPING_SERVER_URL and NODEPING_TOKEN are required"
	exit 2
fi

REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"

preflight

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

if [ -z "$RELEASE_BASE_URL" ]; then
	RELEASE_BASE_URL="$(default_release_base_url "$version")"
fi
RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"

os="$(detect_os)"
arch="$(detect_arch)"
artifact="nodeping-agent_${version}_${os}_${arch}.tar.gz"
checksums="nodeping-agent_${version}_checksums.txt"
download "$RELEASE_BASE_URL/$artifact" "$tmp_dir/$artifact"
download "$RELEASE_BASE_URL/$checksums" "$tmp_dir/$checksums"
if [ -n "${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}" ] || signature_required; then
	download "$RELEASE_BASE_URL/$artifact.minisig" "$tmp_dir/$artifact.minisig"
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

tar -xzf "$tmp_dir/$artifact" -C "$tmp_dir"
install -d -m 0755 "$ETC_DIR"
install -m 0600 /dev/null "$ETC_DIR/nodeping-agent.env"
{
	printf 'NODEPING_SERVER_URL="%s"\n' "$(env_quote "$SERVER_URL")"
	printf 'NODEPING_TOKEN="%s"\n' "$(env_quote "$BINDING_TOKEN")"
	printf 'NODEPING_AGENT_ID="%s"\n' "$(env_quote "$AGENT_ID")"
	printf 'NODEPING_AGENT_NAME="%s"\n' "$(env_quote "$AGENT_NAME")"
	printf 'NODEPING_AGENT_TOKEN_FILE="%s/agent-token"\n' "$(env_quote "$STATE_DIR")"
	printf 'NODEPING_HEARTBEAT_INTERVAL="%s"\n' "$(env_quote "${NODEPING_HEARTBEAT_INTERVAL:-20s}")"
	printf 'NODEPING_PUBLIC_IP_INTERVAL="%s"\n' "$(env_quote "${NODEPING_PUBLIC_IP_INTERVAL:-10m}")"
	printf 'NODEPING_CONCURRENCY="%s"\n' "$(env_quote "${NODEPING_CONCURRENCY:-3}")"
	printf 'NODEPING_AGENT_UPGRADE_MODE="request_file"\n'
	printf 'NODEPING_AGENT_UPGRADE_REQUEST_FILE="%s/update-request.json"\n' "$(env_quote "$STATE_DIR")"
} > "$ETC_DIR/nodeping-agent.env"
chmod 0600 "$ETC_DIR/nodeping-agent.env"

{
	printf 'NODEPING_AGENT_GITHUB_REPOSITORY="%s"\n' "$(env_quote "$GITHUB_REPOSITORY")"
	printf 'NODEPING_AGENT_GITHUB_API_BASE_URL="%s"\n' "$(env_quote "$GITHUB_API_BASE_URL")"
	printf 'NODEPING_AGENT_RELEASE_BASE_URL="%s"\n' "$(env_quote "$CUSTOM_RELEASE_BASE_URL")"
	printf 'NODEPING_AGENT_VERSION="latest"\n'
	printf 'NODEPING_AGENT_INSTALL_PATH="/opt/nodeping-agent/nodeping-agent"\n'
	printf 'NODEPING_AGENT_SERVICE="nodeping-agent.service"\n'
	printf 'NODEPING_AGENT_RESTART="1"\n'
	printf 'NODEPING_AGENT_MINISIGN_PUBLIC_KEY="%s"\n' "$(env_quote "${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}")"
	printf 'NODEPING_AGENT_REQUIRE_SIGNATURE="%s"\n' "$(env_quote "${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}")"
	printf 'NODEPING_AGENT_UPDATE_REQUEST_FILE="%s/update-request.json"\n' "$(env_quote "$STATE_DIR")"
} > "$ETC_DIR/nodeping-agent-update.env"
chmod 0600 "$ETC_DIR/nodeping-agent-update.env"

ENABLE_UPDATER=1 "$tmp_dir/nodeping-agent/install-systemd.sh" "$tmp_dir/nodeping-agent/nodeping-agent"
say "nodeping-agent 已安装，自动升级已启用" "nodeping-agent installed and auto update timer enabled"
