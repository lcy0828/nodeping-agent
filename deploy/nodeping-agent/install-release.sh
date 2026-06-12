#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "run this installer as root, for example: curl ... | sudo env NODEPING_SERVER_URL=... NODEPING_TOKEN=... bash" >&2
	exit 1
fi

SERVER_URL="${NODEPING_SERVER_URL:-}"
BINDING_TOKEN="${NODEPING_TOKEN:-}"
RELEASE_BASE_URL="${NODEPING_AGENT_RELEASE_BASE_URL:-}"
REQUESTED_VERSION="${NODEPING_AGENT_VERSION:-latest}"
AGENT_ID="${NODEPING_AGENT_ID:-$(hostname | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-')}"
AGENT_NAME="${NODEPING_AGENT_NAME:-$(hostname)}"
ETC_DIR="${ETC_DIR:-/etc/nodeping-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/nodeping-agent}"

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		echo "required command not found: $name" >&2
		exit 1
	fi
}

preflight() {
	require_command tar
	require_command awk
	require_command systemctl
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		echo "curl or wget is required" >&2
		exit 1
	fi
	if ! command -v ping >/dev/null 2>&1; then
		echo "ping command not found; install iputils-ping/iputils before running ICMP checks" >&2
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
		echo "curl or wget is required" >&2
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
			echo "NODEPING_AGENT_REQUIRE_SIGNATURE=1 but NODEPING_AGENT_MINISIGN_PUBLIC_KEY is empty" >&2
			return 1
			;;
		esac
		return 0
	fi
	if ! command -v minisign >/dev/null 2>&1; then
		echo "minisign is required when NODEPING_AGENT_MINISIGN_PUBLIC_KEY is configured" >&2
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
		*) echo "unsupported OS for systemd installer: $(uname -s)" >&2; return 1 ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64) echo amd64 ;;
		aarch64|arm64) echo arm64 ;;
		*) echo "unsupported arch: $(uname -m)" >&2; return 1 ;;
	esac
}

env_quote() {
	printf '%s' "$1" | sed 's/[\\"]/\\&/g'
}

if [ -z "$SERVER_URL" ] || [ -z "$BINDING_TOKEN" ]; then
	echo "NODEPING_SERVER_URL and NODEPING_TOKEN are required" >&2
	exit 2
fi

if [ -z "$RELEASE_BASE_URL" ]; then
	echo "NODEPING_AGENT_RELEASE_BASE_URL is required" >&2
	exit 2
fi

preflight

RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

version="$REQUESTED_VERSION"
if [ "$version" = "latest" ]; then
	download "$RELEASE_BASE_URL/latest.txt" "$tmp_dir/latest.txt"
	version="$(tr -d '[:space:]' < "$tmp_dir/latest.txt")"
fi

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
	echo "checksum for $artifact not found in $checksums" >&2
	exit 1
fi

actual="$(sha256_value "$tmp_dir/$artifact")"
if [ "$actual" != "$expected" ]; then
	echo "checksum mismatch for $artifact" >&2
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
	printf 'NODEPING_AGENT_RELEASE_BASE_URL="%s"\n' "$(env_quote "$RELEASE_BASE_URL")"
	printf 'NODEPING_AGENT_VERSION="latest"\n'
	printf 'NODEPING_AGENT_INSTALL_PATH="/opt/nodeping-agent/nodeping-agent"\n'
	printf 'NODEPING_AGENT_SERVICE="nodeping-agent.service"\n'
	printf 'NODEPING_AGENT_RESTART="1"\n'
	printf 'NODEPING_AGENT_MINISIGN_PUBLIC_KEY="%s"\n' "$(env_quote "${NODEPING_AGENT_MINISIGN_PUBLIC_KEY:-}")"
	printf 'NODEPING_AGENT_REQUIRE_SIGNATURE="%s"\n' "$(env_quote "${NODEPING_AGENT_REQUIRE_SIGNATURE:-auto}")"
	printf 'NODEPING_AGENT_UPDATE_REQUEST_FILE="%s/update-request.json"\n' "$(env_quote "$STATE_DIR")"
} > "$ETC_DIR/nodeping-agent-update.env"
chmod 0600 "$ETC_DIR/nodeping-agent-update.env"

"$tmp_dir/nodeping-agent/install-systemd.sh" "$tmp_dir/nodeping-agent/nodeping-agent"
systemctl enable --now nodeping-agent-update.timer
echo "nodeping-agent installed and auto update timer enabled"
