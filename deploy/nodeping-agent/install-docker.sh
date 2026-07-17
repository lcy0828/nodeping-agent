#!/usr/bin/env bash
set -euo pipefail

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

systemctl_quiet() {
	local output
	if ! output="$(systemctl "$@" 2>&1)"; then
		if [ -n "$output" ]; then
			printf '%s\n' "$output" >&2
		fi
		return 1
	fi
}

if [ "$(id -u)" -ne 0 ]; then
	say_err "请以 root 运行 Docker 安装器" "run the Docker installer as root"
	exit 1
fi

SERVER_URL="${NODEPING_SERVER_URL:-}"
BINDING_TOKEN="${NODEPING_TOKEN:-}"
DISTRIBUTION_MODE="${NODEPING_AGENT_DISTRIBUTION_MODE:-cn}"
DEPLOY_BASE_URL="${NODEPING_AGENT_DEPLOY_BASE_URL:-https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent}"
DOCKER_IMAGE_CN="${NODEPING_AGENT_DOCKER_IMAGE_CN:-hub.ilatency.com/ghcr.io/lcy0828/nodeping-agent}"
DOCKER_IMAGE_GLOBAL="${NODEPING_AGENT_DOCKER_IMAGE_GLOBAL:-ghcr.io/lcy0828/nodeping-agent}"
IMAGE_VERSION="${NODEPING_AGENT_IMAGE_VERSION:-latest}"
PROJECT_DIRECTORY="${NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY:-/opt/nodeping-agent}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
AGENT_NAME="${NODEPING_AGENT_NAME:-NodePing Docker Agent}"

is_loopback_http_url() {
	local value="$1"
	[[ "$value" =~ ^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

validate_secure_url() {
	local value="$1" name="$2"
	if [[ "$value" =~ [[:space:]@] ]] || { [[ "$value" != https://* ]] && ! is_loopback_http_url "$value"; }; then
		say_err "$name 必须使用 HTTPS（仅 localhost/回环地址允许 HTTP）" "$name must use HTTPS (HTTP is allowed only for localhost/loopback development)"
		return 1
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

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		return 1
	fi
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
case "$DISTRIBUTION_MODE" in
	cn) selected_image="$DOCKER_IMAGE_CN" ;;
	global) selected_image="$DOCKER_IMAGE_GLOBAL" ;;
	*) say_err "NODEPING_AGENT_DISTRIBUTION_MODE 必须为 cn 或 global" "NODEPING_AGENT_DISTRIBUTION_MODE must be cn or global"; exit 2 ;;
esac

case "$IMAGE_VERSION" in
	''|*[!A-Za-z0-9._-]*) say_err "NODEPING_AGENT_IMAGE_VERSION 无效" "invalid NODEPING_AGENT_IMAGE_VERSION"; exit 2 ;;
esac
case "$PROJECT_DIRECTORY" in
	/*) ;;
	*) say_err "安装目录必须是绝对路径" "project directory must be absolute"; exit 2 ;;
esac
if [[ ! "$PROJECT_DIRECTORY" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
	say_err "安装目录只能包含字母、数字、点、下划线、横线和斜线" "project directory contains unsupported characters"
	exit 2
fi

validate_secure_url "$SERVER_URL" "NODEPING_SERVER_URL"
validate_secure_url "$DEPLOY_BASE_URL" "NODEPING_AGENT_DEPLOY_BASE_URL"
validate_image "NODEPING_AGENT_DOCKER_IMAGE_CN" "$DOCKER_IMAGE_CN"
validate_image "NODEPING_AGENT_DOCKER_IMAGE_GLOBAL" "$DOCKER_IMAGE_GLOBAL"
for item in "NODEPING_TOKEN:$BINDING_TOKEN" "NODEPING_AGENT_ID:$AGENT_ID" "NODEPING_AGENT_NAME:$AGENT_NAME"; do
	validate_env_value "${item%%:*}" "${item#*:}"
done
require_command docker
if ! docker compose version >/dev/null 2>&1; then
	say_err "需要 Docker Compose v2 插件" "Docker Compose v2 plugin is required"
	exit 1
fi
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
	say_err "需要安装 curl 或 wget" "curl or wget is required"
	exit 1
fi

REMOTE_UPGRADE_MODE=disabled
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
	REMOTE_UPGRADE_MODE=request_file
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
download_file "${DEPLOY_BASE_URL%/}/compose.yml" "$tmp_dir/compose.yml"
download_file "${DEPLOY_BASE_URL%/}/update-docker.sh" "$tmp_dir/update-docker.sh"
bash -n "$tmp_dir/update-docker.sh"

install -d -m 0700 "$PROJECT_DIRECTORY"
install -m 0644 "$tmp_dir/compose.yml" "$PROJECT_DIRECTORY/compose.yml"
install -m 0755 "$tmp_dir/update-docker.sh" "$PROJECT_DIRECTORY/update-docker.sh"
CONTROL_DIRECTORY="$PROJECT_DIRECTORY/control"
install -d -m 0700 "$CONTROL_DIRECTORY"

if [ "$REMOTE_UPGRADE_MODE" = "request_file" ]; then
	cat > "$tmp_dir/nodeping-agent-docker-update.service" <<UNIT
[Unit]
Description=Update NodePing Agent Docker deployment
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
Environment="ENV_FILE=$PROJECT_DIRECTORY/.env"
Environment="PROJECT_DIRECTORY=$PROJECT_DIRECTORY"
Environment="NODEPING_AGENT_DOCKER_REQUEST_FILE=$CONTROL_DIRECTORY/update-request.json"
ExecStart=$PROJECT_DIRECTORY/update-docker.sh
UNIT
	cat > "$tmp_dir/nodeping-agent-docker-update.path" <<UNIT
[Unit]
Description=Watch NodePing Agent Docker update requests

[Path]
PathExists=$CONTROL_DIRECTORY/update-request.json
PathChanged=$CONTROL_DIRECTORY/update-request.json
Unit=nodeping-agent-docker-update.service

[Install]
WantedBy=multi-user.target
UNIT
	install -m 0644 "$tmp_dir/nodeping-agent-docker-update.service" /etc/systemd/system/nodeping-agent-docker-update.service
	install -m 0644 "$tmp_dir/nodeping-agent-docker-update.path" /etc/systemd/system/nodeping-agent-docker-update.path
	rm -f "$CONTROL_DIRECTORY/update-request.json"
fi

install -m 0600 /dev/null "$PROJECT_DIRECTORY/.env"
{
	printf 'NODEPING_SERVER_URL="%s"\n' "$(env_quote "$SERVER_URL")"
	printf 'NODEPING_TOKEN="%s"\n' "$(env_quote "$BINDING_TOKEN")"
	printf 'NODEPING_AGENT_ID="%s"\n' "$(env_quote "$AGENT_ID")"
	printf 'NODEPING_AGENT_NAME="%s"\n' "$(env_quote "$AGENT_NAME")"
	printf 'NODEPING_AGENT_DISTRIBUTION_MODE="%s"\n' "$(env_quote "$DISTRIBUTION_MODE")"
	printf 'NODEPING_AGENT_DOCKER_IMAGE_CN="%s"\n' "$(env_quote "$DOCKER_IMAGE_CN")"
	printf 'NODEPING_AGENT_DOCKER_IMAGE_GLOBAL="%s"\n' "$(env_quote "$DOCKER_IMAGE_GLOBAL")"
	printf 'NODEPING_AGENT_IMAGE="%s"\n' "$(env_quote "$selected_image")"
	printf 'NODEPING_AGENT_IMAGE_VERSION="%s"\n' "$(env_quote "$IMAGE_VERSION")"
	printf 'NODEPING_AGENT_DEPLOY_BASE_URL="%s"\n' "$(env_quote "$DEPLOY_BASE_URL")"
	printf 'NODEPING_AGENT_UPGRADE_MODE="%s"\n' "$(env_quote "$REMOTE_UPGRADE_MODE")"
	printf 'NODEPING_AGENT_UPGRADE_REQUEST_FILE="/run/nodeping-agent/update-request.json"\n'
	printf 'NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY="%s"\n' "$(env_quote "$CONTROL_DIRECTORY")"
} > "$PROJECT_DIRECTORY/.env"
chmod 0600 "$PROJECT_DIRECTORY/.env"

if [ "$REMOTE_UPGRADE_MODE" = "request_file" ]; then
	systemctl_quiet daemon-reload
	systemctl_quiet enable --now nodeping-agent-docker-update.path
fi

ENV_FILE="$PROJECT_DIRECTORY/.env" PROJECT_DIRECTORY="$PROJECT_DIRECTORY" "$PROJECT_DIRECTORY/update-docker.sh"
if [ "$REMOTE_UPGRADE_MODE" = "request_file" ]; then
	say "控制台远程升级已启用：nodeping-agent-docker-update.path" "control-panel upgrades enabled: nodeping-agent-docker-update.path"
else
	say "当前主机未运行 systemd，控制台远程升级保持禁用；可手动运行 $PROJECT_DIRECTORY/update-docker.sh" "systemd is not running; control-panel upgrades remain disabled; run $PROJECT_DIRECTORY/update-docker.sh manually"
fi
say "nodeping-agent Docker 部署已安装（$DISTRIBUTION_MODE）" "nodeping-agent Docker deployment installed ($DISTRIBUTION_MODE)"
