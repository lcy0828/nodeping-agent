#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
SERVICE="${SERVICE:-nodeping-agent}"
PROJECT_DIRECTORY="${PROJECT_DIRECTORY:-$SCRIPT_DIR}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_DIRECTORY/compose.yml}"
SERVER_URL="${NODEPING_SERVER_URL:-}"
AGENT_ID="${NODEPING_AGENT_ID:-}"

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

if [ ! -f "$ENV_FILE" ]; then
	say_err "未找到环境文件：$ENV_FILE" "env file not found: $ENV_FILE"
	exit 1
fi

dotenv_value() {
	local key="$1"
	local value
	value="$(grep -E "^[[:space:]]*$key[[:space:]]*=" "$ENV_FILE" | tail -n 1 | sed -E "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//" || true)"
	value="${value%$'\r'}"
	case "$value" in
		\"*\") value="${value#\"}"; value="${value%\"}" ;;
		\'*\') value="${value#\'}"; value="${value%\'}" ;;
	esac
	printf '%s' "$value"
}

if [ -z "$SERVER_URL" ]; then
	SERVER_URL="$(dotenv_value NODEPING_SERVER_URL)"
fi
if [ -z "$AGENT_ID" ]; then
	env_agent_id="$(dotenv_value NODEPING_AGENT_ID)"
	if [ -n "$env_agent_id" ]; then
		AGENT_ID="$env_agent_id"
	fi
fi
if [ -z "${NODEPING_AGENT_TOKEN:-}" ]; then
	env_agent_token="$(dotenv_value NODEPING_AGENT_TOKEN)"
	if [ -n "$env_agent_token" ]; then
		NODEPING_AGENT_TOKEN="$env_agent_token"
	fi
fi

cd "$PROJECT_DIRECTORY"

TARGET_VERSION="${NODEPING_AGENT_IMAGE_VERSION:-$(dotenv_value NODEPING_AGENT_IMAGE_VERSION)}"
TARGET_VERSION="${TARGET_VERSION:-latest}"
if [ "$TARGET_VERSION" != "latest" ]; then
	TARGET_VERSION="nodeping-agent/$TARGET_VERSION"
fi

compose() {
	if [ "$COMPOSE_FILE" = "$PROJECT_DIRECTORY/compose.yml" ] || [ "$COMPOSE_FILE" = "compose.yml" ]; then
		docker compose --env-file "$ENV_FILE" "$@"
	else
		docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
	fi
}

container_id() {
	compose ps -q "$SERVICE" 2>/dev/null | head -n 1
}

container_agent_version() {
	local id="$1"
	if [ -n "$id" ]; then
		docker exec "$id" /usr/local/bin/nodeping-agent -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/nodeping-agent\/\1/p' | head -n 1 || true
	fi
}

container_agent_token() {
	local id="$1"
	if [ -n "${NODEPING_AGENT_TOKEN:-}" ]; then
		printf '%s' "$NODEPING_AGENT_TOKEN"
		return 0
	fi
	if [ -n "$id" ]; then
		docker exec "$id" sh -c 'tr -d "[:space:]" < "${NODEPING_AGENT_TOKEN_FILE:-/var/lib/nodeping-agent/agent-token}"' 2>/dev/null || true
	fi
}

container_agent_id() {
	local id="$1"
	if [ -z "$id" ]; then
		return 0
	fi
	docker exec "$id" /bin/sh -c 'printf "%s" "$NODEPING_AGENT_ID"' 2>/dev/null || true
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
	token="$(container_agent_token "$(container_id)" || true)"
	local agent_id="$AGENT_ID"
	if [ -z "$agent_id" ]; then
		agent_id="$(container_agent_id "$(container_id)" || true)"
	fi
	if [ -z "$SERVER_URL" ] || [ -z "$token" ] || [ -z "$agent_id" ]; then
		return 0
	fi
	local payload
	payload="{\"agent_id\":\"$(json_escape "$agent_id")\",\"event\":\"$(json_escape "$event")\",\"from_version\":\"$(json_escape "$from_version")\",\"to_version\":\"$(json_escape "$to_version")\",\"message\":\"$(json_escape "$message")\"}"
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -m 8 -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null || true
	fi
}

before_container="$(container_id)"
CURRENT_VERSION="$(container_agent_version "$before_container")"
emit_upgrade_event "update_started" "$CURRENT_VERSION" "$TARGET_VERSION" "updating docker deployment"

if [ "${NODEPING_AGENT_DOCKER_BUILD:-0}" = "1" ]; then
	if ! compose up -d --build "$SERVICE"; then
		emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "docker compose build/update failed"
		exit 1
	fi
else
	if ! compose pull "$SERVICE"; then
		emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "docker compose pull failed"
		exit 1
	fi
	if ! compose up -d "$SERVICE"; then
		emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "docker compose up failed"
		exit 1
	fi
fi

after_container="$(container_id)"
NEW_VERSION="$(container_agent_version "$after_container")"
if [ -n "$CURRENT_VERSION" ] && [ -n "$NEW_VERSION" ] && [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
	emit_upgrade_event "up_to_date" "$CURRENT_VERSION" "$NEW_VERSION" "docker image already current"
else
	emit_upgrade_event "update_succeeded" "$CURRENT_VERSION" "${NEW_VERSION:-$TARGET_VERSION}" "docker deployment updated"
fi

say "Docker 部署已更新" "docker deployment updated"
compose ps "$SERVICE"
