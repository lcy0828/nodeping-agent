#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
SERVICE="${SERVICE:-nodeping-agent}"
PROJECT_DIRECTORY="${PROJECT_DIRECTORY:-$SCRIPT_DIR}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_DIRECTORY/compose.yml}"
SERVER_URL="${NODEPING_SERVER_URL:-}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
UPDATE_TIMEOUT_SECONDS="${NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS:-90}"
PULL_TIMEOUT_SECONDS="${NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS:-300}"
READINESS_STABLE_SECONDS="${NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS:-10}"
ALLOW_DOWNGRADE="${NODEPING_AGENT_ALLOW_DOWNGRADE:-0}"
EVENT_TOKEN=""

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

is_loopback_http_url() {
	local url="$1"
	[[ "$url" =~ ^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

validate_secure_url() {
	local url="$1"
	if [[ "$url" =~ [[:space:]@] ]] || { [[ "$url" != https://* ]] && ! is_loopback_http_url "$url"; }; then
		say_err "NODEPING_SERVER_URL 必须使用 HTTPS（仅 localhost/回环地址允许 HTTP）" "NODEPING_SERVER_URL must use HTTPS (HTTP is allowed only for localhost/loopback development)"
		return 1
	fi
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

set_dotenv_value() {
	local key="$1" value="$2" temporary
	temporary="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
	awk -v key="$key" -v value="$value" '
		BEGIN { found=0 }
		index($0, key "=") == 1 { print key "=" value; found=1; next }
		{ print }
		END { if (!found) print key "=" value }
	' "$ENV_FILE" > "$temporary"
	chmod 0600 "$temporary"
	mv -f "$temporary" "$ENV_FILE"
}

validate_image() {
	local name="$1" value="$2"
	if [ -z "$value" ] || [[ "$value" =~ [[:space:]@] ]] || [[ "$value" == -* ]] || [[ ! "$value" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
		say_err "$name 不是有效的容器镜像名称" "$name is not a valid container image name"
		return 1
	fi
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

DISTRIBUTION_MODE="${NODEPING_AGENT_DISTRIBUTION_MODE:-$(dotenv_value NODEPING_AGENT_DISTRIBUTION_MODE)}"
DISTRIBUTION_MODE="${DISTRIBUTION_MODE:-cn}"
DISTRIBUTION_MODE="$(printf '%s' "$DISTRIBUTION_MODE" | tr '[:upper:]' '[:lower:]')"
DOCKER_IMAGE_CN="${NODEPING_AGENT_DOCKER_IMAGE_CN:-$(dotenv_value NODEPING_AGENT_DOCKER_IMAGE_CN)}"
DOCKER_IMAGE_CN="${DOCKER_IMAGE_CN:-hub.ilatency.com/ghcr.io/lcy0828/nodeping-agent}"
DOCKER_IMAGE_GLOBAL="${NODEPING_AGENT_DOCKER_IMAGE_GLOBAL:-$(dotenv_value NODEPING_AGENT_DOCKER_IMAGE_GLOBAL)}"
DOCKER_IMAGE_GLOBAL="${DOCKER_IMAGE_GLOBAL:-ghcr.io/lcy0828/nodeping-agent}"
ORIGINAL_IMAGE="${NODEPING_AGENT_IMAGE:-$(dotenv_value NODEPING_AGENT_IMAGE)}"
case "$DISTRIBUTION_MODE" in
	cn)
		PRIMARY_IMAGE="$DOCKER_IMAGE_CN"
		FALLBACK_IMAGE="$DOCKER_IMAGE_GLOBAL"
		;;
	global)
		PRIMARY_IMAGE="$DOCKER_IMAGE_GLOBAL"
		FALLBACK_IMAGE="$DOCKER_IMAGE_CN"
		;;
	*) say_err "NODEPING_AGENT_DISTRIBUTION_MODE 必须为 cn 或 global" "NODEPING_AGENT_DISTRIBUTION_MODE must be cn or global"; exit 2 ;;
esac
validate_image "NODEPING_AGENT_DOCKER_IMAGE_CN" "$DOCKER_IMAGE_CN"
validate_image "NODEPING_AGENT_DOCKER_IMAGE_GLOBAL" "$DOCKER_IMAGE_GLOBAL"

if [ -n "$SERVER_URL" ]; then
	validate_secure_url "$SERVER_URL"
fi
if [[ ! "$SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
	say_err "SERVICE 名称无效" "invalid SERVICE name"
	exit 2
fi
case "$UPDATE_TIMEOUT_SECONDS" in ''|*[!0-9]*|0) say_err "更新超时必须为正整数" "update timeout must be a positive integer"; exit 2 ;; esac
case "$PULL_TIMEOUT_SECONDS" in ''|*[!0-9]*|0) say_err "镜像拉取超时必须为正整数" "image pull timeout must be a positive integer"; exit 2 ;; esac
case "$READINESS_STABLE_SECONDS" in ''|*[!0-9]*|0) say_err "readiness 稳定窗口必须为正整数" "readiness stable window must be a positive integer"; exit 2 ;; esac
case "$ALLOW_DOWNGRADE" in 0|1) ;; *) say_err "NODEPING_AGENT_ALLOW_DOWNGRADE 必须为 0 或 1" "NODEPING_AGENT_ALLOW_DOWNGRADE must be 0 or 1"; exit 2 ;; esac

cd "$PROJECT_DIRECTORY"

TARGET_TAG="${NODEPING_AGENT_IMAGE_VERSION:-$(dotenv_value NODEPING_AGENT_IMAGE_VERSION)}"
TARGET_TAG="${TARGET_TAG:-latest}"
TARGET_VERSION="$TARGET_TAG"
if [ "$TARGET_TAG" != "latest" ]; then
	TARGET_VERSION="nodeping-agent/$TARGET_TAG"
fi

compose() {
	if [ "$COMPOSE_FILE" = "$PROJECT_DIRECTORY/compose.yml" ] || [ "$COMPOSE_FILE" = "compose.yml" ]; then
		docker compose --env-file "$ENV_FILE" "$@"
	else
		docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
	fi
}

compose_pull() {
	if command -v timeout >/dev/null 2>&1; then
		if [ "$COMPOSE_FILE" = "$PROJECT_DIRECTORY/compose.yml" ] || [ "$COMPOSE_FILE" = "compose.yml" ]; then
			timeout "$PULL_TIMEOUT_SECONDS" docker compose --env-file "$ENV_FILE" pull "$SERVICE"
		else
			timeout "$PULL_TIMEOUT_SECONDS" docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull "$SERVICE"
		fi
	else
		DOCKER_CLIENT_TIMEOUT="$PULL_TIMEOUT_SECONDS" COMPOSE_HTTP_TIMEOUT="$PULL_TIMEOUT_SECONDS" compose pull "$SERVICE"
	fi
}

select_image() {
	local image="$1"
	set_dotenv_value NODEPING_AGENT_IMAGE "$image"
	NODEPING_AGENT_IMAGE="$image"
	export NODEPING_AGENT_IMAGE
	ACTIVE_IMAGE="$image"
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

container_image_id() {
	local id="$1"
	[ -n "$id" ] && docker inspect --format '{{.Image}}' "$id" 2>/dev/null || true
}

container_image_ref() {
	local id="$1"
	[ -n "$id" ] && docker inspect --format '{{.Config.Image}}' "$id" 2>/dev/null || true
}

container_is_ready() {
	local id="$1"
	[ -n "$id" ] || return 1
	local state
	state="$(docker inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null || true)"
	case "$state" in
		'true healthy') return 0 ;;
		'true none') docker exec "$id" /usr/local/bin/nodeping-agent liveness >/dev/null 2>&1 ;;
		*) return 1 ;;
	esac
}

wait_container_ready() {
	local expected_version="${1:-}"
	local deadline=$((SECONDS + UPDATE_TIMEOUT_SECONDS))
	local stable_since=0 id observed_version
	while [ "$SECONDS" -le "$deadline" ]; do
		id="$(container_id)"
		observed_version="$(container_agent_version "$id")"
		if container_is_ready "$id" && [ -n "$observed_version" ] && { [ -z "$expected_version" ] || [ "$observed_version" = "$expected_version" ]; }; then
			if [ "$stable_since" -eq 0 ]; then stable_since=$SECONDS; fi
			if [ $((SECONDS - stable_since)) -ge "$READINESS_STABLE_SECONDS" ]; then
				printf '%s' "$observed_version"
				return 0
			fi
		else
			stable_since=0
		fi
		sleep 1
	done
	return 1
}

version_is_lower() {
	local candidate="${1#nodeping-agent/}"
	local current="${2#nodeping-agent/}"
	candidate="${candidate#v}"
	current="${current#v}"
	[ -n "$candidate" ] && [ -n "$current" ] || return 1
	[ "$candidate" != "$current" ] && [ "$(printf '%s\n%s\n' "$candidate" "$current" | sort -V | head -n 1)" = "$candidate" ]
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
	token="${EVENT_TOKEN:-$(container_agent_token "$(container_id)" || true)}"
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

before_container="$(container_id)"
CURRENT_VERSION="$(container_agent_version "$before_container")"
BEFORE_IMAGE_ID="$(container_image_id "$before_container")"
BEFORE_IMAGE_REF="$(container_image_ref "$before_container")"
EVENT_TOKEN="$(container_agent_token "$before_container" || true)"
emit_upgrade_event "update_started" "$CURRENT_VERSION" "$TARGET_VERSION" "updating docker deployment"

restore_original_image() {
	local image="$ORIGINAL_IMAGE"
	if [ -z "$image" ] && [ -n "$BEFORE_IMAGE_REF" ] && [[ "$BEFORE_IMAGE_REF" == *":$TARGET_TAG" ]]; then
		image="${BEFORE_IMAGE_REF%:$TARGET_TAG}"
	fi
	image="${image:-$PRIMARY_IMAGE}"
	select_image "$image"
}

rollback_docker() {
	local reason="$1"
	emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "$reason"
	emit_upgrade_event "rollback_started" "$TARGET_VERSION" "$CURRENT_VERSION" "$reason"
	if [ -z "$BEFORE_IMAGE_ID" ] || [ -z "$BEFORE_IMAGE_REF" ] || [[ "$BEFORE_IMAGE_REF" == *@* ]]; then
		emit_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "previous docker image reference is unavailable"
		return 1
	fi
	if ! docker image inspect "$BEFORE_IMAGE_ID" >/dev/null 2>&1 || ! docker tag "$BEFORE_IMAGE_ID" "$BEFORE_IMAGE_REF"; then
		emit_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "previous docker image is unavailable"
		return 1
	fi
	restore_original_image
	if ! compose up -d --no-deps --force-recreate "$SERVICE"; then
		emit_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "failed to recreate previous container"
		return 1
	fi
	if wait_container_ready "$CURRENT_VERSION" >/dev/null; then
		emit_upgrade_event "rollback_succeeded" "$TARGET_VERSION" "$CURRENT_VERSION" "previous docker image restored"
		return 0
	fi
	emit_upgrade_event "rollback_failed" "$TARGET_VERSION" "$CURRENT_VERSION" "previous container did not become ready"
	return 1
}

if [ "${NODEPING_AGENT_DOCKER_BUILD:-0}" = "1" ]; then
	if ! compose up -d --build "$SERVICE"; then
		rollback_docker "docker compose build/update failed" || true
		exit 1
	fi
else
	select_image "$PRIMARY_IMAGE"
	if ! compose_pull; then
		if [ "$FALLBACK_IMAGE" = "$PRIMARY_IMAGE" ]; then
			restore_original_image
			emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "docker compose pull failed"
			exit 1
		fi
		say "主镜像源拉取失败，正在尝试备用镜像源" "primary image source failed; trying fallback image source"
		select_image "$FALLBACK_IMAGE"
		if ! compose_pull; then
			restore_original_image
			emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "both Docker image sources failed"
			exit 1
		fi
	fi
	if ! compose up -d "$SERVICE"; then
		rollback_docker "docker compose up failed" || true
		exit 1
	fi
fi

expected_version="$TARGET_VERSION"
if [ "$TARGET_TAG" = "latest" ]; then expected_version=""; fi
if ! NEW_VERSION="$(wait_container_ready "$expected_version")"; then
	rollback_docker "updated container did not become stably ready with the requested version" || true
	exit 1
fi
if [ -z "$NEW_VERSION" ]; then
	rollback_docker "updated container returned an empty version" || true
	exit 1
fi
if [ -n "$CURRENT_VERSION" ] && version_is_lower "$NEW_VERSION" "$CURRENT_VERSION" && [ "$ALLOW_DOWNGRADE" != "1" ]; then
	rollback_docker "docker image downgrade is blocked by policy" || true
	exit 1
fi
if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
	emit_upgrade_event "up_to_date" "$CURRENT_VERSION" "$NEW_VERSION" "docker image already current"
else
	emit_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$NEW_VERSION" "docker deployment updated"
fi

say "Docker 部署已更新" "docker deployment updated"
compose ps "$SERVICE"
