#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
SERVICE="${SERVICE:-nodeping-agent}"
PROJECT_DIRECTORY="${PROJECT_DIRECTORY:-$SCRIPT_DIR}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_DIRECTORY/compose.yml}"
DATA_DIRECTORY="${NODEPING_AGENT_DOCKER_DATA_DIRECTORY:-}"
SERVER_URL="${NODEPING_SERVER_URL:-}"
ALLOW_INSECURE_HTTP="${NODEPING_AGENT_ALLOW_INSECURE_HTTP:-}"
AGENT_ID="${NODEPING_AGENT_ID:-}"
UPDATE_TIMEOUT_SECONDS="${NODEPING_AGENT_DOCKER_UPDATE_TIMEOUT_SECONDS:-90}"
PULL_TIMEOUT_SECONDS="${NODEPING_AGENT_DOCKER_PULL_TIMEOUT_SECONDS:-300}"
READINESS_STABLE_SECONDS="${NODEPING_AGENT_DOCKER_READINESS_STABLE_SECONDS:-10}"
ALLOW_DOWNGRADE="${NODEPING_AGENT_ALLOW_DOWNGRADE:-0}"
UPDATE_REQUEST_FILE="${NODEPING_AGENT_DOCKER_REQUEST_FILE:-$PROJECT_DIRECTORY/control/update-request.json}"
EVENT_TOKEN=""
PREVIOUS_COMPOSE_FILE=""
COMPOSE_UPDATED=0
ORIGINAL_IMAGE_VERSION=""

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
	local url="$1" name="${2:-NODEPING_SERVER_URL}" allow_insecure_http="${3:-false}"
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

json_file_value() {
	local file="$1" key="$2"
	sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

normalize_requested_image_tag() {
	local value="$1"
	value="${value#nodeping-agent/}"
	if [ "$value" = "latest" ]; then
		printf '%s' "$value"
		return 0
	fi
	case "$value" in
		v[0-9]*.[0-9]*.[0-9]*) printf '%s' "$value" ;;
		[0-9]*.[0-9]*.[0-9]*) printf 'v%s' "$value" ;;
		*) printf '%s' "$value" ;;
	esac
}

consume_update_request() {
	[ -r "$UPDATE_REQUEST_FILE" ] || return 0
	local requested
	requested="$(json_file_value "$UPDATE_REQUEST_FILE" version || true)"
	rm -f "$UPDATE_REQUEST_FILE"
	requested="$(normalize_requested_image_tag "$requested")"
	case "$requested" in
		''|*[!A-Za-z0-9._-]*)
			say_err "Docker 升级请求中的版本无效" "Docker upgrade request contains an invalid version"
			return 1
			;;
	esac
	set_dotenv_value NODEPING_AGENT_IMAGE_VERSION "$requested"
}

download_file() {
	local source_url="$1" destination="$2"
	validate_secure_url "$source_url" "deployment URL" >/dev/null 2>&1 || return 1
	if command -v curl >/dev/null 2>&1; then
		if [[ "$source_url" == https://* ]]; then
			curl -fsSL --connect-timeout 8 --max-time 60 --proto '=https' --proto-redir '=https' "$source_url" -o "$destination"
		else
			curl -fsSL --connect-timeout 8 --max-time 60 --proto '=http,https' --proto-redir '=https' "$source_url" -o "$destination"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ "$source_url" == https://* ]]; then
			wget --https-only --timeout=60 --tries=1 -qO "$destination" "$source_url"
		else
			wget --max-redirect=0 --timeout=60 --tries=1 -qO "$destination" "$source_url"
		fi
	else
		return 1
	fi
	[ -s "$destination" ] && ! LC_ALL=C head -c 512 "$destination" | LC_ALL=C grep -aEiq '^[[:space:]]*(<!DOCTYPE html|<html)'
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
if [ -z "$ALLOW_INSECURE_HTTP" ]; then
	ALLOW_INSECURE_HTTP="$(dotenv_value NODEPING_AGENT_ALLOW_INSECURE_HTTP)"
fi
ALLOW_INSECURE_HTTP="$(normalize_allow_insecure_http "${ALLOW_INSECURE_HTTP:-false}")"
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
DEPLOY_BASE_URL="${NODEPING_AGENT_DEPLOY_BASE_URL:-$(dotenv_value NODEPING_AGENT_DEPLOY_BASE_URL)}"
DEPLOY_BASE_URL="${DEPLOY_BASE_URL:-https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent}"
if [ -z "$DATA_DIRECTORY" ]; then
	DATA_DIRECTORY="$(dotenv_value NODEPING_AGENT_DOCKER_DATA_DIRECTORY)"
fi
DATA_DIRECTORY="${DATA_DIRECTORY:-$PROJECT_DIRECTORY/data}"
SYNC_DEPLOYMENT="${NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT:-$(dotenv_value NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT)}"
SYNC_DEPLOYMENT="${SYNC_DEPLOYMENT:-1}"
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
case "$SYNC_DEPLOYMENT" in 0|1) ;; *) say_err "NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT 必须为 0 或 1" "NODEPING_AGENT_DOCKER_SYNC_DEPLOYMENT must be 0 or 1"; exit 2 ;; esac

if [ -n "$SERVER_URL" ]; then
	validate_secure_url "$SERVER_URL" "NODEPING_SERVER_URL" "$ALLOW_INSECURE_HTTP"
fi
if [ "$SYNC_DEPLOYMENT" = "1" ]; then
	validate_secure_url "$DEPLOY_BASE_URL" "NODEPING_AGENT_DEPLOY_BASE_URL"
fi
if [[ ! "$SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
	say_err "SERVICE 名称无效" "invalid SERVICE name"
	exit 2
fi
case "$DATA_DIRECTORY" in
	/*) ;;
	*) say_err "Agent 数据目录必须是绝对路径" "Agent data directory must be absolute"; exit 2 ;;
esac
if [[ ! "$DATA_DIRECTORY" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
	say_err "Agent 数据目录包含不支持的字符" "Agent data directory contains unsupported characters"
	exit 2
fi
case "$DATA_DIRECTORY" in
	/|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
		say_err "Agent 数据目录不能指向系统顶层目录" "Agent data directory must not be a top-level system directory"
		exit 2
		;;
esac
case "$UPDATE_TIMEOUT_SECONDS" in ''|*[!0-9]*|0) say_err "更新超时必须为正整数" "update timeout must be a positive integer"; exit 2 ;; esac
case "$PULL_TIMEOUT_SECONDS" in ''|*[!0-9]*|0) say_err "镜像拉取超时必须为正整数" "image pull timeout must be a positive integer"; exit 2 ;; esac
case "$READINESS_STABLE_SECONDS" in ''|*[!0-9]*|0) say_err "readiness 稳定窗口必须为正整数" "readiness stable window must be a positive integer"; exit 2 ;; esac
case "$ALLOW_DOWNGRADE" in 0|1) ;; *) say_err "NODEPING_AGENT_ALLOW_DOWNGRADE 必须为 0 或 1" "NODEPING_AGENT_ALLOW_DOWNGRADE must be 0 or 1"; exit 2 ;; esac

cd "$PROJECT_DIRECTORY"
set_dotenv_value NODEPING_AGENT_DOCKER_DATA_DIRECTORY "$DATA_DIRECTORY"

ORIGINAL_IMAGE_VERSION="${NODEPING_AGENT_IMAGE_VERSION:-$(dotenv_value NODEPING_AGENT_IMAGE_VERSION)}"
if ! consume_update_request; then
	exit 2
fi
TARGET_TAG="$(dotenv_value NODEPING_AGENT_IMAGE_VERSION)"
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

uses_default_compose_file() {
	[ "$COMPOSE_FILE" = "$PROJECT_DIRECTORY/compose.yml" ] || [ "$COMPOSE_FILE" = "compose.yml" ]
}

restore_previous_compose() {
	if [ "$COMPOSE_UPDATED" = "1" ] && [ -n "$PREVIOUS_COMPOSE_FILE" ] && [ -f "$PREVIOUS_COMPOSE_FILE" ]; then
		cp -p "$PREVIOUS_COMPOSE_FILE" "$PROJECT_DIRECTORY/compose.yml"
		COMPOSE_UPDATED=0
	fi
}

cleanup_compose_backup() {
	if [ -n "$PREVIOUS_COMPOSE_FILE" ]; then
		rm -f "$PREVIOUS_COMPOSE_FILE"
	fi
}

trap cleanup_compose_backup EXIT

sync_default_compose() {
	[ "$SYNC_DEPLOYMENT" = "1" ] || return 0
	uses_default_compose_file || return 0
	local target="$PROJECT_DIRECTORY/compose.yml" candidate
	[ -f "$target" ] || return 1
	candidate="$(mktemp "$PROJECT_DIRECTORY/.compose.yml.download.XXXXXX")"
	if ! download_file "${DEPLOY_BASE_URL%/}/compose.yml" "$candidate"; then
		rm -f "$candidate"
		return 1
	fi
	chmod 0644 "$candidate"
	if ! docker compose --env-file "$ENV_FILE" -f "$candidate" config --quiet; then
		rm -f "$candidate"
		return 1
	fi
	if command -v cmp >/dev/null 2>&1 && cmp -s "$candidate" "$target"; then
		rm -f "$candidate"
		return 0
	fi
	PREVIOUS_COMPOSE_FILE="$(mktemp "$PROJECT_DIRECTORY/.compose.yml.backup.XXXXXX")"
	cp -p "$target" "$PREVIOUS_COMPOSE_FILE"
	mv -f "$candidate" "$target"
	COMPOSE_UPDATED=1
	say "Docker Compose 部署配置已更新" "Docker Compose deployment configuration updated"
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
	# Include stopped containers so a failed deployment remains available for
	# inspection instead of being mistaken for a legacy duplicate.
	compose ps -q --all "$SERVICE" 2>/dev/null | head -n 1
}

canonical_container_id() {
	local id="$1"
	[ -n "$id" ] || return 0
	docker inspect --format '{{.Id}}' "$id" 2>/dev/null || true
}

legacy_container_id() {
	local id candidate_server
	id="$(container_id)"
	if [ -n "$id" ]; then
		printf '%s' "$id"
		return 0
	fi
	for id in $(docker ps -q --filter "label=com.docker.compose.service=$SERVICE" 2>/dev/null || true); do
		candidate_server="$(container_server_url "$id")"
		if [ -n "$candidate_server" ] && [ "$candidate_server" = "${SERVER_URL%/}" ]; then
			printf '%s' "$id"
			return 0
		fi
	done
	for id in $(docker ps -aq --filter "label=com.docker.compose.service=$SERVICE" 2>/dev/null || true); do
		candidate_server="$(container_server_url "$id")"
		if [ -n "$candidate_server" ] && [ "$candidate_server" = "${SERVER_URL%/}" ]; then
			printf '%s' "$id"
			return 0
		fi
	done
}

container_server_url() {
	local value
	value="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null | sed -n 's/^NODEPING_SERVER_URL=//p' | tail -n 1)"
	printf '%s' "${value%/}"
}

normalize_data_directory_permissions() {
	install -d -m 0700 "$DATA_DIRECTORY" || return 1
	chown 0:0 "$DATA_DIRECTORY" || return 1
	chmod 0700 "$DATA_DIRECTORY" || return 1
	local filename path
	for filename in agent-id agent-token release-proxies.tsv latest-version; do
		path="$DATA_DIRECTORY/$filename"
		[ -e "$path" ] || continue
		if [ ! -f "$path" ] || [ -L "$path" ]; then
			say_err "Agent 状态路径不是普通文件：$path" "Agent state path is not a regular file: $path"
			return 1
		fi
		chown 0:0 "$path" || return 1
		chmod 0600 "$path" || return 1
	done
}

data_directory_has_complete_identity() {
	[ -s "$DATA_DIRECTORY/agent-id" ] && [ -s "$DATA_DIRECTORY/agent-token" ]
}

migrate_legacy_agent_state() {
	local id="$1"
	normalize_data_directory_permissions || return 1
	if data_directory_has_complete_identity || [ -z "$id" ]; then
		return 0
	fi
	local mount_info mount_type mount_source
	mount_info="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/nodeping-agent"}}{{printf "%s|%s" .Type .Source}}{{end}}{{end}}' "$id" 2>/dev/null || true)"
	mount_type="${mount_info%%|*}"
	mount_source="${mount_info#*|}"
	case "$mount_type" in
		volume|bind) ;;
		*) say_err "无法确认旧容器的 Agent 数据挂载" "could not identify the legacy Agent data mount"; return 1 ;;
	esac
	if [ -z "$mount_source" ] || [ "$mount_source" = "$mount_info" ]; then
		say_err "旧容器的 Agent 数据挂载来源为空" "the legacy Agent data mount source is empty"
		return 1
	fi
	if [ "$mount_source" = "$DATA_DIRECTORY" ]; then
		say_err "当前 Agent 数据目录缺少完整的 ID 或 Token" "the current Agent data directory is missing its ID or token"
		return 1
	fi
	local filename copied=0
	for filename in agent-id agent-token release-proxies.tsv latest-version; do
		[ -s "$DATA_DIRECTORY/$filename" ] && continue
		if ! docker cp "$id:/var/lib/nodeping-agent/$filename" "$DATA_DIRECTORY/$filename" >/dev/null 2>&1; then
			continue
		fi
		copied=$((copied + 1))
	done
	normalize_data_directory_permissions || return 1
	if ! data_directory_has_complete_identity; then
		say_err "旧容器缺少可迁移的 Agent ID 或 Token" "the legacy container does not contain a complete Agent ID and token"
		return 1
	fi
	if [ "$copied" -gt 0 ]; then
		say "已将旧 Docker 数据卷状态迁移到 $DATA_DIRECTORY" "migrated legacy Docker volume state to $DATA_DIRECTORY"
	fi
}

cleanup_duplicate_agent_containers() {
	local current_id="$1" current_canonical_id id candidate_canonical_id candidate_server removed=0
	current_canonical_id="$(canonical_container_id "$current_id")"
	if [ -z "$current_canonical_id" ]; then
		say_err "无法确认当前 Agent 容器，已跳过重复容器清理" "could not identify the current Agent container; duplicate cleanup was skipped"
		return 1
	fi
	for id in $(docker ps -aq --filter "label=com.docker.compose.service=$SERVICE" 2>/dev/null || true); do
		[ -n "$id" ] || continue
		candidate_canonical_id="$(canonical_container_id "$id")"
		[ -n "$candidate_canonical_id" ] || continue
		[ "$candidate_canonical_id" != "$current_canonical_id" ] || continue
		candidate_server="$(container_server_url "$candidate_canonical_id")"
		[ -n "$candidate_server" ] && [ "$candidate_server" = "${SERVER_URL%/}" ] || continue
		if docker rm -f "$candidate_canonical_id" >/dev/null; then
			removed=$((removed + 1))
		fi
	done
	if [ "$removed" -gt 0 ]; then
		say "已清理 $removed 个同后端的旧重复 Agent 容器" "removed $removed duplicate legacy Agent container(s) for the same backend"
	fi
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
	if [ -r "$DATA_DIRECTORY/agent-token" ]; then
		tr -d '[:space:]' < "$DATA_DIRECTORY/agent-token"
		return 0
	fi
	if [ -n "$id" ]; then
		docker exec "$id" sh -c 'tr -d "[:space:]" < "${NODEPING_AGENT_TOKEN_FILE:-/var/lib/nodeping-agent/agent-token}"' 2>/dev/null || true
	fi
}

container_agent_id() {
	local id="$1"
	if [ -n "$AGENT_ID" ]; then
		printf '%s' "$AGENT_ID"
		return 0
	fi
	if [ -r "$DATA_DIRECTORY/agent-id" ]; then
		tr -d '[:space:]' < "$DATA_DIRECTORY/agent-id"
		return 0
	fi
	if [ -z "$id" ]; then
		return 0
	fi
	docker exec "$id" /bin/sh -c '
		if [ -n "${NODEPING_AGENT_ID:-}" ]; then
			printf "%s" "$NODEPING_AGENT_ID"
		elif [ -r /var/lib/nodeping-agent/agent-id ]; then
			tr -d "[:space:]" < /var/lib/nodeping-agent/agent-id
		fi
	' 2>/dev/null || true
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
			curl -fsS -m 8 --proto '=https' --proto-redir '=https' -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null 2>&1 || true
		else
			curl -fsS -m 8 --proto '=http,https' --proto-redir '=https' -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null 2>&1 || true
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ "$SERVER_URL" == https://* ]]; then
			wget --https-only -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null 2>&1 || true
		else
			wget --max-redirect=0 -qO- --timeout=8 --header="Authorization: Bearer $token" --header="Content-Type: application/json" --post-data="$payload" "${SERVER_URL%/}/api/agent/v1/upgrade-event" >/dev/null 2>&1 || true
		fi
	fi
}

before_container="$(legacy_container_id)"
if ! migrate_legacy_agent_state "$before_container"; then
	say_err "Agent 身份状态迁移失败，已停止更新以避免创建重复节点" "Agent identity migration failed; update stopped to avoid creating a duplicate node"
	exit 1
fi
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
	set_dotenv_value NODEPING_AGENT_IMAGE_VERSION "${ORIGINAL_IMAGE_VERSION:-latest}"
}

rollback_docker() {
	local reason="$1"
	emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "$reason"
	emit_upgrade_event "rollback_started" "$TARGET_VERSION" "$CURRENT_VERSION" "$reason"
	restore_previous_compose
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

if ! sync_default_compose; then
	say_err "无法同步或校验新版 Compose，继续使用现有部署配置" "could not sync or validate the current Compose file; continuing with the existing deployment configuration"
fi

if [ "${NODEPING_AGENT_DOCKER_BUILD:-0}" = "1" ]; then
	if ! compose up -d --build "$SERVICE"; then
		rollback_docker "docker compose build/update failed" || true
		exit 1
	fi
else
	select_image "$PRIMARY_IMAGE"
	if ! compose_pull; then
		if [ "$FALLBACK_IMAGE" = "$PRIMARY_IMAGE" ]; then
			restore_previous_compose
			restore_original_image
			emit_upgrade_event "update_failed" "$CURRENT_VERSION" "$TARGET_VERSION" "docker compose pull failed"
			exit 1
		fi
		say "主镜像源拉取失败，正在尝试备用镜像源" "primary image source failed; trying fallback image source"
		select_image "$FALLBACK_IMAGE"
		if ! compose_pull; then
			restore_previous_compose
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
current_container="$(container_id)"
if [ -z "$current_container" ]; then
	rollback_docker "updated container disappeared before duplicate cleanup" || true
	exit 1
fi
if ! cleanup_duplicate_agent_containers "$current_container"; then
	rollback_docker "could not safely identify the current container during duplicate cleanup" || true
	exit 1
fi
if ! container_is_ready "$current_container"; then
	rollback_docker "updated container stopped during duplicate cleanup" || true
	exit 1
fi
if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
	emit_upgrade_event "up_to_date" "$CURRENT_VERSION" "$NEW_VERSION" "docker image already current"
else
	emit_upgrade_event "update_succeeded" "$CURRENT_VERSION" "$NEW_VERSION" "docker deployment updated"
fi

say "Docker 部署已更新" "docker deployment updated"
compose ps "$SERVICE"
