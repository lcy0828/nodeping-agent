#!/usr/bin/env bash
set -euo pipefail

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

if [ "$(id -u)" -ne 0 ]; then
	say_err "请以 root 运行 Docker 卸载器" "run the Docker uninstaller as root"
	exit 1
fi

PROJECT_DIRECTORY="${NODEPING_AGENT_DOCKER_PROJECT_DIRECTORY:-/opt/nodeping-agent}"
if [ -z "${ENV_FILE:-}" ]; then
	if [ -f "$PROJECT_DIRECTORY/.env" ]; then
		ENV_FILE="$PROJECT_DIRECTORY/.env"
	else
		ENV_FILE="$PROJECT_DIRECTORY/nodeping-agent.env"
	fi
fi
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_DIRECTORY/compose.yml}"
DATA_DIRECTORY="${NODEPING_AGENT_DOCKER_DATA_DIRECTORY:-}"
RUNTIME_DIRECTORY="${NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY:-}"
CONTROL_DIRECTORY="${NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY:-}"
REMOVE_CONFIG="${REMOVE_CONFIG:-0}"
REMOVE_DATA="${REMOVE_DATA:-0}"
REMOVE_RUNTIME="${REMOVE_RUNTIME:-$REMOVE_CONFIG}"
MANAGED_MARKER="Managed by NodePing Docker installer"
PROCD_SERVICE="/etc/init.d/nodeping-agent-docker-update"

validate_flag() {
	local name="$1" value="$2"
	case "$value" in
		0|1) ;;
		*) say_err "$name 必须为 0 或 1" "$name must be 0 or 1"; return 1 ;;
	esac
}

validate_managed_directory() {
	local name="$1" value="$2"
	case "$value" in
		/*) ;;
		*) say_err "$name 必须是绝对路径" "$name must be an absolute path"; return 1 ;;
	esac
	if [[ ! "$value" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
		say_err "$name 包含不支持的字符" "$name contains unsupported characters"
		return 1
	fi
	case "$value" in
		*/../*|*/..|*/./*|*/.|*//*)
			say_err "$name 不能包含点路径或重复斜线" "$name must not contain dot components or repeated slashes"
			return 1
			;;
		/|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
			say_err "$name 不能指向系统顶层目录" "$name must not point to a top-level system directory"
			return 1
			;;
	esac
	if [ -L "$value" ]; then
		say_err "$name 不能是符号链接" "$name must not be a symbolic link"
		return 1
	fi
}

validate_directory_layout() {
	case "$PROJECT_DIRECTORY" in
		"$DATA_DIRECTORY"|"$DATA_DIRECTORY"/*)
			say_err "Agent 数据目录不能等于或包含安装目录" "the Agent data directory must not equal or contain the project directory"
			return 1
			;;
		"$RUNTIME_DIRECTORY"|"$RUNTIME_DIRECTORY"/*)
			say_err "Agent 运行目录不能等于或包含安装目录" "the Agent runtime directory must not equal or contain the project directory"
			return 1
			;;
	esac
	case "$DATA_DIRECTORY" in
		"$RUNTIME_DIRECTORY"|"$RUNTIME_DIRECTORY"/*)
			say_err "Agent 数据目录与运行目录不能重叠" "the Agent data and runtime directories must not overlap"
			return 1
			;;
	esac
	case "$RUNTIME_DIRECTORY" in
		"$DATA_DIRECTORY"/*)
			say_err "Agent 数据目录与运行目录不能重叠" "the Agent data and runtime directories must not overlap"
			return 1
			;;
	esac
}

validate_managed_file() {
	local name="$1" value="$2"
	case "$value" in
		"$PROJECT_DIRECTORY"/*) ;;
		*) say_err "$name 必须位于安装目录内" "$name must be inside the project directory"; return 1 ;;
	esac
	if [[ ! "$value" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
		say_err "$name 包含不支持的字符" "$name contains unsupported characters"
		return 1
	fi
	case "$value" in
		*/../*|*/..|*/./*|*/.|*//*)
			say_err "$name 不能包含点路径或重复斜线" "$name must not contain dot components or repeated slashes"
			return 1
			;;
	esac
	if [ -L "$value" ]; then
		say_err "$name 不能是符号链接" "$name must not be a symbolic link"
		return 1
	fi
}

dotenv_value() {
	local key="$1" value
	[ -f "$ENV_FILE" ] || return 0
	value="$(grep -E "^[[:space:]]*$key[[:space:]]*=" "$ENV_FILE" | tail -n 1 | sed -E "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//" || true)"
	value="${value%$'\r'}"
	case "$value" in
		\"*\") value="${value#\"}"; value="${value%\"}" ;;
		\'*\') value="${value#\'}"; value="${value%\'}" ;;
	esac
	printf '%s' "$value"
}

validate_flag REMOVE_CONFIG "$REMOVE_CONFIG"
validate_flag REMOVE_DATA "$REMOVE_DATA"
validate_flag REMOVE_RUNTIME "$REMOVE_RUNTIME"
validate_managed_directory "安装目录" "$PROJECT_DIRECTORY"
validate_managed_file "环境文件" "$ENV_FILE"
validate_managed_file "Compose 文件" "$COMPOSE_FILE"

if [ -z "$DATA_DIRECTORY" ]; then
	DATA_DIRECTORY="$(dotenv_value NODEPING_AGENT_DOCKER_DATA_DIRECTORY)"
fi
DATA_DIRECTORY="${DATA_DIRECTORY:-$PROJECT_DIRECTORY/data}"
if [ -z "$RUNTIME_DIRECTORY" ]; then
	RUNTIME_DIRECTORY="$(dotenv_value NODEPING_AGENT_DOCKER_RUNTIME_DIRECTORY)"
fi
RUNTIME_DIRECTORY="${RUNTIME_DIRECTORY:-$PROJECT_DIRECTORY/runtime}"
if [ -z "$CONTROL_DIRECTORY" ]; then
	CONTROL_DIRECTORY="$(dotenv_value NODEPING_AGENT_DOCKER_CONTROL_DIRECTORY)"
fi
CONTROL_DIRECTORY="${CONTROL_DIRECTORY:-$PROJECT_DIRECTORY/control}"
validate_managed_directory "Agent 数据目录" "$DATA_DIRECTORY"
validate_managed_directory "Agent 运行目录" "$RUNTIME_DIRECTORY"
validate_managed_directory "升级控制目录" "$CONTROL_DIRECTORY"
validate_directory_layout
if [ "$REMOVE_DATA" = "1" ]; then
	if [ ! -f "$DATA_DIRECTORY/.nodeping-agent-docker-data" ] || [ -L "$DATA_DIRECTORY/.nodeping-agent-docker-data" ] || ! grep -Fqx "$MANAGED_MARKER" "$DATA_DIRECTORY/.nodeping-agent-docker-data"; then
		say_err "拒绝删除未由 NodePing 标记的数据目录：${DATA_DIRECTORY}；尚未修改任何文件" "refusing to delete an unmarked NodePing data directory: $DATA_DIRECTORY; no files were changed"
		exit 2
	fi
fi
if [ "$REMOVE_RUNTIME" = "1" ] && [ -e "$RUNTIME_DIRECTORY" ]; then
	if [ ! -f "$RUNTIME_DIRECTORY/.nodeping-agent-docker-runtime" ] || [ -L "$RUNTIME_DIRECTORY/.nodeping-agent-docker-runtime" ] || ! grep -Fqx "$MANAGED_MARKER" "$RUNTIME_DIRECTORY/.nodeping-agent-docker-runtime"; then
		say_err "拒绝删除未由 NodePing 标记的运行目录：${RUNTIME_DIRECTORY}；尚未修改任何文件" "refusing to delete an unmarked NodePing runtime directory: $RUNTIME_DIRECTORY; no files were changed"
		exit 2
	fi
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
	say_err "需要 Docker Compose v2 才能安全停止并移除当前部署；尚未修改任何文件" "Docker Compose v2 is required to safely stop and remove this deployment; no files were changed"
	exit 1
fi
if [ ! -f "$ENV_FILE" ] || [ ! -f "$COMPOSE_FILE" ]; then
	say_err "缺少环境文件或 compose.yml；尚未修改任何文件" "the environment file or compose.yml is missing; no files were changed"
	exit 1
fi

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	for unit in nodeping-agent-docker-update.path nodeping-agent-docker-update.timer nodeping-agent-docker-update.service; do
		systemctl disable --now "$unit" >/dev/null 2>&1 || true
	done
	for unit_file in \
		/etc/systemd/system/nodeping-agent-docker-update.path \
		/etc/systemd/system/nodeping-agent-docker-update.timer \
		/etc/systemd/system/nodeping-agent-docker-update.service; do
		if [ -f "$unit_file" ] && grep -Fq "$MANAGED_MARKER" "$unit_file"; then
			rm -f "$unit_file"
		fi
	done
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ -f "$PROCD_SERVICE" ] && grep -Fq "$MANAGED_MARKER" "$PROCD_SERVICE"; then
	"$PROCD_SERVICE" stop >/dev/null 2>&1 || true
	"$PROCD_SERVICE" disable >/dev/null 2>&1 || true
	rm -f "$PROCD_SERVICE"
fi

rm -f "$CONTROL_DIRECTORY/update-request.json" "$CONTROL_DIRECTORY/update-request.json.processing" "$CONTROL_DIRECTORY/update-request.json.failed"
rm -f "$PROJECT_DIRECTORY/update-docker.sh" "$PROJECT_DIRECTORY/watch-docker-update.sh" "$PROJECT_DIRECTORY/uninstall-docker.sh"

if [ "$REMOVE_CONFIG" = "1" ]; then
	rm -f "$ENV_FILE" "$COMPOSE_FILE"
	rmdir "$CONTROL_DIRECTORY" >/dev/null 2>&1 || true
else
	say "已保留 Docker 配置：$ENV_FILE 和 $COMPOSE_FILE" "kept Docker configuration: $ENV_FILE and $COMPOSE_FILE"
fi

if [ "$REMOVE_DATA" = "1" ]; then
	rm -rf "$DATA_DIRECTORY"
	case "$CONTROL_DIRECTORY" in
		"$PROJECT_DIRECTORY"/*)
			rm -rf "$CONTROL_DIRECTORY"
			;;
	esac
else
	say "已保留 Agent 数据目录：$DATA_DIRECTORY" "kept Agent data directory: $DATA_DIRECTORY"
fi

if [ "$REMOVE_RUNTIME" = "1" ]; then
	rm -rf "$RUNTIME_DIRECTORY"
else
	say "已保留 Agent 运行目录：$RUNTIME_DIRECTORY" "kept Agent runtime directory: $RUNTIME_DIRECTORY"
fi

rmdir "$PROJECT_DIRECTORY" >/dev/null 2>&1 || true
say "nodeping-agent Docker 部署已移除" "nodeping-agent Docker deployment removed"
