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
	say_err "请以 root 运行安装器，例如：sudo ./install-systemd.sh" "run this installer as root, for example: sudo ./install-systemd.sh"
	exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_BIN="${1:-$SCRIPT_DIR/nodeping-agent}"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodeping-agent}"
INSTALL_BIN="${INSTALL_BIN:-$INSTALL_DIR/nodeping-agent}"
ETC_DIR="${ETC_DIR:-/etc/nodeping-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/nodeping-agent}"
SERVICE_USER="${SERVICE_USER:-nodeping-agent}"
SERVICE_GROUP="${SERVICE_GROUP:-nodeping-agent}"

require_command() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		say_err "缺少必需命令：$name" "required command not found: $name"
		exit 1
	fi
}

systemd_version() {
	local version
	version="$(systemctl --version 2>/dev/null | awk 'NR==1 { print $2 }')"
	case "$version" in
		''|*[!0-9]*) printf '0\n' ;;
		*) printf '%s\n' "$version" ;;
	esac
}

write_agent_service() {
	local target="$1"
	local version="$2"
	{
		cat <<UNIT
[Unit]
Description=NodePing Agent
Documentation=file:$ETC_DIR/README.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
EnvironmentFile=$ETC_DIR/nodeping-agent.env
ExecStart=$INSTALL_BIN
Restart=always
RestartSec=5s
TimeoutStopSec=35s
KillSignal=SIGTERM
WorkingDirectory=$STATE_DIR

NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
UNIT
		if [ "$version" -ge 231 ]; then
			printf 'RuntimeDirectory=nodeping-agent\n'
			printf 'CapabilityBoundingSet=CAP_NET_RAW\n'
			printf 'AmbientCapabilities=CAP_NET_RAW\n'
		fi
		if [ "$version" -ge 232 ]; then
			printf 'ProtectSystem=strict\n'
			printf 'ReadWritePaths=%s\n' "$STATE_DIR"
		else
			printf 'ProtectSystem=full\n'
		fi
		if [ "$version" -ge 235 ]; then
			printf 'StateDirectory=nodeping-agent\n'
		fi
		if [ "$version" -ge 242 ]; then
			printf 'LockPersonality=true\n'
		fi
		cat <<'UNIT'

[Install]
WantedBy=multi-user.target
UNIT
	} > "$target"
}

preflight() {
	require_command systemctl
	require_command getent
	require_command groupadd
	require_command useradd
	require_command install
	require_command mktemp
	if ! command -v ping >/dev/null 2>&1; then
		say_err "未找到 ping 命令；运行 ICMP 检测前请安装 iputils-ping/iputils" "ping command not found; install iputils-ping/iputils before running ICMP checks"
		exit 1
	fi
	if ! systemctl list-unit-files >/dev/null 2>&1; then
		say_err "此安装器需要 systemd" "systemd is required for this installer"
		exit 1
	fi
}

if [ ! -x "$SOURCE_BIN" ]; then
	say_err "未找到 agent 二进制或文件不可执行：$SOURCE_BIN" "agent binary not found or not executable: $SOURCE_BIN"
	exit 1
fi

preflight

if [ -x "$INSTALL_BIN" ]; then
	current_version="$("$INSTALL_BIN" -version 2>/dev/null || true)"
	say "当前已安装版本：$current_version" "current installed version: $current_version"
fi
installing_version="$("$SOURCE_BIN" -version 2>/dev/null || true)"
say "正在安装版本：$installing_version" "installing version: $installing_version"

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
	groupadd --system "$SERVICE_GROUP"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
	useradd --system \
		--gid "$SERVICE_GROUP" \
		--home-dir "$STATE_DIR" \
		--shell /usr/sbin/nologin \
		"$SERVICE_USER"
fi

install -d -m 0755 "$ETC_DIR"
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
install -m 0755 "$SOURCE_BIN" "$INSTALL_BIN"
if command -v setcap >/dev/null 2>&1; then
	setcap cap_net_raw+ep "$INSTALL_BIN" >/dev/null 2>&1 || true
fi
write_agent_service /etc/systemd/system/nodeping-agent.service "$(systemd_version)"
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.service" /etc/systemd/system/nodeping-agent-update.service
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.timer" /etc/systemd/system/nodeping-agent-update.timer
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.path" /etc/systemd/system/nodeping-agent-update.path
install -m 0755 "$SCRIPT_DIR/update-nodeping-agent.sh" "$INSTALL_DIR/nodeping-agent-update"

if [ -f "$SCRIPT_DIR/uninstall-systemd.sh" ]; then
	install -m 0755 "$SCRIPT_DIR/uninstall-systemd.sh" "$ETC_DIR/uninstall-systemd.sh"
fi

if [ -f "$SCRIPT_DIR/README.md" ]; then
	install -m 0644 "$SCRIPT_DIR/README.md" "$ETC_DIR/README.md"
fi

if [ ! -f "$ETC_DIR/nodeping-agent.env" ]; then
	install -m 0600 "$SCRIPT_DIR/nodeping-agent.env.example" "$ETC_DIR/nodeping-agent.env"
	say "已创建 $ETC_DIR/nodeping-agent.env；启动前请编辑 NODEPING_SERVER_URL 和 NODEPING_TOKEN" "created $ETC_DIR/nodeping-agent.env; edit NODEPING_SERVER_URL and NODEPING_TOKEN before starting"
fi

if [ ! -f "$ETC_DIR/nodeping-agent-update.env" ]; then
	install -m 0600 "$SCRIPT_DIR/nodeping-agent-update.env.example" "$ETC_DIR/nodeping-agent-update.env"
	say "已创建 $ETC_DIR/nodeping-agent-update.env；仅在使用自定义发布源时需要编辑" "created $ETC_DIR/nodeping-agent-update.env; edit only if using a custom release source"
fi

systemctl_quiet daemon-reload
systemctl_quiet enable nodeping-agent.service
say "nodeping-agent.service 已启用" "nodeping-agent.service enabled"
systemctl_quiet enable --now nodeping-agent-update.path
say "远程升级监听已启用：nodeping-agent-update.path" "remote update watcher enabled: nodeping-agent-update.path"

if ! grep -Eq 'your-nodeping\.example|np_xxx' "$ETC_DIR/nodeping-agent.env"; then
	systemctl_quiet restart nodeping-agent.service
	say "nodeping-agent.service 已启动" "nodeping-agent.service started"
	set -a
	# shellcheck disable=SC1090
	. "$ETC_DIR/nodeping-agent.env"
	set +a
	doctor_dir="$(mktemp -d)"
	if "$INSTALL_BIN" doctor --json >"$doctor_dir/result.json" 2>"$doctor_dir/error.log"; then
		"$INSTALL_BIN" doctor || true
		say "nodeping-agent 自检通过" "nodeping-agent doctor passed"
	else
		cat "$doctor_dir/error.log" >&2 || true
		say_err "nodeping-agent 自检发现问题；请检查配置并查看 journalctl -u nodeping-agent" "nodeping-agent doctor reported issues; check configuration and journalctl -u nodeping-agent"
		systemctl_quiet stop nodeping-agent.service || true
		systemctl status nodeping-agent.service --no-pager -l >&2 || true
		journalctl -u nodeping-agent.service -n 60 --no-pager >&2 || true
		rm -rf "$doctor_dir"
		exit 1
	fi
	rm -rf "$doctor_dir"
else
	say "nodeping-agent.service 已启用，但因环境文件仍包含占位值未启动" "nodeping-agent.service enabled but not started because env still contains placeholders"
fi

if [ "${ENABLE_UPDATER:-0}" = "1" ]; then
	systemctl_quiet enable --now nodeping-agent-update.timer
	say "nodeping-agent-update.timer 已启用" "nodeping-agent-update.timer enabled"
else
	say "自动升级单元已安装；可执行 systemctl enable --now nodeping-agent-update.timer 启用" "auto update units installed; enable with: systemctl enable --now nodeping-agent-update.timer"
fi
