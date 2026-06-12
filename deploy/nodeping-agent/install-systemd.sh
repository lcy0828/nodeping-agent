#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "run this installer as root, for example: sudo ./install-systemd.sh" >&2
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
		echo "required command not found: $name" >&2
		exit 1
	fi
}

preflight() {
	require_command systemctl
	require_command getent
	require_command groupadd
	require_command useradd
	require_command install
	if ! command -v ping >/dev/null 2>&1; then
		echo "ping command not found; install iputils-ping/iputils before running ICMP checks" >&2
		exit 1
	fi
	if ! systemctl list-unit-files >/dev/null 2>&1; then
		echo "systemd is required for this installer" >&2
		exit 1
	fi
}

if [ ! -x "$SOURCE_BIN" ]; then
	echo "agent binary not found or not executable: $SOURCE_BIN" >&2
	exit 1
fi

preflight

if [ -x "$INSTALL_BIN" ]; then
	echo "current installed version: $("$INSTALL_BIN" -version 2>/dev/null || true)"
fi
echo "installing version: $("$SOURCE_BIN" -version 2>/dev/null || true)"

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
install -m 0644 "$SCRIPT_DIR/nodeping-agent.service" /etc/systemd/system/nodeping-agent.service
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.service" /etc/systemd/system/nodeping-agent-update.service
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.timer" /etc/systemd/system/nodeping-agent-update.timer
install -m 0644 "$SCRIPT_DIR/nodeping-agent-update.path" /etc/systemd/system/nodeping-agent-update.path
install -m 0755 "$SCRIPT_DIR/update-nodeping-agent.sh" "$INSTALL_DIR/nodeping-agent-update"

if [ -f "$SCRIPT_DIR/uninstall-systemd.sh" ]; then
	install -m 0755 "$SCRIPT_DIR/uninstall-systemd.sh" "$ETC_DIR/uninstall-systemd.sh"
fi

if [ -f "$SCRIPT_DIR/update-docker.sh" ]; then
	install -m 0755 "$SCRIPT_DIR/update-docker.sh" "$INSTALL_DIR/nodeping-agent-docker-update"
fi

if [ -f "$SCRIPT_DIR/nodeping-agent-docker-update.service" ]; then
	install -m 0644 "$SCRIPT_DIR/nodeping-agent-docker-update.service" /etc/systemd/system/nodeping-agent-docker-update.service
	install -m 0644 "$SCRIPT_DIR/nodeping-agent-docker-update.timer" /etc/systemd/system/nodeping-agent-docker-update.timer
fi

if [ -f "$SCRIPT_DIR/README.md" ]; then
	install -m 0644 "$SCRIPT_DIR/README.md" "$ETC_DIR/README.md"
fi

if [ ! -f "$ETC_DIR/nodeping-agent.env" ]; then
	install -m 0600 "$SCRIPT_DIR/nodeping-agent.env.example" "$ETC_DIR/nodeping-agent.env"
	echo "created $ETC_DIR/nodeping-agent.env; edit NODEPING_SERVER_URL and NODEPING_TOKEN before starting"
fi

if [ ! -f "$ETC_DIR/nodeping-agent-update.env" ]; then
	install -m 0600 "$SCRIPT_DIR/nodeping-agent-update.env.example" "$ETC_DIR/nodeping-agent-update.env"
	echo "created $ETC_DIR/nodeping-agent-update.env; edit only if using a custom release source"
fi

if [ -f "$SCRIPT_DIR/nodeping-agent-docker-update.env.example" ] && [ ! -f "$ETC_DIR/nodeping-agent-docker-update.env" ]; then
	install -m 0600 "$SCRIPT_DIR/nodeping-agent-docker-update.env.example" "$ETC_DIR/nodeping-agent-docker-update.env"
fi

systemctl daemon-reload
systemctl enable nodeping-agent.service
systemctl enable --now nodeping-agent-update.path

if ! grep -Eq 'your-nodeping\.example|np_xxx' "$ETC_DIR/nodeping-agent.env"; then
	systemctl restart nodeping-agent.service
	echo "nodeping-agent.service started"
	set -a
	# shellcheck disable=SC1090
	. "$ETC_DIR/nodeping-agent.env"
	set +a
	if "$INSTALL_BIN" -doctor; then
		echo "nodeping-agent doctor passed"
	else
		echo "nodeping-agent doctor reported issues; check configuration and journalctl -u nodeping-agent" >&2
	fi
else
	echo "nodeping-agent.service enabled but not started because env still contains placeholders"
fi

if [ "${ENABLE_UPDATER:-0}" = "1" ]; then
	systemctl enable --now nodeping-agent-update.timer
	echo "nodeping-agent-update.timer enabled"
else
	echo "auto update units installed; enable with: systemctl enable --now nodeping-agent-update.timer"
fi
echo "remote update watcher enabled: nodeping-agent-update.path"
