#!/usr/bin/env bash
set -euo pipefail

say() {
	printf '%s / %s\n' "$1" "$2"
}

say_err() {
	printf '%s / %s\n' "$1" "$2" >&2
}

if [ "$(id -u)" -ne 0 ]; then
	say_err "请以 root 运行卸载器，例如：sudo ./uninstall-systemd.sh" "run this uninstaller as root, for example: sudo ./uninstall-systemd.sh"
	exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-/opt/nodeping-agent}"
INSTALL_BIN="${INSTALL_BIN:-$INSTALL_DIR/nodeping-agent}"
UPDATE_BIN="${UPDATE_BIN:-$INSTALL_DIR/nodeping-agent-update}"
DOCKER_UPDATE_BIN="${DOCKER_UPDATE_BIN:-$INSTALL_DIR/nodeping-agent-docker-update}"
ETC_DIR="${ETC_DIR:-/etc/nodeping-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/nodeping-agent}"
SERVICE_USER="${SERVICE_USER:-nodeping-agent}"
REMOVE_CONFIG="${REMOVE_CONFIG:-0}"
REMOVE_STATE="${REMOVE_STATE:-0}"
REMOVE_USER="${REMOVE_USER:-0}"

for unit in nodeping-agent-update.path nodeping-agent-update.timer nodeping-agent-docker-update.timer nodeping-agent.service; do
	if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
		systemctl disable --now "$unit" >/dev/null 2>&1 || true
	fi
done

for unit in \
	nodeping-agent.service \
	nodeping-agent-update.service \
	nodeping-agent-update.path \
	nodeping-agent-update.timer \
	nodeping-agent-docker-update.service \
	nodeping-agent-docker-update.timer; do
	rm -f "/etc/systemd/system/$unit"
done

rm -f "$INSTALL_BIN" "$INSTALL_BIN.previous" "$UPDATE_BIN" "$DOCKER_UPDATE_BIN"
rmdir "$INSTALL_DIR" >/dev/null 2>&1 || true
systemctl daemon-reload

if [ "$REMOVE_CONFIG" = "1" ]; then
	rm -rf "$ETC_DIR"
else
	say "已保留配置目录：$ETC_DIR" "kept config directory: $ETC_DIR"
fi

if [ "$REMOVE_STATE" = "1" ]; then
	rm -rf "$STATE_DIR"
else
	say "已保留状态目录：$STATE_DIR" "kept state directory: $STATE_DIR"
fi

if [ "$REMOVE_USER" = "1" ] && id -u "$SERVICE_USER" >/dev/null 2>&1; then
	userdel "$SERVICE_USER" >/dev/null 2>&1 || true
fi

say "nodeping-agent systemd 部署已移除" "nodeping-agent systemd deployment removed"
