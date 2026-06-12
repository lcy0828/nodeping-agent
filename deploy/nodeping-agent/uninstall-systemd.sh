#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "run this uninstaller as root, for example: sudo ./uninstall-systemd.sh" >&2
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
	echo "kept config directory: $ETC_DIR"
fi

if [ "$REMOVE_STATE" = "1" ]; then
	rm -rf "$STATE_DIR"
else
	echo "kept state directory: $STATE_DIR"
fi

if [ "$REMOVE_USER" = "1" ] && id -u "$SERVICE_USER" >/dev/null 2>&1; then
	userdel "$SERVICE_USER" >/dev/null 2>&1 || true
fi

echo "nodeping-agent systemd deployment removed"
