#!/bin/sh
set -u

ACTIVE_PATH="${NODEPING_AGENT_INSTALL_PATH:-/opt/nodeping-agent/nodeping-agent}"
BACKUP_PATH="${NODEPING_AGENT_BACKUP_PATH:-/opt/nodeping-agent/nodeping-agent.previous}"
FALLBACK_PATH="${NODEPING_AGENT_FALLBACK_PATH:-/usr/local/lib/nodeping-agent/nodeping-agent}"
ACTIVATION_FILE="${NODEPING_AGENT_ACTIVATION_FILE:-/var/lib/nodeping-agent/updates/activation.pending}"
STABLE_SECONDS="${NODEPING_AGENT_ACTIVATION_STABLE_SECONDS:-20}"
UPGRADE_SCRIPT="${NODEPING_AGENT_UPGRADE_SCRIPT:-/usr/local/bin/nodeping-agent-update}"
PROMOTE_LEGACY_DOCKER_UPGRADE="${NODEPING_AGENT_PROMOTE_LEGACY_DOCKER_UPGRADE:-false}"

case "$STABLE_SECONDS" in
	''|*[!0-9]*|0) STABLE_SECONDS=20 ;;
esac

mkdir -p "$(dirname "$ACTIVE_PATH")" "$(dirname "$ACTIVATION_FILE")"
chmod 0700 "$(dirname "$ACTIVE_PATH")" "$(dirname "$ACTIVATION_FILE")" 2>/dev/null || true

promote_legacy_docker_upgrade_mode() {
	case "$PROMOTE_LEGACY_DOCKER_UPGRADE" in
		1|true) ;;
		*) return ;;
	esac
	[ "${NODEPING_INSTALL_MODE:-}" = "docker" ] || return
	case "${NODEPING_AGENT_UPGRADE_MODE:-}" in
		request_file|request-file|path) ;;
		*) return ;;
	esac
	[ -x "$UPGRADE_SCRIPT" ] || return
	NODEPING_AGENT_UPGRADE_MODE=container
	export NODEPING_AGENT_UPGRADE_MODE
	printf '%s\n' "promoted legacy Docker request-file upgrades to the container updater" >&2
}

promote_legacy_docker_upgrade_mode

binary_version() {
	"$1" -version 2>/dev/null | sed -n 's/.*version=\([^ ]*\).*/nodeping-agent\/\1/p' | head -n 1
}

select_binary() {
	if [ -x "$ACTIVE_PATH" ] && [ -n "$(binary_version "$ACTIVE_PATH")" ]; then
		printf '%s\n' "$ACTIVE_PATH"
		return
	fi
	printf '%s\n' "$FALLBACK_PATH"
}

pending_version() {
	if [ -f "$ACTIVATION_FILE" ] && [ ! -L "$ACTIVATION_FILE" ]; then
		LC_ALL=C head -n 1 "$ACTIVATION_FILE" | tr -d '\r\n'
	fi
}

rollback_candidate() {
	failed_version="$1"
	if [ -x "$BACKUP_PATH" ] && [ -n "$(binary_version "$BACKUP_PATH")" ]; then
		cp "$BACKUP_PATH" "${ACTIVE_PATH}.rollback"
		chmod 0755 "${ACTIVE_PATH}.rollback"
		mv -f "${ACTIVE_PATH}.rollback" "$ACTIVE_PATH"
		printf '%s\n' "container candidate $failed_version failed; restored $(binary_version "$ACTIVE_PATH")" >&2
	else
		rm -f "$ACTIVE_PATH"
		printf '%s\n' "container candidate $failed_version failed; restored image fallback" >&2
	fi
	rm -f "$ACTIVATION_FILE"
}

stopping=0
child_pid=""
stable_pid=""

forward_stop() {
	stopping=1
	if [ -n "$child_pid" ]; then
		kill -TERM "$child_pid" 2>/dev/null || true
	fi
}

trap forward_stop TERM INT HUP

while :; do
	binary="$(select_binary)"
	if [ ! -x "$binary" ]; then
		printf '%s\n' "no executable NodePing Agent binary found" >&2
		exit 127
	fi
	launched_version="$(binary_version "$binary")"
	pending="$(pending_version)"
	if [ -n "$pending" ] && [ "$pending" != "$launched_version" ]; then
		active_version="$(binary_version "$ACTIVE_PATH" 2>/dev/null || true)"
		if [ -z "$active_version" ]; then
			rollback_candidate "$pending"
			binary="$(select_binary)"
			launched_version="$(binary_version "$binary")"
		elif [ "$active_version" != "$pending" ]; then
			printf '%s\n' "discarding stale container activation marker: $pending" >&2
			rm -f "$ACTIVATION_FILE"
		fi
	fi
	if [ -z "$launched_version" ]; then
		printf '%s\n' "NodePing Agent binary did not report a version: $binary" >&2
		exit 126
	fi

	NODEPING_AGENT_ACTIVE_BINARY="$binary" "$binary" "$@" &
	child_pid=$!
	(
		sleep "$STABLE_SECONDS"
		if kill -0 "$child_pid" 2>/dev/null && [ "$(pending_version)" = "$launched_version" ]; then
			rm -f "$ACTIVATION_FILE"
			printf '%s\n' "container candidate activated: $launched_version" >&2
		fi
	) &
	stable_pid=$!

	wait "$child_pid"
	kill "$stable_pid" 2>/dev/null || true
	wait "$stable_pid" 2>/dev/null || true
	stable_pid=""

	if [ "$stopping" = "1" ]; then
		kill -TERM "$child_pid" 2>/dev/null || true
		wait "$child_pid" 2>/dev/null || true
		child_pid=""
		exit 0
	fi
	child_pid=""

	pending="$(pending_version)"
	if [ -n "$pending" ]; then
		if [ "$pending" = "$launched_version" ]; then
			rollback_candidate "$pending"
		else
			active_version="$(binary_version "$ACTIVE_PATH" 2>/dev/null || true)"
			if [ "$active_version" != "$pending" ]; then
				printf '%s\n' "discarding stale container activation marker: $pending" >&2
				rm -f "$ACTIVATION_FILE"
			else
				printf '%s\n' "restarting Agent to activate $pending" >&2
			fi
		fi
	fi
	sleep 1
done
