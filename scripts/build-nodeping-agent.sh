#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist/nodeping-agent/$VERSION}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 linux/arm/v7 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1"
	else
		shasum -a 256 "$1"
	fi
}

write_platforms_file() {
	local path="$1"
	{
		printf '# Supported Platforms\n\n'
		printf 'Generated for version `%s`.\n\n' "$VERSION"
		printf '| OS | Arch | Notes |\n'
		printf '| --- | --- | --- |\n'
		printf '| linux | amd64 | systemd and Docker supported |\n'
		printf '| linux | arm64 | systemd and Docker supported |\n'
		printf '| linux | armv7 | systemd supported |\n'
		printf '| darwin | amd64 | manual run only |\n'
		printf '| darwin | arm64 | manual run only |\n'
		printf '| windows | amd64 | manual run only |\n'
		printf '| windows | arm64 | manual run only |\n\n'
		printf 'The agent uses the system `ping` command for ICMP checks. Linux hosts need `iputils-ping` or an equivalent package.\n'
	} > "$path"
}

write_release_notes_file() {
	local path="$1"
	{
		printf '# NodePing Agent %s\n\n' "$VERSION"
		printf '%s\n' "- Commit: \`$COMMIT\`"
		printf '%s\n\n' "- Build date: \`$BUILD_DATE\`"
		printf '## Highlights\n\n'
		printf '%s\n' '- Registers and heartbeats with the NodePing backend.'
		printf '%s\n' '- Reports public egress IP.'
		printf '%s\n' '- Executes ICMP/TCP/UDP, long probe, HTTP, real HTTP/3 request, DNS lookup/compare, TLS, traceroute, MTR, node status and IP discovery tasks from the backend task stream.'
		printf '%s\n' '- Includes systemd, Docker Compose, auto-update, rollback, uninstall and doctor tooling.'
	} > "$path"
}

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/nodeping-agent_"$VERSION"_*.tar.gz
rm -f "$DIST_DIR"/nodeping-agent_"$VERSION"_checksums.txt
rm -f "$DIST_DIR"/nodeping-agent_"$VERSION"_manifest.json
rm -f "$DIST_DIR"/latest.txt
rm -f "$DIST_DIR"/install-release.sh
rm -f "$DIST_DIR"/install-docker.sh
rm -f "$DIST_DIR"/compose.yml
rm -f "$DIST_DIR"/docker.env.example
rm -f "$DIST_DIR"/update-docker.sh
rm -f "$DIST_DIR"/VERSION
rm -f "$DIST_DIR"/PLATFORMS.md
rm -f "$DIST_DIR"/RELEASE_NOTES.md

checksums_file="$DIST_DIR/nodeping-agent_${VERSION}_checksums.txt"
manifest_entries="$DIST_DIR/.nodeping-agent_${VERSION}_manifest.entries"
rm -f "$manifest_entries"

echo "building nodeping-agent version=$VERSION commit=$COMMIT date=$BUILD_DATE"

for platform in $PLATFORMS; do
	IFS=/ read -r goos goarch variant extra <<EOF
$platform
EOF
	if [ -n "${extra:-}" ] || [ -z "$goos" ] || [ -z "$goarch" ]; then
		echo "invalid platform: $platform" >&2
		exit 1
	fi
	goarm=""
	target_id="${goos}_${goarch}"
	manifest_arch="$goarch"
	if [ "$goarch" = "arm" ]; then
		case "${variant:-}" in
			v*) goarm="${variant#v}" ;;
			"") goarm=7 ;;
			*) echo "invalid arm variant in platform: $platform" >&2; exit 1 ;;
		esac
		target_id="${goos}_${goarch}v${goarm}"
		manifest_arch="${goarch}v${goarm}"
	elif [ -n "${variant:-}" ]; then
		echo "unexpected platform variant: $platform" >&2
		exit 1
	fi
	archive_ext="tar.gz"
	binary_name="nodeping-agent"
	if [ "$goos" = "windows" ]; then
		binary_name="nodeping-agent.exe"
	fi
	artifact="nodeping-agent_${VERSION}_${target_id}.${archive_ext}"
	package_dir="$(mktemp -d)"
	trap 'rm -rf "$package_dir"' EXIT

	mkdir -p "$package_dir/nodeping-agent"
	(
		cd "$ROOT_DIR"
		GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 go build \
			-trimpath \
			-ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
			-o "$package_dir/nodeping-agent/$binary_name" \
			./cmd/nodeping-agent
	)

	cp "$ROOT_DIR/cmd/nodeping-agent/README.md" "$package_dir/nodeping-agent/README.md"
	printf '%s\n' "$VERSION" > "$package_dir/nodeping-agent/VERSION"
	write_platforms_file "$package_dir/nodeping-agent/PLATFORMS.md"
	write_release_notes_file "$package_dir/nodeping-agent/RELEASE_NOTES.md"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent.service" "$package_dir/nodeping-agent/nodeping-agent.service"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent.env.example" "$package_dir/nodeping-agent/nodeping-agent.env.example"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-update.env.example" "$package_dir/nodeping-agent/nodeping-agent-update.env.example"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-update.service" "$package_dir/nodeping-agent/nodeping-agent-update.service"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-update.path" "$package_dir/nodeping-agent/nodeping-agent-update.path"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-update.timer" "$package_dir/nodeping-agent/nodeping-agent-update.timer"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-docker-update.env.example" "$package_dir/nodeping-agent/nodeping-agent-docker-update.env.example"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-docker-update.service" "$package_dir/nodeping-agent/nodeping-agent-docker-update.service"
	cp "$ROOT_DIR/deploy/nodeping-agent/nodeping-agent-docker-update.timer" "$package_dir/nodeping-agent/nodeping-agent-docker-update.timer"
	cp "$ROOT_DIR/deploy/nodeping-agent/compose.yml" "$package_dir/nodeping-agent/compose.yml"
	cp "$ROOT_DIR/deploy/nodeping-agent/docker.env.example" "$package_dir/nodeping-agent/docker.env.example"
	cp "$ROOT_DIR/deploy/nodeping-agent/install-release.sh" "$package_dir/nodeping-agent/install-release.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/install-docker.sh" "$package_dir/nodeping-agent/install-docker.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/install-systemd.sh" "$package_dir/nodeping-agent/install-systemd.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/uninstall-systemd.sh" "$package_dir/nodeping-agent/uninstall-systemd.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/update-nodeping-agent.sh" "$package_dir/nodeping-agent/update-nodeping-agent.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/update-docker.sh" "$package_dir/nodeping-agent/update-docker.sh"
	chmod 0755 "$package_dir/nodeping-agent/$binary_name" \
		"$package_dir/nodeping-agent/install-release.sh" \
		"$package_dir/nodeping-agent/install-docker.sh" \
		"$package_dir/nodeping-agent/install-systemd.sh" \
		"$package_dir/nodeping-agent/uninstall-systemd.sh" \
		"$package_dir/nodeping-agent/update-nodeping-agent.sh" \
		"$package_dir/nodeping-agent/update-docker.sh"

	tar -C "$package_dir" -czf "$DIST_DIR/$artifact" nodeping-agent
	checksum_line="$(
		cd "$DIST_DIR"
		sha256_file "$artifact"
	)"
	printf '%s\n' "$checksum_line" >> "$checksums_file"
	artifact_sha256="${checksum_line%%[[:space:]]*}"
	printf '%s\t%s\t%s\t%s\n' "$artifact" "$goos" "$manifest_arch" "$artifact_sha256" >> "$manifest_entries"
	rm -rf "$package_dir"
	trap - EXIT
	echo "built $artifact"
done

printf '%s\n' "$VERSION" > "$DIST_DIR/VERSION"
printf '%s\n' "$VERSION" > "$DIST_DIR/latest.txt"
write_platforms_file "$DIST_DIR/PLATFORMS.md"
write_release_notes_file "$DIST_DIR/RELEASE_NOTES.md"
{
	printf '{\n'
	printf '  "name": "nodeping-agent",\n'
	printf '  "version": "%s",\n' "$VERSION"
	printf '  "commit": "%s",\n' "$COMMIT"
	printf '  "build_date": "%s",\n' "$BUILD_DATE"
	printf '  "checksums": "nodeping-agent_%s_checksums.txt",\n' "$VERSION"
	printf '  "schema_version": 1,\n'
	printf '  "artifacts": [\n'
	entry_number=0
	entry_count="$(wc -l < "$manifest_entries" | tr -d '[:space:]')"
	while IFS=$'\t' read -r artifact_name artifact_os artifact_arch artifact_sha256; do
		entry_number=$((entry_number + 1))
		comma=,
		if [ "$entry_number" -eq "$entry_count" ]; then
			comma=
		fi
		printf '    {"name": "%s", "os": "%s", "arch": "%s", "sha256": "%s"}%s\n' \
			"$artifact_name" "$artifact_os" "$artifact_arch" "$artifact_sha256" "$comma"
	done < "$manifest_entries"
	printf '  ]\n'
	printf '}\n'
} > "$DIST_DIR/nodeping-agent_${VERSION}_manifest.json"
rm -f "$manifest_entries"

echo "release files written to $DIST_DIR"
