#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist/nodeping-agent/$VERSION}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64}"

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
		printf '| darwin | amd64 | manual run only |\n'
		printf '| darwin | arm64 | manual run only |\n\n'
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
rm -f "$DIST_DIR"/install-release.sh
rm -f "$DIST_DIR"/compose.yml
rm -f "$DIST_DIR"/docker.env.example
rm -f "$DIST_DIR"/update-docker.sh
rm -f "$DIST_DIR"/VERSION
rm -f "$DIST_DIR"/PLATFORMS.md
rm -f "$DIST_DIR"/RELEASE_NOTES.md

checksums_file="$DIST_DIR/nodeping-agent_${VERSION}_checksums.txt"

echo "building nodeping-agent version=$VERSION commit=$COMMIT date=$BUILD_DATE"

for platform in $PLATFORMS; do
	goos="${platform%/*}"
	goarch="${platform#*/}"
	artifact="nodeping-agent_${VERSION}_${goos}_${goarch}.tar.gz"
	package_dir="$(mktemp -d)"
	trap 'rm -rf "$package_dir"' EXIT

	mkdir -p "$package_dir/nodeping-agent"
	(
		cd "$ROOT_DIR"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build \
			-trimpath \
			-ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
			-o "$package_dir/nodeping-agent/nodeping-agent" \
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
	cp "$ROOT_DIR/deploy/nodeping-agent/docker-compose.yml" "$package_dir/nodeping-agent/docker-compose.yml"
	cp "$ROOT_DIR/deploy/nodeping-agent/compose.yml" "$package_dir/nodeping-agent/compose.yml"
	cp "$ROOT_DIR/deploy/nodeping-agent/docker.env.example" "$package_dir/nodeping-agent/docker.env.example"
	cp "$ROOT_DIR/deploy/nodeping-agent/install-release.sh" "$package_dir/nodeping-agent/install-release.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/install-systemd.sh" "$package_dir/nodeping-agent/install-systemd.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/uninstall-systemd.sh" "$package_dir/nodeping-agent/uninstall-systemd.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/update-nodeping-agent.sh" "$package_dir/nodeping-agent/update-nodeping-agent.sh"
	cp "$ROOT_DIR/deploy/nodeping-agent/update-docker.sh" "$package_dir/nodeping-agent/update-docker.sh"
	chmod 0755 "$package_dir/nodeping-agent/nodeping-agent" \
		"$package_dir/nodeping-agent/install-release.sh" \
		"$package_dir/nodeping-agent/install-systemd.sh" \
		"$package_dir/nodeping-agent/uninstall-systemd.sh" \
		"$package_dir/nodeping-agent/update-nodeping-agent.sh" \
		"$package_dir/nodeping-agent/update-docker.sh"

	tar -C "$package_dir" -czf "$DIST_DIR/$artifact" nodeping-agent
	(
		cd "$DIST_DIR"
		sha256_file "$artifact"
	) >> "$checksums_file"
	rm -rf "$package_dir"
	trap - EXIT
	echo "built $artifact"
done

printf '%s\n' "$VERSION" > "$DIST_DIR/latest.txt"
printf '%s\n' "$VERSION" > "$DIST_DIR/VERSION"
cp "$ROOT_DIR/deploy/nodeping-agent/install-release.sh" "$DIST_DIR/install-release.sh"
cp "$ROOT_DIR/deploy/nodeping-agent/compose.yml" "$DIST_DIR/compose.yml"
cp "$ROOT_DIR/deploy/nodeping-agent/docker.env.example" "$DIST_DIR/docker.env.example"
cp "$ROOT_DIR/deploy/nodeping-agent/update-docker.sh" "$DIST_DIR/update-docker.sh"
write_platforms_file "$DIST_DIR/PLATFORMS.md"
write_release_notes_file "$DIST_DIR/RELEASE_NOTES.md"
chmod 0755 "$DIST_DIR/install-release.sh" "$DIST_DIR/update-docker.sh"
{
	printf '{\n'
	printf '  "name": "nodeping-agent",\n'
	printf '  "version": "%s",\n' "$VERSION"
	printf '  "commit": "%s",\n' "$COMMIT"
	printf '  "build_date": "%s",\n' "$BUILD_DATE"
	printf '  "checksums": "nodeping-agent_%s_checksums.txt"\n' "$VERSION"
	printf '}\n'
} > "$DIST_DIR/nodeping-agent_${VERSION}_manifest.json"

echo "release files written to $DIST_DIR"
