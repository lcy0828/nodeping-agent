#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
IMAGE="${IMAGE:-nodeping-agent}"
PLATFORMS="${PLATFORMS:-linux/$(go env GOARCH)}"
PUSH="${PUSH:-0}"
NO_LATEST="${NO_LATEST:-0}"

if ! docker buildx version >/dev/null 2>&1; then
	echo "docker buildx is required" >&2
	exit 1
fi

output_flag="--load"
if [ "$PUSH" = "1" ]; then
	output_flag="--push"
elif [[ "$PLATFORMS" == *,* ]]; then
	echo "multi-platform docker builds require PUSH=1, or set PLATFORMS to a single platform" >&2
	exit 1
fi

tags=(-t "$IMAGE:$VERSION")
if [ "$NO_LATEST" != "1" ]; then
	tags+=(-t "$IMAGE:latest")
fi

docker buildx build \
	--platform "$PLATFORMS" \
	-f "$ROOT_DIR/deploy/nodeping-agent/Dockerfile" \
	--build-arg "VERSION=$VERSION" \
	--build-arg "COMMIT=$COMMIT" \
	--build-arg "BUILD_DATE=$BUILD_DATE" \
	"${tags[@]}" \
	"$output_flag" \
	"$ROOT_DIR"

echo "docker image built: $IMAGE:$VERSION"
