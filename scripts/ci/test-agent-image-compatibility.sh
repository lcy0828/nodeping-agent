#!/usr/bin/env bash

set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
contract_directory="$repository_root/deploy/nodeping-agent/upgrade-compatibility"
contract_release=${1:-latest}

if [[ $contract_release == latest ]]; then
  contract_release=$(
    find "$contract_directory" -maxdepth 1 -type f -name 'v?.?.?.env' -print \
      | LC_ALL=C sort \
      | tail -n 1 \
      | sed 's/\.env$//' \
      | xargs basename
  )
fi
[[ -n $contract_release ]] || {
  printf '%s\n' 'no Agent compatibility contract was found' >&2
  exit 1
}

image_version=${2:-$contract_release}
contract_path="$contract_directory/$contract_release.env"
"$repository_root/scripts/agent-upgrade-compatibility.sh" verify "$contract_release"

probe_paths=$(
  sed -n 's/^docker_probe_paths=//p' "$contract_path"
)
[[ -n $probe_paths ]] || {
  printf '%s\n' "docker_probe_paths is empty in $contract_path" >&2
  exit 1
}

if [[ ${NODEPING_AGENT_COMPATIBILITY_SKIP_BUILD:-0} == 1 ]]; then
  image=${NODEPING_AGENT_COMPATIBILITY_IMAGE:?set NODEPING_AGENT_COMPATIBILITY_IMAGE when skipping the build}
else
  image_repository=${NODEPING_AGENT_COMPATIBILITY_IMAGE_REPOSITORY:-nodeping-agent-upgrade-compatibility}
  image="$image_repository:$image_version"
  VERSION="$image_version" \
    IMAGE="$image_repository" \
    NO_LATEST=1 \
    PUSH=0 \
    PLATFORMS="linux/$(go env GOARCH)" \
    "$repository_root/scripts/build-nodeping-agent-image.sh"
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
  printf 'Agent compatibility image is unavailable: %s\n' "$image" >&2
  exit 1
fi

old_ifs=$IFS
IFS=,
for probe_path in $probe_paths; do
  output=$(docker run --rm --entrypoint "$probe_path" "$image" -version)
  case "$output" in
    "nodeping-agent version=$image_version "*) ;;
    *)
      IFS=$old_ifs
      printf 'unexpected version output from %s: %s\n' "$probe_path" "$output" >&2
      exit 1
      ;;
  esac
done
IFS=$old_ifs

docker run --rm --entrypoint /bin/sh "$image" -eu -c '
  test -x /usr/local/bin/nodeping-agent-update
  test -x /usr/local/bin/nodeping-agent-entrypoint
'

printf 'Agent image compatibility smoke test passed: %s (%s -> %s)\n' \
  "$image" "$contract_release" "$image_version"
