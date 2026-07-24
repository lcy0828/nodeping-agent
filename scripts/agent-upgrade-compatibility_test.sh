#!/usr/bin/env bash

set -Eeuo pipefail

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compatibility_script="$script_directory/agent-upgrade-compatibility.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/nodeping-agent-compatibility.XXXXXX")
test_repository="$test_root/repository"
contract_directory="$test_root/contracts"

cleanup() {
  rm -R -- "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'agent upgrade compatibility test failed: %s\n' "$1" >&2
  exit 1
}

run_compatibility() {
  NODEPING_RELEASE_REPOSITORY="$test_repository" \
    NODEPING_AGENT_COMPATIBILITY_DIRECTORY="$contract_directory" \
    "$compatibility_script" "$@"
}

assert_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

write_contract() {
  local release=$1
  local previous_release=$2
  local status=$3
  local reason=$4
  local probe_paths=${5:-/usr/local/bin/nodeping-agent,/usr/local/lib/nodeping-agent/nodeping-agent}
  printf '%s\n' \
    "release=$release" \
    "previous_release=$previous_release" \
    "minimum_direct_upgrade_release=v0.0.35" \
    "status=$status" \
    "incompatibility_reason=$reason" \
    "docker_probe_paths=$probe_paths" \
    "verification=go-tests,docker-legacy-paths,legacy-mode-promotion" \
    > "$contract_directory/$release.env"
}

mkdir -p "$contract_directory"
git init -q "$test_repository"
git -C "$test_repository" config user.name "NodePing Compatibility Test"
git -C "$test_repository" config user.email "compatibility-test@nodeping.invalid"
git -C "$test_repository" commit -q --allow-empty -m "v0.0.35"
git -C "$test_repository" tag -a v0.0.35 -m v0.0.35
git -C "$test_repository" commit -q --allow-empty -m "v0.0.38"
git -C "$test_repository" tag -a v0.0.38 -m v0.0.38

write_contract v0.1.0 v0.0.38 compatible none
run_compatibility lint >/dev/null
run_compatibility verify v0.1.0 >/dev/null
run_compatibility gate v0.1.0 >/dev/null

write_contract v0.1.0 v0.0.37 compatible none
assert_failure run_compatibility verify v0.1.0
write_contract v0.1.0 v0.0.38 compatible none

write_contract v0.1.0 v0.0.38 compatible none /usr/local/lib/nodeping-agent/nodeping-agent
assert_failure run_compatibility verify v0.1.0
write_contract v0.1.0 v0.0.38 compatible none

write_contract v0.1.0 v0.0.38 incompatible breaks-legacy-layout
assert_failure run_compatibility gate v0.1.0
assert_failure env \
  NODEPING_RELEASE_REPOSITORY="$test_repository" \
  NODEPING_AGENT_COMPATIBILITY_DIRECTORY="$contract_directory" \
  NODEPING_AGENT_RELEASE_TRIGGER=workflow_dispatch \
  NODEPING_AGENT_RELEASE_ACTOR=somebody-else \
  NODEPING_AGENT_INCOMPATIBLE_CONFIRMATION='CONFIRM_INCOMPATIBLE_AGENT_UPGRADE:v0.0.38->v0.1.0' \
  "$compatibility_script" gate v0.1.0
assert_failure env \
  NODEPING_RELEASE_REPOSITORY="$test_repository" \
  NODEPING_AGENT_COMPATIBILITY_DIRECTORY="$contract_directory" \
  NODEPING_AGENT_RELEASE_TRIGGER=workflow_dispatch \
  NODEPING_AGENT_RELEASE_ACTOR=lcy0828 \
  NODEPING_AGENT_INCOMPATIBLE_CONFIRMATION='confirm' \
  "$compatibility_script" gate v0.1.0
env \
  NODEPING_RELEASE_REPOSITORY="$test_repository" \
  NODEPING_AGENT_COMPATIBILITY_DIRECTORY="$contract_directory" \
  NODEPING_AGENT_RELEASE_TRIGGER=workflow_dispatch \
  NODEPING_AGENT_RELEASE_ACTOR=lcy0828 \
  NODEPING_AGENT_INCOMPATIBLE_CONFIRMATION='CONFIRM_INCOMPATIBLE_AGENT_UPGRADE:v0.0.38->v0.1.0' \
  "$compatibility_script" gate v0.1.0 >/dev/null

write_contract v0.1.0 v0.0.38 compatible none
git -C "$test_repository" commit -q --allow-empty -m "v0.1.0"
git -C "$test_repository" tag -a v0.1.0 -m v0.1.0
write_contract v0.1.1 v0.1.0 compatible none
run_compatibility verify v0.1.1 >/dev/null
run_compatibility lint >/dev/null

printf '%s\n' 'Agent upgrade compatibility policy tests passed'
