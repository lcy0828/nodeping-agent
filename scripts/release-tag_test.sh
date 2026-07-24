#!/usr/bin/env bash

set -Eeuo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
release_script="$script_dir/release-tag.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/nodeping-release-tag.XXXXXX")
test_repo="$test_root/repository"

cleanup() {
  rm -R -- "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'release tag policy test failed: %s\n' "$1" >&2
  exit 1
}

assert_output() {
  local expected=$1
  shift
  local actual
  actual=$(NODEPING_RELEASE_REPOSITORY="$test_repo" "$@")
  [[ $actual == "$expected" ]] || fail "got '$actual', expected '$expected'"
}

assert_failure() {
  if NODEPING_RELEASE_REPOSITORY="$test_repo" "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

git init -q "$test_repo"
git -C "$test_repo" config user.name "NodePing Release Test"
git -C "$test_repo" config user.email "release-test@nodeping.invalid"
git -C "$test_repo" commit -q --allow-empty -m "initial"

"$release_script" check server server-v0.0.1 >/dev/null
"$release_script" check server server-v9.9.9 >/dev/null
"$release_script" check agent v0.1.0 >/dev/null
assert_failure "$release_script" check server server-v0.0.0
assert_failure "$release_script" check server server-v0.1.10
assert_failure "$release_script" check server server-v0.10.0
assert_failure "$release_script" check agent v10.0.0
assert_failure "$release_script" check agent v0.1.0-rc.1

git -C "$test_repo" tag -a server-v0.1.60 -m server-v0.1.60
git -C "$test_repo" tag -a v0.0.38 -m v0.0.38
assert_output server-v0.2.0 "$release_script" next server
assert_output v0.1.0 "$release_script" next agent

git -C "$test_repo" tag -a server-v0.2.0 -m server-v0.2.0
NODEPING_RELEASE_REPOSITORY="$test_repo" \
  "$release_script" verify server server-v0.2.0 >/dev/null
assert_output server-v0.2.1 "$release_script" next server

git -C "$test_repo" tag -a server-v0.2.2 -m server-v0.2.2
assert_output server-v0.2.1 "$release_script" next server
assert_failure "$release_script" verify server server-v0.2.2

git -C "$test_repo" tag server-v0.2.1
assert_failure "$release_script" verify server server-v0.2.1
assert_output server-v0.2.1 "$release_script" next server
git -C "$test_repo" tag -d server-v0.2.1 >/dev/null
git -C "$test_repo" tag -a server-v0.2.1 -m server-v0.2.1
NODEPING_RELEASE_REPOSITORY="$test_repo" \
  "$release_script" verify server server-v0.2.1 >/dev/null
NODEPING_RELEASE_REPOSITORY="$test_repo" \
  "$release_script" verify server server-v0.2.2 >/dev/null

for patch in 3 4 5 6 7 8 9; do
  git -C "$test_repo" tag -a "server-v0.2.$patch" -m "server-v0.2.$patch"
done
assert_output server-v0.3.0 "$release_script" next server

git -C "$test_repo" tag -a v0.1.0 -m v0.1.0
NODEPING_RELEASE_REPOSITORY="$test_repo" \
  "$release_script" verify agent v0.1.0 >/dev/null
assert_output v0.1.1 "$release_script" next agent

printf 'Release tag policy tests passed\n'
