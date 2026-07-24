#!/usr/bin/env bash

set -Eeuo pipefail

repo_root=${NODEPING_RELEASE_REPOSITORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/release-tag.sh check <server|agent> <tag>
  scripts/release-tag.sh next <server|agent>
  scripts/release-tag.sh verify <server|agent> <tag>
EOF
  exit 2
}

configure_kind() {
  case "$1" in
    server)
      tag_prefix=server-v
      tag_regex='^server-v([0-9])\.([0-9])\.([0-9])$'
      policy_baseline_index=19
      ;;
    agent)
      tag_prefix=v
      tag_regex='^v([0-9])\.([0-9])\.([0-9])$'
      policy_baseline_index=9
      ;;
    *)
      printf 'unknown release kind: %s\n' "$1" >&2
      usage
      ;;
  esac
}

parse_tag() {
  local candidate=$1
  local report_error=${2:-1}

  if [[ ! $candidate =~ $tag_regex ]]; then
    if [[ $report_error == 1 ]]; then
      printf 'invalid %s release tag: %s; expected %sM.m.p with one digit per component\n' \
        "$release_kind" "$candidate" "$tag_prefix" >&2
    fi
    return 1
  fi

  tag_major=${BASH_REMATCH[1]}
  tag_minor=${BASH_REMATCH[2]}
  tag_patch=${BASH_REMATCH[3]}
  tag_index=$((10#$tag_major * 100 + 10#$tag_minor * 10 + 10#$tag_patch))
  if ((tag_index == 0)); then
    if [[ $report_error == 1 ]]; then
      printf '%s0.0.0 is reserved; the first release is %s0.0.1\n' \
        "$tag_prefix" "$tag_prefix" >&2
    fi
    return 1
  fi
}

tag_from_index() {
  local index=$1
  if ((index < 1 || index > 999)); then
    printf 'release sequence exhausted at %s9.9.9; revise the policy before continuing\n' \
      "$tag_prefix" >&2
    return 1
  fi

  printf '%s%d.%d.%d\n' \
    "$tag_prefix" \
    "$((index / 100))" \
    "$(((index / 10) % 10))" \
    "$((index % 10))"
}

require_repository() {
  if ! git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
    printf 'release tag repository is unavailable: %s\n' "$repo_root" >&2
    exit 1
  fi
}

next_tag() {
  local excluded_tag=${1:-}
  local index=$policy_baseline_index
  local expected_tag
  local object_type
  local target_type

  while ((index < 999)); do
    expected_tag=$(tag_from_index "$((index + 1))")
    if [[ $expected_tag == "$excluded_tag" ]]; then
      break
    fi
    if ! git -C "$repo_root" show-ref --verify --quiet "refs/tags/$expected_tag"; then
      break
    fi
    object_type=$(git -C "$repo_root" cat-file -t "refs/tags/$expected_tag")
    if [[ $object_type != tag ]]; then
      break
    fi
    target_type=$(git -C "$repo_root" cat-file -t "${expected_tag}^{}")
    if [[ $target_type != commit ]]; then
      break
    fi
    index=$((index + 1))
  done

  tag_from_index "$((index + 1))"
}

verify_tag() {
  local candidate=$1
  local expected_tag
  local object_type
  local target_type

  parse_tag "$candidate"
  expected_tag=$(next_tag "$candidate")
  if [[ $candidate != "$expected_tag" ]]; then
    printf 'release tag is out of sequence: got %s, expected %s\n' \
      "$candidate" "$expected_tag" >&2
    return 1
  fi
  if ! git -C "$repo_root" show-ref --verify --quiet "refs/tags/$candidate"; then
    printf 'release tag does not exist locally: %s\n' "$candidate" >&2
    return 1
  fi

  object_type=$(git -C "$repo_root" cat-file -t "refs/tags/$candidate")
  if [[ $object_type != tag ]]; then
    printf 'release tag must be annotated: %s\n' "$candidate" >&2
    return 1
  fi
  target_type=$(git -C "$repo_root" cat-file -t "${candidate}^{}")
  if [[ $target_type != commit ]]; then
    printf 'release tag must resolve to a commit: %s\n' "$candidate" >&2
    return 1
  fi

  printf '%s release tag verified: %s\n' "$release_kind" "$candidate"
}

command_name=${1:-}
release_kind=${2:-}
[[ -n $command_name && -n $release_kind ]] || usage
configure_kind "$release_kind"

case "$command_name" in
  check)
    [[ $# -eq 3 ]] || usage
    parse_tag "$3"
    printf '%s release tag format is valid: %s\n' "$release_kind" "$3"
    ;;
  next)
    [[ $# -eq 2 ]] || usage
    require_repository
    next_tag
    ;;
  verify)
    [[ $# -eq 3 ]] || usage
    require_repository
    verify_tag "$3"
    ;;
  *)
    usage
    ;;
esac
