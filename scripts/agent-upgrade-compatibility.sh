#!/usr/bin/env bash

set -Eeuo pipefail

repository_root=${NODEPING_RELEASE_REPOSITORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
contract_directory=${NODEPING_AGENT_COMPATIBILITY_DIRECTORY:-$repository_root/deploy/nodeping-agent/upgrade-compatibility}
release_owner=${NODEPING_AGENT_RELEASE_OWNER:-lcy0828}

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/agent-upgrade-compatibility.sh lint
  scripts/agent-upgrade-compatibility.sh verify <release>
  scripts/agent-upgrade-compatibility.sh gate <release>

An incompatible release can pass "gate" only for a workflow_dispatch run with:
  NODEPING_AGENT_RELEASE_TRIGGER=workflow_dispatch
  NODEPING_AGENT_RELEASE_ACTOR=<repository owner>
  NODEPING_AGENT_INCOMPATIBLE_CONFIRMATION=CONFIRM_INCOMPATIBLE_AGENT_UPGRADE:<previous>-><release>
EOF
  exit 2
}

fail() {
  printf 'agent upgrade compatibility check failed: %s\n' "$1" >&2
  return 1
}

require_release_format() {
  local candidate=$1
  if [[ ! $candidate =~ ^v([0-9])\.([0-9])\.([0-9])$ ]]; then
    fail "invalid release $candidate; expected vM.m.p with one digit per component"
    return 1
  fi
  release_index=$((10#${BASH_REMATCH[1]} * 100 + 10#${BASH_REMATCH[2]} * 10 + 10#${BASH_REMATCH[3]}))
  if ((release_index < 10)); then
    fail "release $candidate predates the compatibility-contract baseline v0.1.0"
    return 1
  fi
}

release_from_index() {
  local index=$1
  printf 'v%d.%d.%d\n' \
    "$((index / 100))" \
    "$(((index / 10) % 10))" \
    "$((index % 10))"
}

expected_previous_release() {
  local candidate=$1
  require_release_format "$candidate" || return 1
  if [[ $candidate == v0.1.0 ]]; then
    printf 'v0.0.38\n'
    return
  fi
  release_from_index "$((release_index - 1))"
}

require_annotated_commit_tag() {
  local tag=$1
  local object_type
  local target_type
  if ! git -C "$repository_root" show-ref --verify --quiet "refs/tags/$tag"; then
    fail "required release tag does not exist: $tag"
    return 1
  fi
  object_type=$(git -C "$repository_root" cat-file -t "refs/tags/$tag")
  if [[ $object_type != tag ]]; then
    fail "required release tag is not annotated: $tag"
    return 1
  fi
  target_type=$(git -C "$repository_root" cat-file -t "${tag}^{}")
  if [[ $target_type != commit ]]; then
    fail "required release tag does not resolve to a commit: $tag"
    return 1
  fi
}

read_contract() {
  local contract_path=$1
  local line
  local line_number=0
  local key
  local value

  contract_release=
  contract_previous_release=
  contract_minimum_release=
  contract_status=
  contract_reason=
  contract_docker_probe_paths=
  contract_verification=
  seen_release=0
  seen_previous_release=0
  seen_minimum_release=0
  seen_status=0
  seen_reason=0
  seen_docker_probe_paths=0
  seen_verification=0

  [[ -f $contract_path && ! -L $contract_path ]] || {
    fail "contract is missing or is a symbolic link: $contract_path"
    return 1
  }

  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    line=${line%$'\r'}
    case "$line" in
      ''|\#*) continue ;;
    esac
    if [[ ! $line =~ ^([a-z_]+)=([A-Za-z0-9_.,:/-]+)$ ]]; then
      fail "invalid contract syntax at $contract_path:$line_number"
      return 1
    fi
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    case "$key" in
      release)
        ((seen_release == 0)) || { fail "duplicate key release in $contract_path"; return 1; }
        contract_release=$value
        seen_release=1
        ;;
      previous_release)
        ((seen_previous_release == 0)) || { fail "duplicate key previous_release in $contract_path"; return 1; }
        contract_previous_release=$value
        seen_previous_release=1
        ;;
      minimum_direct_upgrade_release)
        ((seen_minimum_release == 0)) || { fail "duplicate key minimum_direct_upgrade_release in $contract_path"; return 1; }
        contract_minimum_release=$value
        seen_minimum_release=1
        ;;
      status)
        ((seen_status == 0)) || { fail "duplicate key status in $contract_path"; return 1; }
        contract_status=$value
        seen_status=1
        ;;
      incompatibility_reason)
        ((seen_reason == 0)) || { fail "duplicate key incompatibility_reason in $contract_path"; return 1; }
        contract_reason=$value
        seen_reason=1
        ;;
      docker_probe_paths)
        ((seen_docker_probe_paths == 0)) || { fail "duplicate key docker_probe_paths in $contract_path"; return 1; }
        contract_docker_probe_paths=$value
        seen_docker_probe_paths=1
        ;;
      verification)
        ((seen_verification == 0)) || { fail "duplicate key verification in $contract_path"; return 1; }
        contract_verification=$value
        seen_verification=1
        ;;
      *)
        fail "unknown key $key in $contract_path"
        return 1
        ;;
    esac
  done < "$contract_path"

  if ((seen_release + seen_previous_release + seen_minimum_release + seen_status + seen_reason + seen_docker_probe_paths + seen_verification != 7)); then
    fail "contract is missing one or more required keys: $contract_path"
    return 1
  fi
}

validate_probe_paths() {
  local path
  local path_count=0
  local old_ifs=$IFS
  if [[ $contract_docker_probe_paths == ,* || $contract_docker_probe_paths == *, || $contract_docker_probe_paths == *,,* ]]; then
    fail "docker_probe_paths contains an empty item"
    return 1
  fi
  IFS=,
  for path in $contract_docker_probe_paths; do
    path_count=$((path_count + 1))
    if [[ ! $path =~ ^/[A-Za-z0-9._/-]+$ || $path == *'/../'* || $path == */.. ]]; then
      IFS=$old_ifs
      fail "invalid Docker probe path in contract: $path"
      return 1
    fi
  done
  IFS=$old_ifs
  if ((path_count == 0)); then
    fail "docker_probe_paths must not be empty"
    return 1
  fi
}

csv_contains() {
  local csv=$1
  local item=$2
  [[ ,$csv, == *",$item,"* ]]
}

validate_contract() {
  local requested_release=$1
  local contract_path="$contract_directory/$requested_release.env"
  local expected_previous

  require_release_format "$requested_release" || return 1
  read_contract "$contract_path" || return 1
  [[ $contract_release == "$requested_release" ]] || {
    fail "contract release is $contract_release, expected $requested_release"
    return 1
  }
  [[ $(basename "$contract_path") == "$contract_release.env" ]] || {
    fail "contract filename does not match release $contract_release"
    return 1
  }

  expected_previous=$(expected_previous_release "$requested_release") || return 1
  [[ $contract_previous_release == "$expected_previous" ]] || {
    fail "previous_release is $contract_previous_release, expected $expected_previous"
    return 1
  }
  [[ $contract_minimum_release =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    fail "invalid minimum_direct_upgrade_release: $contract_minimum_release"
    return 1
  }
  case "$contract_status" in
    compatible)
      [[ $contract_reason == none ]] || {
        fail "compatible releases must use incompatibility_reason=none"
        return 1
      }
      ;;
    incompatible)
      [[ $contract_reason != none ]] || {
        fail "incompatible releases must record a machine-readable incompatibility_reason"
        return 1
      }
      ;;
    *)
      fail "status must be compatible or incompatible"
      return 1
      ;;
  esac
  if [[ $contract_verification == ,* || $contract_verification == *, || $contract_verification == *,,* ]]; then
    fail "verification contains an empty item"
    return 1
  fi
  if ! csv_contains "$contract_verification" go-tests ||
    ! csv_contains "$contract_verification" docker-legacy-paths; then
    fail "verification must include go-tests and docker-legacy-paths"
    return 1
  fi
  validate_probe_paths || return 1
  if [[ $contract_status == compatible ]]; then
    if ! csv_contains "$contract_docker_probe_paths" /usr/local/lib/nodeping-agent/nodeping-agent; then
      fail "compatible Docker releases must preserve the canonical Agent probe path"
      return 1
    fi
    if [[ $contract_minimum_release == v0.0.35 ]]; then
      if ! csv_contains "$contract_docker_probe_paths" /usr/local/bin/nodeping-agent; then
        fail "compatibility with v0.0.35 requires /usr/local/bin/nodeping-agent"
        return 1
      fi
    fi
  fi
  require_annotated_commit_tag "$contract_previous_release" || return 1
  require_annotated_commit_tag "$contract_minimum_release" || return 1
  if ! git -C "$repository_root" merge-base --is-ancestor \
    "${contract_minimum_release}^{}" "${contract_previous_release}^{}"; then
    fail "$contract_minimum_release is not an ancestor of $contract_previous_release"
    return 1
  fi
}

lint_contracts() {
  local contracts=()
  local contract_path
  local release
  shopt -s nullglob
  contracts=("$contract_directory"/v*.env)
  shopt -u nullglob
  ((${#contracts[@]} > 0)) || {
    fail "no Agent upgrade compatibility contracts found in $contract_directory"
    return 1
  }
  for contract_path in "${contracts[@]}"; do
    release=$(basename "$contract_path" .env)
    validate_contract "$release" || return 1
  done
  printf 'Agent upgrade compatibility contracts verified: %d\n' "${#contracts[@]}"
}

gate_release() {
  local requested_release=$1
  local expected_confirmation
  validate_contract "$requested_release" || return 1
  if [[ $contract_status == compatible ]]; then
    printf 'Agent direct upgrade approved by compatible contract: %s -> %s\n' \
      "$contract_previous_release" "$contract_release"
    return
  fi

  expected_confirmation="CONFIRM_INCOMPATIBLE_AGENT_UPGRADE:${contract_previous_release}->${contract_release}"
  [[ ${NODEPING_AGENT_RELEASE_TRIGGER:-} == workflow_dispatch ]] || {
    fail "incompatible release requires a manual workflow_dispatch"
    return 1
  }
  [[ ${NODEPING_AGENT_RELEASE_ACTOR:-} == "$release_owner" ]] || {
    fail "incompatible release can only be approved by $release_owner"
    return 1
  }
  [[ ${NODEPING_AGENT_INCOMPATIBLE_CONFIRMATION:-} == "$expected_confirmation" ]] || {
    fail "incompatible release requires exact confirmation: $expected_confirmation"
    return 1
  }
  printf 'Agent incompatible upgrade explicitly approved by %s: %s -> %s\n' \
    "$release_owner" "$contract_previous_release" "$contract_release"
}

command_name=${1:-}
case "$command_name" in
  lint)
    [[ $# -eq 1 ]] || usage
    lint_contracts
    ;;
  verify)
    [[ $# -eq 2 ]] || usage
    validate_contract "$2"
    printf 'Agent upgrade compatibility contract verified: %s (%s)\n' "$2" "$contract_status"
    ;;
  gate)
    [[ $# -eq 2 ]] || usage
    gate_release "$2"
    ;;
  *)
    usage
    ;;
esac
