#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly VERIFY_SCRIPT="${SCRIPT_DIR}/verify-unbound-dnstap-patch.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-unbound-repro.XXXXXX")"
readonly WORK_DIR

cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT

for pass_name in first second; do
  log_path="${WORK_DIR}/${pass_name}.log"
  hashes_path="${WORK_DIR}/${pass_name}.sha256"
  if ! "${VERIFY_SCRIPT}" >"${log_path}" 2>&1; then
    printf '%s reproducibility build failed\n' "${pass_name}" >&2
    tail -n 200 "${log_path}" >&2
    exit 1
  fi
  grep -E '^(binary_sha256|metadata_sha256) ' "${log_path}" > "${hashes_path}"
  if [[ "$(wc -l < "${hashes_path}" | tr -d '[:space:]')" != "17" ]]; then
    printf 'expected exactly three helper and fourteen metadata hashes in %s pass\n' "${pass_name}" >&2
    exit 1
  fi
  cat "${hashes_path}"
done

diff -u "${WORK_DIR}/first.sha256" "${WORK_DIR}/second.sha256"
printf 'Unbound dnstap unsigned binary reproducibility verification passed\n'
