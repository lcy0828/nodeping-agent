#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 077

for command_name in curl go; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'required command is missing: %s\n' "${command_name}" >&2
    exit 1
  fi
done

artifact_dir="${1:-${NODEPING_UNBOUND_OUTPUT_DIR:-}}"
if [[ -z "${artifact_dir}" || ! -d "${artifact_dir}" ]]; then
  printf 'usage: %s <unbound-helper-artifact-directory>\n' "$0" >&2
  exit 1
fi
artifact_dir="$(CDPATH='' cd -- "${artifact_dir}" && pwd -P)"
readonly artifact_dir

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPOSITORY_ROOT
readonly TOOL_DIR="${REPOSITORY_ROOT}/scripts/unbound-helper-metadata"
SCHEMA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-unbound-schemas.XXXXXX")"
readonly SCHEMA_DIR
cleanup() {
  rm -R -- "${SCHEMA_DIR}"
}
trap cleanup EXIT

download() {
  local destination="$1"
  local url="$2"
  curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
    --silent --show-error --output "${destination}" "${url}"
}

download \
  "${SCHEMA_DIR}/bom-1.6.schema.json" \
  "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json"
download \
  "${SCHEMA_DIR}/spdx.schema.json" \
  "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json"
download \
  "${SCHEMA_DIR}/jsf-0.82.schema.json" \
  "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/jsf-0.82.schema.json"
download \
  "${SCHEMA_DIR}/spdx-2.3.schema.json" \
  "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json"

go -C "${TOOL_DIR}" test -count=1 ./...
go -C "${TOOL_DIR}" run . validate \
  --artifact-dir "${artifact_dir}" \
  --cyclonedx-schema "${SCHEMA_DIR}/bom-1.6.schema.json" \
  --spdx-schema "${SCHEMA_DIR}/spdx-2.3.schema.json"

printf 'Unbound helper manifest, licenses, CycloneDX 1.6, and SPDX 2.3 verification passed\n'
