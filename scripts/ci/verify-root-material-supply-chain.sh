#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 077

readonly ROOT_HINTS_URL="https://www.internic.net/domain/named.root"
readonly ROOT_HINTS_SHA256="cfc5bdedab77e5ad0af9250db1bd701af79cb361a0e150721f468d524eb557fd"
readonly ROOT_ANCHORS_URL="https://data.iana.org/root-anchors/root-anchors.xml"
readonly ROOT_ANCHORS_SHA256="3ccaab38830025ee0a0f6c1f25769427544f81ea2865aa860468f3ef5278b908"
readonly ROOT_ANCHORS_SIGNATURE_URL="https://data.iana.org/root-anchors/root-anchors.p7s"
readonly ROOT_ANCHORS_SIGNATURE_SHA256="644e0e22842c6b7a57fda13d286941fd7449a179f0a3763578fa9a251d307dd1"
readonly ICANN_BUNDLE_URL="https://data.iana.org/root-anchors/icannbundle.pem"
readonly ICANN_BUNDLE_SHA256="18ce7215812d1a2cad8d9d4d3d7c26f7235a9b5ec6f0c1e214e15230fd4f9e24"
readonly OUTPUT_DIR="${NODEPING_ROOT_MATERIAL_OUTPUT_DIR:-}"

for command_name in curl go openssl; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'required command is missing: %s\n' "${command_name}" >&2
    exit 1
  fi
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  printf 'sha256sum or shasum is required\n' >&2
  exit 1
}

verify_sha256() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256_file "${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'SHA-256 mismatch for %s: got %s, want %s\n' "${path}" "${actual}" "${expected}" >&2
    exit 1
  fi
}

download() {
  local destination="$1"
  local url="$2"
  curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
    --silent --show-error --output "${destination}" "${url}"
}

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPOSITORY_ROOT
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-root-material.XXXXXX")"
readonly WORK_DIR
cleanup() {
  rm -R -- "${WORK_DIR}"
}
trap cleanup EXIT

download "${WORK_DIR}/named.root" "${ROOT_HINTS_URL}"
download "${WORK_DIR}/root-anchors.xml" "${ROOT_ANCHORS_URL}"
download "${WORK_DIR}/root-anchors.p7s" "${ROOT_ANCHORS_SIGNATURE_URL}"
download "${WORK_DIR}/icannbundle.pem" "${ICANN_BUNDLE_URL}"

verify_sha256 "${WORK_DIR}/named.root" "${ROOT_HINTS_SHA256}"
verify_sha256 "${WORK_DIR}/root-anchors.xml" "${ROOT_ANCHORS_SHA256}"
verify_sha256 "${WORK_DIR}/root-anchors.p7s" "${ROOT_ANCHORS_SIGNATURE_SHA256}"
verify_sha256 "${WORK_DIR}/icannbundle.pem" "${ICANN_BUNDLE_SHA256}"

openssl smime -verify \
  -inform DER \
  -in "${WORK_DIR}/root-anchors.p7s" \
  -content "${WORK_DIR}/root-anchors.xml" \
  -CAfile "${WORK_DIR}/icannbundle.pem" \
  -purpose any \
  -out /dev/null

cd "${REPOSITORY_ROOT}"
go run ./scripts/verify-root-material.go \
  "${WORK_DIR}/named.root" \
  "${WORK_DIR}/root-anchors.xml"

if [[ -n "${OUTPUT_DIR}" ]]; then
  mkdir -p "${OUTPUT_DIR}"
  cp "${WORK_DIR}/named.root" "${OUTPUT_DIR}/named.root"
  cp "${WORK_DIR}/root-anchors.xml" "${OUTPUT_DIR}/root-anchors.xml"
  cp "${WORK_DIR}/root-anchors.p7s" "${OUTPUT_DIR}/root-anchors.p7s"
  cp "${WORK_DIR}/icannbundle.pem" "${OUTPUT_DIR}/icannbundle.pem"
  chmod 0644 \
    "${OUTPUT_DIR}/named.root" \
    "${OUTPUT_DIR}/root-anchors.xml" \
    "${OUTPUT_DIR}/root-anchors.p7s" \
    "${OUTPUT_DIR}/icannbundle.pem"
  printf 'verified_root_material_output %s\n' "${OUTPUT_DIR}"
fi

printf 'IANA root hints and CMS-signed trust-anchor seed verification passed\n'
