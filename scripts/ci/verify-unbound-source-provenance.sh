#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 077

for command_name in awk curl gpg sha256sum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'required command is missing: %s\n' "${command_name}" >&2
    exit 1
  fi
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-unbound-provenance.XXXXXX")"
readonly WORK_DIR
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT

download() {
  local destination="$1"
  local url="$2"
  curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
    --silent --show-error --output "${destination}" "${url}"
}

verify_sha256() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256sum "${path}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'SHA-256 mismatch for %s: got %s, want %s\n' \
      "${path}" "${actual}" "${expected}" >&2
    exit 1
  fi
}

verify_release() {
  local name="$1"
  local archive_url="$2"
  local archive_sha256="$3"
  local signature_url="$4"
  local signature_sha256="$5"
  local key_url="$6"
  local key_sha256="$7"
  local signing_fingerprint="$8"
  local primary_fingerprint="$9"
  local component_dir="${WORK_DIR}/${name}"
  local gpg_home="${component_dir}/gnupg"
  local archive_path="${component_dir}/source"
  local signature_path="${component_dir}/source.asc"
  local key_path="${component_dir}/release-key.asc"
  local status_path="${component_dir}/gpg.status"
  local stderr_path="${component_dir}/gpg.stderr"

  mkdir -p "${gpg_home}"
  chmod 700 "${gpg_home}"
  download "${archive_path}" "${archive_url}"
  download "${signature_path}" "${signature_url}"
  download "${key_path}" "${key_url}"
  verify_sha256 "${archive_path}" "${archive_sha256}"
  verify_sha256 "${signature_path}" "${signature_sha256}"
  verify_sha256 "${key_path}" "${key_sha256}"

  gpg --batch --homedir "${gpg_home}" --import "${key_path}" >/dev/null 2>&1
  if ! gpg --batch --homedir "${gpg_home}" --with-colons \
    --fingerprint --fingerprint | awk -F: '$1 == "fpr" { print $10 }' | \
    grep -Fx "${primary_fingerprint}" >/dev/null; then
    printf '%s keyring is missing primary fingerprint %s\n' \
      "${name}" "${primary_fingerprint}" >&2
    exit 1
  fi
  if ! gpg --batch --homedir "${gpg_home}" --with-colons \
    --fingerprint --fingerprint | awk -F: '$1 == "fpr" { print $10 }' | \
    grep -Fx "${signing_fingerprint}" >/dev/null; then
    printf '%s keyring is missing signing fingerprint %s\n' \
      "${name}" "${signing_fingerprint}" >&2
    exit 1
  fi

  if ! gpg --batch --no-auto-key-import --no-auto-key-retrieve \
    --homedir "${gpg_home}" --status-file "${status_path}" \
    --verify "${signature_path}" "${archive_path}" 2>"${stderr_path}"; then
    cat "${stderr_path}" >&2
    printf '%s detached signature verification failed\n' "${name}" >&2
    exit 1
  fi

  valid_signatures="$(awk '$2 == "VALIDSIG" { print $3 " " $NF }' "${status_path}")"
  if [[ "${valid_signatures}" != "${signing_fingerprint} ${primary_fingerprint}" ]]; then
    printf '%s VALIDSIG mismatch: got %s, want %s %s\n' \
      "${name}" "${valid_signatures:-<none>}" \
      "${signing_fingerprint}" "${primary_fingerprint}" >&2
    exit 1
  fi
  printf 'source_signature_ok %s %s %s\n' \
    "${name}" "${signing_fingerprint}" "${primary_fingerprint}"
}

verify_release \
  openssl-3.5.7 \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz \
  a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz.asc \
  d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2 \
  https://openssl-library.org/source/pubkeys.asc \
  56e106cd1c44bdb117aec24795f6dfbecaa9bfa0a2901b85331f0059aad16d53 \
  BA5473A2B0587B07FB27CF2D216094DFD0CB81EF \
  BA5473A2B0587B07FB27CF2D216094DFD0CB81EF

verify_release \
  unbound-1.25.1 \
  https://nlnetlabs.nl/downloads/unbound/unbound-1.25.1.tar.gz \
  0fe8b6277b0959cfd17562debac0aa5f71e0b02dc4ffa9c60271c583edab586f \
  https://nlnetlabs.nl/downloads/unbound/unbound-1.25.1.tar.gz.asc \
  387296d9a53d59fef89b5ccc3be7a58306fcb3c5febf1e99270ccca9030127a1 \
  https://nlnetlabs.nl/downloads/keys/releases-g2.asc \
  9779ccb2c448bb8cc099c3ab7d0fc40e5cd72fcc9627a85853dd646cd360139b \
  231018690C4D903EF419146AA144323DEAACDF45 \
  231018690C4D903EF419146AA144323DEAACDF45

verify_release \
  libevent-2.1.13-stable \
  https://github.com/libevent/libevent/releases/download/release-2.1.13-stable/libevent-2.1.13-stable.tar.gz \
  f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c \
  https://github.com/libevent/libevent/releases/download/release-2.1.13-stable/libevent-2.1.13-stable.tar.gz.asc \
  d875a6a702adbd0bb28e99e0add5cd9558514d4167068374a3d1676fa9fb31e0 \
  https://keys.openpgp.org/vks/v1/by-fingerprint/7A02B3521DC75C542BA015456AFEE6D49E92B601 \
  2b6512f0a734d252de59841a868d4d9a9fe22cca6824fae0f4c49fd5b8d66903 \
  7A02B3521DC75C542BA015456AFEE6D49E92B601 \
  2133BC600AB133E1D826D173FE43009C4607B1FB

verify_release \
  expat-2.8.2 \
  https://github.com/libexpat/libexpat/releases/download/R_2_8_2/expat-2.8.2.tar.xz \
  3ad89b8588e6644bd4e49981480d48b21289eebbcd4f0a1a4afb1c29f99b6ab4 \
  https://github.com/libexpat/libexpat/releases/download/R_2_8_2/expat-2.8.2.tar.xz.asc \
  7a1b630aa5cbffa6e3dab55d3e0a50438d5b36c61926b3628b59e707af5d3640 \
  https://keys.openpgp.org/vks/v1/by-fingerprint/CB8DE70A90CFBF6C3BF5CC5696262ACFFBD3AEC6 \
  dd0ffdf7d4262e887208af17617c7b84781969b832ebfd4ac24e9fcfddf93241 \
  CB8DE70A90CFBF6C3BF5CC5696262ACFFBD3AEC6 \
  3176EF7DB2367F1FCA4F306B1F9B0E909AF37285

printf 'Unbound helper upstream source provenance verification passed\n'
