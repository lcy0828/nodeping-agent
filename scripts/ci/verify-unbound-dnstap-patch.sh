#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
export ZERO_AR_DATE=1
umask 022

readonly UNBOUND_VERSION="1.25.1"
readonly UNBOUND_ARCHIVE="unbound-${UNBOUND_VERSION}.tar.gz"
readonly UNBOUND_URL="https://nlnetlabs.nl/downloads/unbound/${UNBOUND_ARCHIVE}"
readonly UNBOUND_SHA256="0fe8b6277b0959cfd17562debac0aa5f71e0b02dc4ffa9c60271c583edab586f"
readonly UNBOUND_LICENSE_SHA256="8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db"

readonly PROTOBUF_VERSION="21.12"
readonly PROTOBUF_ARCHIVE="protobuf-all-${PROTOBUF_VERSION}.tar.gz"
readonly PROTOBUF_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOBUF_ARCHIVE}"
readonly PROTOBUF_SHA256="2c6a36c7b5a55accae063667ef3c55f2642e67476d96d355ff0acb13dbb47f09"
readonly PROTOBUF_LICENSE_SHA256="6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d"

readonly PROTOBUF_C_VERSION="1.5.2"
readonly PROTOBUF_C_ARCHIVE="protobuf-c-${PROTOBUF_C_VERSION}.tar.gz"
readonly PROTOBUF_C_URL="https://github.com/protobuf-c/protobuf-c/releases/download/v${PROTOBUF_C_VERSION}/${PROTOBUF_C_ARCHIVE}"
readonly PROTOBUF_C_SHA256="e2c86271873a79c92b58fef7ebf8de1aa0df4738347a8bd5d4e65a80a16d0d24"
readonly PROTOBUF_C_LICENSE_SHA256="2d1d028bd27f8c85bc970d720519d2069ca6213fcb26b9dea444a7c39d24bbb3"

readonly OPENSSL_VERSION="3.5.7"
readonly OPENSSL_ARCHIVE="openssl-${OPENSSL_VERSION}.tar.gz"
readonly OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_ARCHIVE}"
readonly OPENSSL_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
readonly OPENSSL_LICENSE_SHA256="7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"

readonly LIBEVENT_VERSION="2.1.13-stable"
readonly LIBEVENT_ARCHIVE="libevent-${LIBEVENT_VERSION}.tar.gz"
readonly LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/${LIBEVENT_ARCHIVE}"
readonly LIBEVENT_SHA256="f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c"
readonly LIBEVENT_LICENSE_SHA256="ff02effc9b331edcdac387d198691bfa3e575e7d244ad10cb826aa51ef085670"

readonly EXPAT_VERSION="2.8.2"
readonly EXPAT_ARCHIVE="expat-${EXPAT_VERSION}.tar.xz"
readonly EXPAT_URL="https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VERSION//./_}/${EXPAT_ARCHIVE}"
readonly EXPAT_SHA256="3ad89b8588e6644bd4e49981480d48b21289eebbcd4f0a1a4afb1c29f99b6ab4"
readonly EXPAT_LICENSE_SHA256="31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPOSITORY_ROOT
readonly PATCH_PATH="${REPOSITORY_ROOT}/third_party/unbound/patches/0001-dnstap-deterministic-evidence.patch"
readonly METADATA_TOOL_DIR="${REPOSITORY_ROOT}/scripts/unbound-helper-metadata"
readonly PATCH_SHA256="a42affbccfa7ede0d86672258c8775a69bf02156b299bcc8d55bfc3a791557ae"
readonly SOURCE_DATE_EPOCH="1779265372"
readonly UNBOUND_INSTALL_PREFIX="/opt/nodeping/unbound"
readonly OUTPUT_DIR="${NODEPING_UNBOUND_OUTPUT_DIR:-}"

for command_name in cmake curl go make patch perl pkg-config sed strings tar; do
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

download_archive() {
  local destination="$1"
  local url="$2"
  curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
    --silent --show-error --output "${destination}" "${url}"
}

archive_path() {
  local archive_name="$1"
  local url="$2"
  if [[ -n "${NODEPING_UNBOUND_SOURCE_ARCHIVES:-}" ]]; then
    printf '%s/%s\n' "${NODEPING_UNBOUND_SOURCE_ARCHIVES%/}" "${archive_name}"
    return
  fi
  local destination="${DOWNLOAD_DIR}/${archive_name}"
  download_archive "${destination}" "${url}"
  printf '%s\n' "${destination}"
}

build_jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
if [[ ! "${build_jobs}" =~ ^[1-9][0-9]*$ ]]; then
  build_jobs=2
fi

case "$(uname -s)" in
  Darwin)
    target_os=darwin
    ;;
  Linux)
    target_os=linux
    ;;
  *)
    printf 'unsupported native build platform: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac
case "$(uname -m)" in
  arm64 | aarch64)
    target_arch=arm64
    ;;
  amd64 | x86_64)
    target_arch=amd64
    ;;
  *)
    printf 'unsupported native build architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
readonly target_os target_arch

link_map_ldflags() {
  local map_path="$1"
  case "${target_os}" in
    darwin)
      printf '%s\n' "-Wl,-map,${map_path}"
      ;;
    linux)
      printf '%s\n' "-Wl,-Map,${map_path}"
      ;;
  esac
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-unbound-verify.XXXXXX")"
WORK_DIR="$(CDPATH='' cd -- "${WORK_DIR}" && pwd -P)"
readonly WORK_DIR
readonly DOWNLOAD_DIR="${WORK_DIR}/downloads"
readonly PROTOBUF_PREFIX="${WORK_DIR}/protobuf-install"
readonly PROTOBUF_C_PREFIX="${WORK_DIR}/protobuf-c-install"
readonly OPENSSL_LOGICAL_PREFIX="/opt/nodeping/unbound/deps/openssl"
readonly OPENSSL_STAGE="${WORK_DIR}/openssl-stage"
readonly OPENSSL_PREFIX="${OPENSSL_STAGE}${OPENSSL_LOGICAL_PREFIX}"
readonly LIBEVENT_PREFIX="${WORK_DIR}/libevent-install"
readonly EXPAT_PREFIX="${WORK_DIR}/expat-install"
readonly OPENSSL_CONFIGURE_PREFIX="../openssl-stage${OPENSSL_LOGICAL_PREFIX}"
readonly LIBEVENT_CONFIGURE_PREFIX="../libevent-install"
readonly EXPAT_CONFIGURE_PREFIX="../expat-install"
mkdir -p "${DOWNLOAD_DIR}"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT

verify_sha256 "${PATCH_PATH}" "${PATCH_SHA256}"

protobuf_archive_path="$(archive_path "${PROTOBUF_ARCHIVE}" "${PROTOBUF_URL}")"
protobuf_c_archive_path="$(archive_path "${PROTOBUF_C_ARCHIVE}" "${PROTOBUF_C_URL}")"
openssl_archive_path="$(archive_path "${OPENSSL_ARCHIVE}" "${OPENSSL_URL}")"
libevent_archive_path="$(archive_path "${LIBEVENT_ARCHIVE}" "${LIBEVENT_URL}")"
expat_archive_path="$(archive_path "${EXPAT_ARCHIVE}" "${EXPAT_URL}")"
unbound_archive_path="$(archive_path "${UNBOUND_ARCHIVE}" "${UNBOUND_URL}")"

for archive_path_value in \
  "${protobuf_archive_path}" \
  "${protobuf_c_archive_path}" \
  "${openssl_archive_path}" \
  "${libevent_archive_path}" \
  "${expat_archive_path}" \
  "${unbound_archive_path}"; do
  if [[ ! -f "${archive_path_value}" ]]; then
    printf 'source archive is missing: %s\n' "${archive_path_value}" >&2
    exit 1
  fi
done

verify_sha256 "${protobuf_archive_path}" "${PROTOBUF_SHA256}"
verify_sha256 "${protobuf_c_archive_path}" "${PROTOBUF_C_SHA256}"
verify_sha256 "${openssl_archive_path}" "${OPENSSL_SHA256}"
verify_sha256 "${libevent_archive_path}" "${LIBEVENT_SHA256}"
verify_sha256 "${expat_archive_path}" "${EXPAT_SHA256}"
verify_sha256 "${unbound_archive_path}" "${UNBOUND_SHA256}"

tar -xzf "${protobuf_archive_path}" -C "${WORK_DIR}"
tar -xzf "${protobuf_c_archive_path}" -C "${WORK_DIR}"
tar -xzf "${openssl_archive_path}" -C "${WORK_DIR}"
tar -xzf "${libevent_archive_path}" -C "${WORK_DIR}"
tar -xf "${expat_archive_path}" -C "${WORK_DIR}"
tar -xzf "${unbound_archive_path}" -C "${WORK_DIR}"

readonly PROTOBUF_SOURCE="${WORK_DIR}/protobuf-${PROTOBUF_VERSION}"
readonly PROTOBUF_BUILD="${WORK_DIR}/protobuf-build"
readonly PROTOBUF_C_SOURCE="${WORK_DIR}/protobuf-c-${PROTOBUF_C_VERSION}"
readonly OPENSSL_SOURCE="${WORK_DIR}/openssl-${OPENSSL_VERSION}"
readonly LIBEVENT_SOURCE="${WORK_DIR}/libevent-${LIBEVENT_VERSION}"
readonly EXPAT_SOURCE="${WORK_DIR}/expat-${EXPAT_VERSION}"
readonly EXPAT_BUILD="${WORK_DIR}/expat-build"
readonly UNBOUND_SOURCE="${WORK_DIR}/unbound-${UNBOUND_VERSION}"
readonly OUTPUT_STAGE="${WORK_DIR}/verified-helper-output"
readonly LINK_MAP_DIR="${WORK_DIR}/link-maps"
mkdir -p "${OUTPUT_STAGE}" "${LINK_MAP_DIR}"

verify_sha256 "${PROTOBUF_SOURCE}/LICENSE" "${PROTOBUF_LICENSE_SHA256}"
verify_sha256 "${PROTOBUF_C_SOURCE}/LICENSE" "${PROTOBUF_C_LICENSE_SHA256}"
verify_sha256 "${OPENSSL_SOURCE}/LICENSE.txt" "${OPENSSL_LICENSE_SHA256}"
verify_sha256 "${LIBEVENT_SOURCE}/LICENSE" "${LIBEVENT_LICENSE_SHA256}"
verify_sha256 "${EXPAT_SOURCE}/COPYING" "${EXPAT_LICENSE_SHA256}"
verify_sha256 "${UNBOUND_SOURCE}/LICENSE" "${UNBOUND_LICENSE_SHA256}"

cmake \
  -S "${PROTOBUF_SOURCE}/cmake" \
  -B "${PROTOBUF_BUILD}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${PROTOBUF_PREFIX}" \
  -Dprotobuf_BUILD_CONFORMANCE=OFF \
  -Dprotobuf_BUILD_EXAMPLES=OFF \
  -Dprotobuf_BUILD_LIBPROTOC=OFF \
  -Dprotobuf_BUILD_PROTOC_BINARIES=ON \
  -Dprotobuf_BUILD_SHARED_LIBS=OFF \
  -Dprotobuf_BUILD_TESTS=OFF
cmake --build "${PROTOBUF_BUILD}" --parallel "${build_jobs}"
cmake --install "${PROTOBUF_BUILD}"
"${PROTOBUF_PREFIX}/bin/protoc" --version | grep -Fx 'libprotoc 3.21.12'

(
  cd "${PROTOBUF_C_SOURCE}"
  PATH="${PROTOBUF_PREFIX}/bin:${PATH}" \
    PKG_CONFIG_PATH="${PROTOBUF_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}" \
    CFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    ./configure \
      --prefix="${PROTOBUF_C_PREFIX}" \
      --disable-shared \
      --enable-static
  make -j "${build_jobs}"
  make install
)
"${PROTOBUF_C_PREFIX}/bin/protoc-c" --version | grep -Fx 'protobuf-c 1.5.2'

(
  cd "${OPENSSL_SOURCE}"
  export SOURCE_DATE_EPOCH
  # OpenSSL records these flags in libcrypto. Its build uses relative source
  # paths, so including an absolute prefix-map would itself break reproducibility.
  CFLAGS="-O2 -g0" \
    CXXFLAGS="-O2 -g0" \
    ./Configure \
    --prefix="${OPENSSL_LOGICAL_PREFIX}" \
    --libdir=lib \
    --openssldir="${OPENSSL_LOGICAL_PREFIX}/ssl" \
    no-docs \
    no-module \
    no-pinshared \
    no-shared \
    no-tests
  make -j "${build_jobs}" build_sw
  make DESTDIR="${OPENSSL_STAGE}" install_sw
)
"${OPENSSL_PREFIX}/bin/openssl" version | grep -F "OpenSSL ${OPENSSL_VERSION} "
test -f "${OPENSSL_PREFIX}/lib/libcrypto.a"
test -f "${OPENSSL_PREFIX}/lib/libssl.a"

(
  cd "${LIBEVENT_SOURCE}"
  export SOURCE_DATE_EPOCH
  CFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    ./configure \
    --prefix="${LIBEVENT_PREFIX}" \
    --disable-libevent-regress \
    --disable-openssl \
    --disable-samples \
    --disable-shared \
    --enable-static
  make -j "${build_jobs}"
  make install
)
test -f "${LIBEVENT_PREFIX}/lib/libevent.a"

cmake \
  -S "${EXPAT_SOURCE}" \
  -B "${EXPAT_BUILD}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
  -DCMAKE_CXX_FLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
  -DCMAKE_INSTALL_PREFIX="${EXPAT_PREFIX}" \
  -DEXPAT_BUILD_DOCS=OFF \
  -DEXPAT_BUILD_EXAMPLES=OFF \
  -DEXPAT_BUILD_TESTS=OFF \
  -DEXPAT_BUILD_TOOLS=OFF \
  -DEXPAT_SHARED_LIBS=OFF
cmake --build "${EXPAT_BUILD}" --parallel "${build_jobs}"
cmake --install "${EXPAT_BUILD}"
test -f "${EXPAT_PREFIX}/lib/libexpat.a"

(
  cd "${UNBOUND_SOURCE}"
  patch --dry-run --fuzz=0 -p1 < "${PATCH_PATH}"
  patch --fuzz=0 -p1 < "${PATCH_PATH}"
)

(
  cd "${UNBOUND_SOURCE}"
  export PATH="${PROTOBUF_C_PREFIX}/bin:${PROTOBUF_PREFIX}/bin:${PATH}"
  export PKG_CONFIG_PATH="${PROTOBUF_C_PREFIX}/lib/pkgconfig:${PROTOBUF_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
  export SOURCE_DATE_EPOCH
  CFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=${WORK_DIR}=/usr/src/nodeping-unbound" \
    ./configure \
    --prefix="${UNBOUND_INSTALL_PREFIX}" \
    --with-ssl="${OPENSSL_CONFIGURE_PREFIX}" \
    --with-libevent="${LIBEVENT_CONFIGURE_PREFIX}" \
    --with-libexpat="${EXPAT_CONFIGURE_PREFIX}" \
    --enable-dnstap \
    --enable-static \
    --disable-shared \
    --disable-rpath \
    --with-protobuf-c="../protobuf-c-install"
  configured_ldflags="$(sed -n 's/^LDFLAGS=//p' Makefile)"
  if [[ -z "${configured_ldflags}" ]]; then
    printf 'configured Unbound LDFLAGS are empty\n' >&2
    exit 1
  fi
  grep -Fx '#define USE_DNSTAP 1' config.h
  make -j "${build_jobs}" unbound \
    LDFLAGS="${configured_ldflags} $(link_map_ldflags "${LINK_MAP_DIR}/unbound.map")"
  make -j "${build_jobs}" unbound-checkconf \
    LDFLAGS="${configured_ldflags} $(link_map_ldflags "${LINK_MAP_DIR}/unbound-checkconf.map")"
  make -j "${build_jobs}" unbound-anchor \
    LDFLAGS="${configured_ldflags} $(link_map_ldflags "${LINK_MAP_DIR}/unbound-anchor.map")"
  for link_map_name in unbound unbound-checkconf unbound-anchor; do
    test -s "${LINK_MAP_DIR}/${link_map_name}.map"
  done
  ./unbound -V | grep -Fx "Version ${UNBOUND_VERSION}"
  anchor_help="$(./unbound-anchor -h 2>&1 || true)"
  grep -Fx "Version ${UNBOUND_VERSION}" <<< "${anchor_help}"

  for binary_name in unbound unbound-checkconf unbound-anchor; do
    binary_path="./${binary_name}"
    if [[ -x ".libs/${binary_name}" ]]; then
      binary_path=".libs/${binary_name}"
    fi
    strings_path="${WORK_DIR}/${binary_name}.strings"
    strings "${binary_path}" > "${strings_path}"
    if grep -F "${WORK_DIR}" "${strings_path}" >/dev/null; then
      printf 'binary contains its random build root: %s\n' "${binary_name}" >&2
      grep -F "${WORK_DIR}" "${strings_path}" | head -n 10 >&2
      exit 1
    fi
    case "$(uname -s)" in
      Darwin)
        dynamic_dependencies="$(otool -L "${binary_path}")"
        ;;
      Linux)
        dynamic_dependencies="$(ldd "${binary_path}")"
        ;;
      *)
        printf 'unsupported dependency-inspection platform: %s\n' "$(uname -s)" >&2
        exit 1
        ;;
    esac
    if grep -Eiq 'lib(crypto|ssl|event|expat|protobuf-c)' <<< "${dynamic_dependencies}"; then
      printf 'binary uses a dynamic pinned dependency: %s\n%s\n' \
        "${binary_name}" "${dynamic_dependencies}" >&2
      exit 1
    fi
    cp "${binary_path}" "${OUTPUT_STAGE}/${binary_name}"
    chmod 0755 "${OUTPUT_STAGE}/${binary_name}"
    printf 'binary_sha256 %s %s\n' "${binary_name}" "$(sha256_file "${binary_path}")"
  done
)

go -C "${METADATA_TOOL_DIR}" run . generate \
  --artifact-dir "${OUTPUT_STAGE}" \
  --link-map-dir "${LINK_MAP_DIR}" \
  --license-source-dir "${REPOSITORY_ROOT}/third_party/unbound" \
  --patch-path "${PATCH_PATH}" \
  --target-os "${target_os}" \
  --target-arch "${target_arch}" \
  --compiler "${CC:-cc}" \
  --sdk-name "${NODEPING_UNBOUND_SDK_NAME:-}" \
  --sdk-version "${NODEPING_UNBOUND_SDK_VERSION:-}" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}"

for metadata_relative_path in \
  THIRD_PARTY_NOTICES.md \
  licenses/unbound-BSD-3-Clause.txt \
  licenses/openssl-Apache-2.0.txt \
  licenses/libevent-BSD-3-Clause.txt \
  licenses/expat-MIT.txt \
  licenses/protobuf-c-BSD-2-Clause.txt \
  licenses/protobuf-BSD-3-Clause.txt \
  unbound.cdx.json \
  unbound.spdx.json \
  unbound-checkconf.cdx.json \
  unbound-checkconf.spdx.json \
  unbound-anchor.cdx.json \
  unbound-anchor.spdx.json \
  unbound-helper-manifest.json; do
  metadata_path="${OUTPUT_STAGE}/${metadata_relative_path}"
  test -s "${metadata_path}"
  printf 'metadata_sha256 %s %s\n' \
    "${metadata_relative_path}" "$(sha256_file "${metadata_path}")"
done

if [[ -n "${OUTPUT_DIR}" ]]; then
  mkdir -p "${OUTPUT_DIR}"
  cp -R "${OUTPUT_STAGE}/." "${OUTPUT_DIR}/"
  printf 'verified_helper_output %s\n' "${OUTPUT_DIR}"
fi

printf 'Unbound %s dnstap patch clean-apply/build verification passed\n' "${UNBOUND_VERSION}"
