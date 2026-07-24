#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 077

readonly ACTIONLINT_VERSION="1.7.12"
readonly SHELLCHECK_VERSION="0.11.0"

for command_name in curl tar; do
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
    printf 'SHA-256 mismatch for %s: got %s, want %s\n' \
      "${path}" "${actual}" "${expected}" >&2
    exit 1
  fi
}

case "$(uname -s)" in
  Darwin)
    platform=darwin
    ;;
  Linux)
    platform=linux
    ;;
  *)
    printf 'unsupported lint platform: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64 | aarch64)
    actionlint_arch=arm64
    shellcheck_arch=aarch64
    ;;
  amd64 | x86_64)
    actionlint_arch=amd64
    shellcheck_arch=x86_64
    ;;
  *)
    printf 'unsupported lint architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

case "${platform}/${actionlint_arch}" in
  darwin/amd64)
    actionlint_sha256=5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644
    ;;
  darwin/arm64)
    actionlint_sha256=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
    ;;
  linux/amd64)
    actionlint_sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    ;;
  linux/arm64)
    actionlint_sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
    ;;
esac

case "${platform}/${shellcheck_arch}" in
  darwin/x86_64)
    shellcheck_sha256=3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
    ;;
  darwin/aarch64)
    shellcheck_sha256=56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
    ;;
  linux/x86_64)
    shellcheck_sha256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
    ;;
  linux/aarch64)
    shellcheck_sha256=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
    ;;
esac

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPOSITORY_ROOT
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nodeping-agent-lint.XXXXXX")"
readonly WORK_DIR
cleanup() {
  rm -R -- "${WORK_DIR}"
}
trap cleanup EXIT

readonly ACTIONLINT_ARCHIVE="${WORK_DIR}/actionlint.tar.gz"
readonly SHELLCHECK_ARCHIVE="${WORK_DIR}/shellcheck.tar.xz"
readonly ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_${platform}_${actionlint_arch}.tar.gz"
readonly SHELLCHECK_URL="https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.${platform}.${shellcheck_arch}.tar.xz"

curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
  --silent --show-error --output "${ACTIONLINT_ARCHIVE}" "${ACTIONLINT_URL}"
curl --fail --location --proto '=https' --retry 3 --retry-all-errors \
  --silent --show-error --output "${SHELLCHECK_ARCHIVE}" "${SHELLCHECK_URL}"
verify_sha256 "${ACTIONLINT_ARCHIVE}" "${actionlint_sha256}"
verify_sha256 "${SHELLCHECK_ARCHIVE}" "${shellcheck_sha256}"

tar -xzf "${ACTIONLINT_ARCHIVE}" -C "${WORK_DIR}" actionlint
tar -xJf "${SHELLCHECK_ARCHIVE}" -C "${WORK_DIR}"
readonly ACTIONLINT_BINARY="${WORK_DIR}/actionlint"
readonly SHELLCHECK_BINARY="${WORK_DIR}/shellcheck-v${SHELLCHECK_VERSION}/shellcheck"

actionlint_reported_version="$("${ACTIONLINT_BINARY}" -version 2>&1 | sed -n '1p')"
if [[ "${actionlint_reported_version}" != "${ACTIONLINT_VERSION}" ]]; then
  printf 'actionlint version mismatch: got %s, want %s\n' \
    "${actionlint_reported_version}" "${ACTIONLINT_VERSION}" >&2
  exit 1
fi
shellcheck_reported_version="$("${SHELLCHECK_BINARY}" --version | awk '$1 == "version:" { print $2 }')"
if [[ "${shellcheck_reported_version}" != "${SHELLCHECK_VERSION}" ]]; then
  printf 'ShellCheck version mismatch: got %s, want %s\n' \
    "${shellcheck_reported_version}" "${SHELLCHECK_VERSION}" >&2
  exit 1
fi

cd "${REPOSITORY_ROOT}"
"${ACTIONLINT_BINARY}" -no-color -shellcheck="${SHELLCHECK_BINARY}"
for script_path in \
  scripts/agent-upgrade-compatibility.sh \
  scripts/agent-upgrade-compatibility_test.sh \
  scripts/release-tag.sh \
  scripts/release-tag_test.sh \
  scripts/ci/lint-agent-workflows.sh \
  scripts/ci/test-agent-image-compatibility.sh \
  scripts/ci/verify-unbound-dnstap-patch.sh \
  scripts/ci/verify-unbound-dnstap-reproducible.sh \
  scripts/ci/verify-unbound-helper-metadata.sh \
  scripts/ci/verify-root-material-supply-chain.sh \
  scripts/ci/verify-unbound-source-provenance.sh \
  deploy/nodeping-agent/container-entrypoint.sh; do
  "${SHELLCHECK_BINARY}" -x "${script_path}"
done

printf 'Agent workflow and shell static checks passed\n'
