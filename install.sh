#!/usr/bin/env bash
# Keyla Everywhere installer.
#
# Default: download the latest release asset for this platform. If no release
# exists yet (or the requested asset is missing), build from the tagged source
# checkout instead. No GitHub API token is required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/clovieflow/keyla-everywhere/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --source
#   KEYLA_VERSION=1.2.3 bash install.sh --binary
#
# Environment:
#   KEYLA_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   KEYLA_SOURCE_DIR   source checkout (default: ~/.local/share/keyla-src)
#   KEYLA_VERSION      release tag without the leading v (default: latest)
#   KEYLA_REPO         owner/repo (default: clovieflow/keyla-everywhere)

set -euo pipefail

REPO="${KEYLA_REPO:-clovieflow/keyla-everywhere}"
INSTALL_DIR="${KEYLA_INSTALL_DIR:-${HOME}/.local/bin}"
SOURCE_DIR="${KEYLA_SOURCE_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/keyla-src}"
VERSION="${KEYLA_VERSION:-}"
MODE="auto"

usage() {
  cat <<'USAGE'
Keyla Everywhere installer.

Default: download the latest release asset for this platform. If no release
exists yet, build from the source checkout instead.

Usage:
  curl -fsSL https://raw.githubusercontent.com/clovieflow/keyla-everywhere/main/install.sh | bash
  bash install.sh --source
  KEYLA_VERSION=1.0.0 bash install.sh --binary

Environment:
  KEYLA_INSTALL_DIR  destination directory (default: ~/.local/bin)
  KEYLA_SOURCE_DIR   source checkout (default: ~/.local/share/keyla-src)
  KEYLA_VERSION      release tag without v (default: latest)
  KEYLA_REPO         owner/repo (default: clovieflow/keyla-everywhere)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) MODE="source"; shift ;;
    --binary) MODE="binary"; shift ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --dir) INSTALL_DIR="${2:?--dir needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64) PLATFORM="linux-x64" ;;
  Linux/aarch64|Linux/arm64) PLATFORM="linux-arm64" ;;
  Darwin/arm64) PLATFORM="darwin-arm64" ;;
  Darwin/x86_64) PLATFORM="darwin-x64" ;;
  *) echo "Unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

install_binary() {
  local source="$1"
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$source" "$INSTALL_DIR/keyla"
  echo "Installed: $INSTALL_DIR/keyla"
  echo
  echo "Next:"
  echo "  keyla setup        # create .env and an encryption key"
  echo "  keyla doctor       # check PostgreSQL and migrations"
  echo "  keyla up           # run in the foreground"
  echo
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Add $INSTALL_DIR to PATH to run 'keyla' without an absolute path." ;;
  esac
}

download_binary() {
  local base
  if [ -n "$VERSION" ]; then
    base="https://github.com/${REPO}/releases/download/v${VERSION#v}"
  else
    base="https://github.com/${REPO}/releases/latest/download"
  fi
  local asset="keyla-${PLATFORM}"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/keyla.XXXXXX")"
  trap 'rm -f "$tmp" "${tmp}.sha256"' RETURN
  echo "Downloading ${base}/${asset}"
  if ! curl --fail --silent --show-error --location --retry 3 \
    --output "$tmp" "${base}/${asset}"; then
    rm -f "$tmp"
    return 1
  fi
  if curl --fail --silent --show-error --location --retry 3 \
    --output "${tmp}.sha256" "${base}/${asset}.sha256" 2>/dev/null; then
    local expected actual
    expected="$(awk '{print $1}' "${tmp}.sha256")"
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "$tmp" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
    fi
    if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
      echo "Checksum mismatch for ${asset}" >&2
      rm -f "$tmp" "${tmp}.sha256"
      return 1
    fi
  fi
  chmod 0755 "$tmp"
  install_binary "$tmp"
}

build_from_source() {
  need git
  need bun
  need cargo
  echo "No usable release asset; building from source at ${SOURCE_DIR}"
  if [ -d "${SOURCE_DIR}/.git" ]; then
    if [ -n "$(git -C "$SOURCE_DIR" status --porcelain)" ]; then
      echo "Source checkout is dirty: ${SOURCE_DIR}" >&2
      echo "Clean it or set KEYLA_SOURCE_DIR to a clean checkout." >&2
      exit 1
    fi
    git -C "$SOURCE_DIR" fetch --depth 1 origin main
    git -C "$SOURCE_DIR" checkout --detach origin/main
  else
    mkdir -p "$(dirname "$SOURCE_DIR")"
    git clone --depth 1 "https://github.com/${REPO}.git" "$SOURCE_DIR"
  fi
  ( cd "$SOURCE_DIR"
    bun install --frozen-lockfile
    bun run dashboard:build
    cargo build --release --locked -p keyla-cli --bin keyla
  )
  install_binary "${SOURCE_DIR}/target/release/keyla"
}

case "$MODE" in
  source) build_from_source ;;
  binary)
    if ! download_binary; then
      echo "No release binary found for ${PLATFORM}." >&2
      exit 1
    fi
    ;;
  auto)
    if ! download_binary; then
      build_from_source
    fi
    ;;
esac
