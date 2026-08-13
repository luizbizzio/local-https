#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2024-2026 Luiz Bizzio
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REPO_RAW_BASE_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main"
REPO_RAW_BASE="${LOCAL_HTTPS_RAW_BASE:-$REPO_RAW_BASE_DEFAULT}"
SCRIPT_NAME="local-https"
INSTALL_PATH="/usr/local/sbin/local-https"
SOURCE_URL_DEFAULT="${REPO_RAW_BASE}/local-https.sh"
SOURCE_URL="${LOCAL_HTTPS_SOURCE_URL:-$SOURCE_URL_DEFAULT}"

EXPECTED_SHA256_DEFAULT="7521956ac681eb1683c40c5cd82899ca0c762f3f712f3f9888c8ec341a748880"
EXPECTED_SHA256="${LOCAL_HTTPS_EXPECTED_SHA256:-$EXPECTED_SHA256_DEFAULT}"

NONINTERACTIVE="${LOCAL_HTTPS_NONINTERACTIVE:-0}"
UPDATE_ONLY="${LOCAL_HTTPS_UPDATE_ONLY:-0}"
case "$NONINTERACTIVE" in 1|true|TRUE|yes|YES) NONINTERACTIVE=1 ;; *) NONINTERACTIVE=0 ;; esac
case "$UPDATE_ONLY" in 1|true|TRUE|yes|YES) UPDATE_ONLY=1 ;; *) UPDATE_ONLY=0 ;; esac
out() { printf '%b\n' "$1"; }
die() { printf '%b\n' "\033[31m[ERROR]\033[0m $1\n" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run as root. Use: curl ... | sudo bash"
}

tmpfile_make() {
  mktemp -p /tmp local-https.install.XXXXXX
}

curl_fetch() {
  local url="$1"
  local out_file="$2"

  curl -fsSL --proto '=https' --tlsv1.2 \
    --connect-timeout 10 \
    --max-time 60 \
    -o "$out_file" \
    "$url"
}
sha256_of_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'
    return 0
  fi
  return 1
}

verify_sha256_if_set() {
  local f="$1"

  [ -n "$EXPECTED_SHA256" ] || return 0
  local got=""
  got="$(sha256_of_file "$f" 2>/dev/null || true)"
  [ -n "$got" ] || die "Cannot compute SHA-256."

  [ "$got" = "$EXPECTED_SHA256" ] || \
    die "SHA-256 mismatch. Expected: $EXPECTED_SHA256 | Got: $got"

  out "\033[32m[OK]\033[0m SHA-256 verified."
}

sanity_check_script() {
  local f="$1"

  [ -s "$f" ] || die "Downloaded file is empty."
  [ "$(wc -c < "$f")" -ge 2000 ] || die "Downloaded file too small."

  head -n 1 "$f" | grep -Eq '^#!' || die "Missing shebang."
  if head -n 5 "$f" | grep -Eqi '<!doctype html|<html|404'; then
    die "Downloaded content looks like HTML."
  fi

  grep -qE 'SCRIPT_CMD_NAME="local-https"|parse_cli' "$f" || \
    die "Downloaded file does not look like local-https.sh."

  bash -n "$f" >/dev/null 2>&1 || die "Downloaded local-https.sh failed syntax validation."
}

script_version_from_file() {
  local f="$1"
  awk -F'"' '/^[[:space:]]*VERSION="[0-9]+\.[0-9]+\.[0-9]+"/ { print $2; exit }' "$f" 2>/dev/null || true
}

installed_version() {
  [ -x "$INSTALL_PATH" ] || return 0
  "$INSTALL_PATH" --version 2>/dev/null | awk '{ print $NF; exit }' || true
}

install_atomic() {
  local src="$1"
  local dst="$2"
  local d
  d="$(dirname "$dst")"

  install -d -m 755 "$d"

  local tmpdst
  tmpdst="$(mktemp "$d/.local-https.tmp.XXXXXX")"
  chmod 700 "$tmpdst"

  install -m 755 "$src" "$tmpdst"
  mv -f "$tmpdst" "$dst"
}

run_installer_interactive() {
  out "\033[36m[INFO]\033[0m Running: local-https --install"

  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    exec </dev/tty >/dev/tty 2>/dev/tty env \
      LOCAL_HTTPS_BOOTSTRAP=1 \
      LOCAL_HTTPS_NONINTERACTIVE="$NONINTERACTIVE" \
      LOCAL_HTTPS_AUTO_PIHOLE="${LOCAL_HTTPS_AUTO_PIHOLE:-}" \
      LOCAL_HTTPS_DOMAIN="${LOCAL_HTTPS_DOMAIN:-}" \
      "$INSTALL_PATH" --install
  fi
  exec env \
    LOCAL_HTTPS_BOOTSTRAP=1 \
    LOCAL_HTTPS_NONINTERACTIVE=1 \
    LOCAL_HTTPS_AUTO_PIHOLE="${LOCAL_HTTPS_AUTO_PIHOLE:-}" \
    LOCAL_HTTPS_DOMAIN="${LOCAL_HTTPS_DOMAIN:-}" \
    "$INSTALL_PATH" --install
}

prompt_run_setup() {
  if [ "$NONINTERACTIVE" -eq 1 ]; then
    run_installer_interactive
  fi

  if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    out "\033[34m[INFO]\033[0m No interactive terminal detected. Running setup non-interactively."
    run_installer_interactive
  fi

  local answer=""
  printf '%b' "\033[36m[?]\033[0m Run the initial setup now? (Y/n): " >/dev/tty
  read -r answer </dev/tty || answer=""

  case "$answer" in
    n|N|no|NO)
      out "\033[34m[INFO]\033[0m Setup skipped."
      out "\033[34m[INFO]\033[0m Run it later with: sudo local-https --install"
      ;;
    *)
      run_installer_interactive
      ;;
  esac
}

main() {
  require_root
  need_cmd curl
  need_cmd install
  need_cmd mktemp
  need_cmd grep
  need_cmd head
  need_cmd wc
  need_cmd awk
  need_cmd dirname
  need_cmd mv
  need_cmd chmod
  need_cmd rm
  need_cmd bash
  local tmp=""
  cleanup() { [ -n "${tmp:-}" ] && rm -f "$tmp" >/dev/null 2>&1 || true; }
  trap cleanup EXIT

  local had_binary=0
  local was_configured=0
  local current_version=""
  local target_version=""

  [ -f "$INSTALL_PATH" ] && had_binary=1

  if [ -f "/var/lib/local-https/installed" ] || [ -f "/var/lib/local-https/state.env" ]; then
    was_configured=1
  fi

  if [ "$had_binary" -eq 1 ]; then
    current_version="$(installed_version)"
  fi

  out "\033[36m[INFO]\033[0m Downloading: $SOURCE_URL"

  tmp="$(tmpfile_make)"
  curl_fetch "$SOURCE_URL" "$tmp" || die "Download failed."

  verify_sha256_if_set "$tmp"
  sanity_check_script "$tmp"

  target_version="$(script_version_from_file "$tmp")"

  if [ "$had_binary" -eq 1 ]; then
    if [ -n "$current_version" ] && [ -n "$target_version" ] && [ "$current_version" = "$target_version" ]; then
      out "\033[36m[INFO]\033[0m Reinstalling local-https v${target_version}..."
    elif [ -n "$current_version" ] && [ -n "$target_version" ]; then
      out "\033[36m[INFO]\033[0m Updating local-https v${current_version} -> v${target_version}..."
    elif [ -n "$target_version" ]; then
      out "\033[36m[INFO]\033[0m Updating local-https to v${target_version}..."
    else
      out "\033[36m[INFO]\033[0m Updating: $INSTALL_PATH"
    fi
  else
    if [ -n "$target_version" ]; then
      out "\033[36m[INFO]\033[0m Installing local-https v${target_version}..."
    else
      out "\033[36m[INFO]\033[0m Installing: $INSTALL_PATH"
    fi
  fi

  install_atomic "$tmp" "$INSTALL_PATH"
  rm -f "$tmp" >/dev/null 2>&1 || true
  tmp=""

  if [ "$had_binary" -eq 1 ]; then
    out "\033[32m[OK]\033[0m Updated: $INSTALL_PATH"
  else
    out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"
  fi

  "$INSTALL_PATH" --version 2>/dev/null || true

  if [ "$UPDATE_ONLY" -eq 1 ]; then
    if [ "$was_configured" -eq 1 ]; then
      out "\033[34m[INFO]\033[0m Existing certificates and configuration were kept."
    else
      out "\033[34m[INFO]\033[0m Program updated. Initial setup was not changed."
    fi
    exit 0
  fi

  if [ "$was_configured" -eq 1 ]; then
    out "\033[34m[INFO]\033[0m Existing certificates and configuration were kept."
    exit 0
  fi

  if [ "$had_binary" -eq 1 ]; then
    out "\033[34m[INFO]\033[0m No completed setup was detected."
  fi

  echo ""
  prompt_run_setup
}

main "$@"
