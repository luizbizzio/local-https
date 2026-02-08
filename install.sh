#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REPO_RAW_BASE_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main"
REPO_RAW_BASE="${LOCAL_HTTPS_RAW_BASE:-$REPO_RAW_BASE_DEFAULT}"

SCRIPT_NAME="local-https"
INSTALL_PATH="/usr/local/sbin/local-https"
SOURCE_URL_DEFAULT="${REPO_RAW_BASE}/local-https.sh"
SOURCE_URL="${LOCAL_HTTPS_SOURCE_URL:-$SOURCE_URL_DEFAULT}"

EXPECTED_SHA256_DEFAULT="99b1c6b27f4fcc862f6616fef9b6a04a96af0af0c072504515ae169076947ec5"
EXPECTED_SHA256="${LOCAL_HTTPS_EXPECTED_SHA256:-$EXPECTED_SHA256_DEFAULT}"

NONINTERACTIVE="${LOCAL_HTTPS_NONINTERACTIVE:-0}"
case "$NONINTERACTIVE" in 1|true|TRUE|yes|YES) NONINTERACTIVE=1 ;; *) NONINTERACTIVE=0 ;; esac

out() { printf '%b\n' "$1"; }
die() { printf '%b\n' "\033[31m[ERROR]\033[0m $1\n" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run as root. Use: curl ... | sudo bash"
}

tmpfile_make() {
  local t=""
  t="$(mktemp -p /tmp local-https.install.XXXXXX)"
  chmod 600 "$t" >/dev/null 2>&1 || true
  echo "$t"
}

curl_fetch() {
  local url="$1"
  local out_file="$2"

  curl -fsSL --proto '=https' --tlsv1.2 \
    --connect-timeout 10 \
    --max-time 60 \
    "$url" -o "$out_file"
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

  if [ -z "$EXPECTED_SHA256" ]; then
    out "\033[33m[WARN]\033[0m No expected SHA-256 set. Skipping hash verification."
    return 0
  fi

  local got=""
  got="$(sha256_of_file "$f" 2>/dev/null || true)"
  [ -n "$got" ] || die "Cannot compute SHA-256 (need sha256sum/shasum/openssl)."

  if [ "$got" != "$EXPECTED_SHA256" ]; then
    die "SHA-256 mismatch. Expected: $EXPECTED_SHA256 | Got: $got"
  fi

  out "\033[32m[OK]\033[0m SHA-256 verified."
}

sanity_check_script() {
  local f="$1"

  [ -s "$f" ] || die "Downloaded file is empty."
  local bytes=0
  bytes="$(wc -c < "$f" 2>/dev/null | tr -d ' ' || echo 0)"
  [ "$bytes" -ge 2000 ] || die "Downloaded file too small ($bytes bytes). Refusing."

  head -n 1 "$f" | grep -Eq '^#!' || die "Downloaded file has no shebang. Refusing."

  if head -n 5 "$f" | grep -Eqi '<!doctype html|<html|github.com.*404|not found'; then
    die "Downloaded content looks like HTML/404 page. Refusing."
  fi

  if ! grep -qE 'SCRIPT_CMD_NAME="local-https"|INSTALL_PATH="/usr/local/sbin/local-https"|parse_cli' "$f" 2>/dev/null; then
    die "Downloaded file does not look like local-https.sh. Refusing."
  fi
}

install_atomic() {
  local src="$1"
  local dst="$2"

  install -d -m 755 "$(dirname "$dst")" >/dev/null 2>&1 || true

  local tmpdst=""
  tmpdst="$(mktemp -p /tmp local-https.bin.XXXXXX)"
  chmod 700 "$tmpdst" >/dev/null 2>&1 || true

  install -m 755 "$src" "$tmpdst" >/dev/null 2>&1 || die "Failed to stage install."
  mv -f "$tmpdst" "$dst" >/dev/null 2>&1 || die "Failed to move into place."
  chmod 755 "$dst" >/dev/null 2>&1 || true
}

run_installer_interactive() {
  out "\033[36m[INFO]\033[0m Running: local-https --install"

  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    exec </dev/tty >/dev/tty 2>/dev/tty env \
      LOCAL_HTTPS_BOOTSTRAP=1 \
      LOCAL_HTTPS_NONINTERACTIVE=0 \
      "$INSTALL_PATH" --install
  fi

  if [ -t 0 ]; then
    exec env LOCAL_HTTPS_BOOTSTRAP=1 LOCAL_HTTPS_NONINTERACTIVE=0 "$INSTALL_PATH" --install
  fi

  die "Interactive input is required, but no TTY is available. Download then run: curl -fsSL \"$SOURCE_URL\" -o local-https.sh && sudo bash local-https.sh --install"
}

main() {
  require_root
  need_cmd curl
  need_cmd install
  need_cmd mktemp
  need_cmd grep
  need_cmd head
  need_cmd wc

  out "\033[36m[INFO]\033[0m Downloading: $SOURCE_URL"

  local tmp=""
  tmp="$(tmpfile_make)"

  if curl_fetch "$SOURCE_URL" "$tmp"; then
    :
  else
    rm -f "$tmp" >/dev/null 2>&1 || true
    die "Download failed."
  fi

  verify_sha256_if_set "$tmp"
  sanity_check_script "$tmp"

  out "\033[36m[INFO]\033[0m Installing: $INSTALL_PATH"
  install_atomic "$tmp" "$INSTALL_PATH"
  rm -f "$tmp" >/dev/null 2>&1 || true

  out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"

  run_installer_interactive
}

main "$@"
