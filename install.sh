#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REPO_RAW_BASE_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main"
REPO_RAW_BASE="${LOCAL_HTTPS_RAW_BASE:-$REPO_RAW_BASE_DEFAULT}"

SCRIPT_NAME="local-https"
INSTALL_PATH="/usr/local/sbin/local-https"
SOURCE_URL_DEFAULT="${REPO_RAW_BASE}/local-https.sh"
SOURCE_URL="${LOCAL_HTTPS_SOURCE_URL:-$SOURCE_URL_DEFAULT}"

EXPECTED_SHA256_DEFAULT="51cdad5046718e6837731a8800bf7e4efd2d583ba0643dbc5d5b909c55752ed0"
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
      "$INSTALL_PATH" --install
  fi

  exec env \
    LOCAL_HTTPS_BOOTSTRAP=1 \
    LOCAL_HTTPS_NONINTERACTIVE=1 \
    LOCAL_HTTPS_AUTO_PIHOLE="${LOCAL_HTTPS_AUTO_PIHOLE:-}" \
    "$INSTALL_PATH" --install
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

  local tmp=""
  cleanup() { [ -n "$tmp" ] && rm -f "$tmp" >/dev/null 2>&1 || true; }
  trap cleanup EXIT

  out "\033[36m[INFO]\033[0m Downloading: $SOURCE_URL"

  tmp="$(tmpfile_make)"
  curl_fetch "$SOURCE_URL" "$tmp" || die "Download failed."

  verify_sha256_if_set "$tmp"
  sanity_check_script "$tmp"

  out "\033[36m[INFO]\033[0m Installing: $INSTALL_PATH"
  install_atomic "$tmp" "$INSTALL_PATH"

  out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"

  run_installer_interactive
}

main "$@"
