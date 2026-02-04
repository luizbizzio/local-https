#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_URL_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main/local-https.sh"
SCRIPT_URL="${LOCAL_HTTPS_SOURCE_URL:-$SCRIPT_URL_DEFAULT}"

INSTALL_PATH="${LOCAL_HTTPS_INSTALL_PATH:-/usr/local/sbin/local-https}"

EXPECTED_SHA256="PUT_SHA256_HERE"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
die() { echo -e "\033[31m[ERROR]\033[0m $1" >&2; exit 1; }

[ "${EXPECTED_SHA256}" != "PUT_SHA256_HERE" ] || die "Replace PUT_SHA256_HERE with the real sha256"

if [ "$(id -u)" -ne 0 ]; then
  die "Run as root. Example: curl -fsSL https://raw.githubusercontent.com/luizbizzio/local-https/main/install.sh | sudo bash"
fi

DL=""
if need_cmd curl; then
  DL="curl"
elif need_cmd wget; then
  DL="wget"
else
  die "Need curl or wget"
fi

TMPDIR="$(mktemp -d)"
chmod 700 "$TMPDIR" >/dev/null 2>&1 || true
TMPFILE="$TMPDIR/local-https.sh"

cleanup() { rm -rf "$TMPDIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [ "$DL" = "curl" ]; then
  curl -fsSL "$SCRIPT_URL" -o "$TMPFILE" || die "Download failed: $SCRIPT_URL"
else
  wget -qO "$TMPFILE" "$SCRIPT_URL" || die "Download failed: $SCRIPT_URL"
fi

[ -s "$TMPFILE" ] || die "Downloaded file is empty"
head -n 1 "$TMPFILE" | grep -qE '^#!/(usr/bin/env bash|bin/bash)$' || die "Downloaded file does not look like a bash script"

if need_cmd sha256sum; then
  ACTUAL_SHA256="$(sha256sum "$TMPFILE" | awk '{print $1}')"
elif need_cmd shasum; then
  ACTUAL_SHA256="$(shasum -a 256 "$TMPFILE" | awk '{print $1}')"
else
  die "Need sha256sum or shasum"
fi

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "Expected: $EXPECTED_SHA256" >&2
  echo "Actual:   $ACTUAL_SHA256" >&2
  die "SHA256 mismatch. Refusing to install."
fi

install -d -m 755 "$(dirname "$INSTALL_PATH")" >/dev/null 2>&1 || true
install -m 755 "$TMPFILE" "$INSTALL_PATH" || die "Install failed: $INSTALL_PATH"

echo -e "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"
exec "$INSTALL_PATH" --install
