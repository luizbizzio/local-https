#!/bin/bash
set -e
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

die() { echo -e "\033[31m[ERROR]\033[0m $1" >&2; exit 1; }
info() { echo -e "\033[34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[32m[OK]\033[0m $1"; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."

command -v curl >/dev/null 2>&1 || die "curl not found."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found."
command -v install >/dev/null 2>&1 || die "install not found."

INSTALL_PATH="${LOCAL_HTTPS_INSTALL_PATH:-/usr/local/sbin/local-https}"
SCRIPT_URL_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main/local-https.sh"
SCRIPT_URL="${LOCAL_HTTPS_SOURCE_URL:-$SCRIPT_URL_DEFAULT}"

EXPECTED_SHA256="b6e8ba5faaaa8451896439566a0d4cdf7bb0268cc03bc7e54c800e2ae62cb36d"

TMP="$(mktemp)"
chmod 700 "$TMP" >/dev/null 2>&1 || true
cleanup() { rm -f "$TMP" >/dev/null 2>&1 || true; }
trap cleanup EXIT

info "Downloading: $SCRIPT_URL"
curl -fsSL "$SCRIPT_URL" -o "$TMP" || die "Download failed."

GOT_SHA256="$(sha256sum "$TMP" | awk '{print $1}')"
[ "$GOT_SHA256" = "$EXPECTED_SHA256" ] || die "SHA-256 mismatch. Expected $EXPECTED_SHA256 but got $GOT_SHA256"

ok "SHA-256 verified."
install -d -m 755 "$(dirname "$INSTALL_PATH")" >/dev/null 2>&1 || true
install -m 755 "$TMP" "$INSTALL_PATH" || die "Install failed."

ok "Installed: $INSTALL_PATH"

NI="0"
[ -t 0 ] || NI="1"

exec env LOCAL_HTTPS_BOOTSTRAP=1 LOCAL_HTTPS_NONINTERACTIVE="$NI" "$INSTALL_PATH" --install
