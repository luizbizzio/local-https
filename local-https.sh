#!/bin/bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

STEP_DELAY="${STEP_DELAY:-0.7}"

NONINTERACTIVE="${LOCAL_HTTPS_NONINTERACTIVE:-0}"
VERBOSE="${LOCAL_HTTPS_VERBOSE:-0}"
BOOTSTRAP="${LOCAL_HTTPS_BOOTSTRAP:-0}"

SAN_MAX_IPS="${LOCAL_HTTPS_SAN_MAX_IPS:-20}"
ADD_SUDO_USER_TO_CERT_GROUP="${LOCAL_HTTPS_ADD_SUDO_USER_TO_CERT_GROUP:-0}"
TECH_INSECURE_TLS="${LOCAL_HTTPS_TECH_INSECURE_TLS:-0}"
case "$TECH_INSECURE_TLS" in 1|true|TRUE|yes|YES) TECH_INSECURE_TLS=1 ;; *) TECH_INSECURE_TLS=0 ;; esac

case "$NONINTERACTIVE" in 1|true|TRUE|yes|YES) NONINTERACTIVE=1 ;; *) NONINTERACTIVE=0 ;; esac
case "$VERBOSE" in 1|true|TRUE|yes|YES) VERBOSE=1 ;; *) VERBOSE=0 ;; esac
case "$BOOTSTRAP" in 1|true|TRUE|yes|YES) BOOTSTRAP=1 ;; *) BOOTSTRAP=0 ;; esac
case "$ADD_SUDO_USER_TO_CERT_GROUP" in 1|true|TRUE|yes|YES) ADD_SUDO_USER_TO_CERT_GROUP=1 ;; *) ADD_SUDO_USER_TO_CERT_GROUP=0 ;; esac
AUTO_PIHOLE="${LOCAL_HTTPS_AUTO_PIHOLE:-}"

case "$AUTO_PIHOLE" in
  1|true|TRUE|yes|YES) AUTO_PIHOLE=1 ;;
  0|false|FALSE|no|NO) AUTO_PIHOLE=0 ;;
  "")
    if [ "$BOOTSTRAP" -eq 1 ]; then
      AUTO_PIHOLE=1
    else
      AUTO_PIHOLE=0
    fi
    ;;
  *) AUTO_PIHOLE=0 ;;
esac

[ ! -t 0 ] && NONINTERACTIVE=1

pause_step() { [ "$NONINTERACTIVE" -eq 1 ] && return 0; [ ! -t 1 ] && return 0; sleep "$STEP_DELAY"; }

out() { printf '%b\n' "$1"; pause_step; }
vout() { [ "$VERBOSE" -eq 1 ] && out "$1" || true; }
die() { printf '%b\n' "\033[31m[ERROR]\033[0m $1" >&2; exit 1; }

SCRIPT_CMD_NAME="local-https"
INSTALL_PATH="/usr/local/sbin/local-https"

SCRIPT_SOURCE_URL_DEFAULT="https://raw.githubusercontent.com/luizbizzio/local-https/main/local-https.sh"
SCRIPT_SOURCE_URL="${LOCAL_HTTPS_SOURCE_URL:-$SCRIPT_SOURCE_URL_DEFAULT}"

SSL_DIR="/etc/ssl/servercerts"
CERT_GROUP="certs"

CA_KEY="$SSL_DIR/rootCA.key"
CA_CRT="$SSL_DIR/rootCA.crt"
CA_SRL="$SSL_DIR/rootCA.srl"

SERVER_KEY="$SSL_DIR/server.key"
SERVER_CSR="$SSL_DIR/server.csr"
SERVER_CRT="$SSL_DIR/server.crt"
SERVER_PEM="$SSL_DIR/server.pem"
SERVER_PFX="$SSL_DIR/server.pfx"

PFX_PASS_FILE="$SSL_DIR/.pfx-pass"
RENEW_WINDOW_SECONDS=$((7*24*3600))

CA_EC_CURVE="prime256v1"
SERVER_EC_CURVE="prime256v1"

PIHOLE_TOML="/etc/pihole/pihole.toml"
PIHOLE_FTL_CERT=""

PIHOLE_PRESENT=0
TECH_PRESENT=0
TECH_BASE_URL=""
TECH_SERVICE=""

FILTERED_IPS=""
TAILSCALE_DNS=""
TAILSCALE_SHORT=""

STATE_DIR="/var/lib/local-https"
STATE_FILE="$STATE_DIR/state.env"
INSTALL_MARKER="$STATE_DIR/installed"

SYSTEMD_SERVICE_PATH="/etc/systemd/system/local-https-renew.service"
SYSTEMD_TIMER_PATH="/etc/systemd/system/local-https-renew.timer"

CRON_LOG_PATH="/var/log/local-https-renew.log"
LOGROTATE_PATH="/etc/logrotate.d/local-https-renew"

AUTORENEW_METHOD="none"
CERT_RENEWED=0
FORCE_RENEW=0
UNINSTALL_YES=0
UNINSTALL_PURGE=0

has_systemctl() { command -v systemctl >/dev/null 2>&1; }
has_service_cmd() { command -v service >/dev/null 2>&1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }
has_logger() { command -v logger >/dev/null 2>&1; }

sh_quote() {
  local s="$1"
  printf "'%s'" "$(printf '%s' "$s" | sed "s/'/'\\\\''/g")"
}

state_unquote() {
  local v="$1"
  if [ -z "$v" ]; then
    printf '%s' ""
    return 0
  fi
  case "$v" in
    \'*\')
      v="${v#\'}"
      v="${v%\'}"
      v="${v//\'\\\'\'/\'}"
      printf '%s' "$v"
      return 0
      ;;
    *)
      printf '%s' "$v"
      return 0
      ;;
  esac
}

read_state_value() {
  local key="$1"
  [ -f "$STATE_FILE" ] || return 0
  local line val
  line="$(grep -E "^${key}=" "$STATE_FILE" 2>/dev/null | head -n1 || true)"
  [ -n "$line" ] || return 0
  val="${line#*=}"
  state_unquote "$val" || true
}

svc_active() {
  local name="$1"
  if has_systemctl; then
    systemctl is-active --quiet "$name" >/dev/null 2>&1
    return $?
  fi
  if has_service_cmd; then
    service "$name" status >/dev/null 2>&1
    return $?
  fi
  return 1
}

svc_restart() {
  local name="$1"
  if has_systemctl; then
    systemctl restart "$name" >/dev/null 2>&1 || return 1
    return 0
  fi
  if has_service_cmd; then
    service "$name" restart >/dev/null 2>&1 || return 1
    return 0
  fi
  return 1
}

svc_restart_cmd_hint() {
  local name="$1"
  if has_systemctl; then
    echo "sudo systemctl restart $name"
    return 0
  fi
  if has_service_cmd; then
    echo "sudo service $name restart"
    return 0
  fi
  echo "restart $name manually"
}

restart_or_warn() {
  local name="$1"
  local label="$2"
  if svc_restart "$name"; then
    out "\033[32m[✓]\033[0m ${label} restarted."
    return 0
  fi
  out "\033[31m[✗]\033[0m Failed to restart ${label}. Run: $(svc_restart_cmd_hint "$name")"
  return 1
}

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."; }

require_installed() {
  [ -f "$INSTALL_MARKER" ] || [ -f "$INSTALL_PATH" ] || die "Not installed. Run: $SCRIPT_CMD_NAME --install"
}

need_apt() { command -v apt-get >/dev/null 2>&1 || die "apt-get not found. Debian/Ubuntu only."; }

prompt_yn() {
  local prompt="$1"
  local default="${2:-N}"
  if [ "$NONINTERACTIVE" -eq 1 ]; then
    [ "$default" = "Y" ] && return 0 || return 1
  fi
  local ans=""
  read -r -p "$prompt" ans
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    n|N|no|NO) return 1 ;;
    "") [ "$default" = "Y" ] && return 0 || return 1 ;;
    *) return 2 ;;
  esac
}

prompt_yn_loop() {
  local prompt="$1"
  local default="${2:-N}"
  while true; do
    if prompt_yn "$prompt" "$default"; then
      return 0
    else
      local rc=$?
      if [ "$rc" -eq 1 ]; then
        return 1
      fi
      out "\033[33m[!]\033[0m Invalid input. Type y or n."
    fi
  done
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
  local ip="$1"
  [[ "$ip" == *:* ]]
}

ip_ok_for_san() {
  local ip="$1"

  if is_ipv4 "$ip"; then
    case "$ip" in
      0.0.0.0) return 1 ;;
      127.*) return 1 ;;
      169.254.*) return 1 ;;
      172.17.*|172.18.*|172.19.*|172.20.*) return 1 ;;
    esac
    return 0
  fi

  if is_ipv6 "$ip"; then
    case "$ip" in
      ::1) return 1 ;;
      fe80:*|FE80:*) return 1 ;;
    esac
    return 0
  fi

  return 1
}

collect_san_ips_from_hostname_i() {
  local raw ips out_ips="" kept=0 total=0 truncated=0
  raw="$(hostname -I 2>/dev/null || true)"
  raw="$(printf '%s' "$raw" | tr -s ' ' | sed 's/[[:space:]]*$//' || true)"

  for ips in $raw; do
    total=$((total + 1))
    case "$ips" in
      *%*) continue ;;
    esac
    ip_ok_for_san "$ips" || continue
    if [ "$kept" -ge "$SAN_MAX_IPS" ]; then
      truncated=1
      continue
    fi
    if [ -z "$out_ips" ]; then
      out_ips="$ips"
    else
      out_ips="$out_ips $ips"
    fi
    kept=$((kept + 1))
  done

  FILTERED_IPS="$out_ips"

  if [ "$truncated" -eq 1 ]; then
    vout "\033[33m[!]\033[0m Too many IPs for SAN. Truncated to $SAN_MAX_IPS."
  fi
}

print_repo_hint() {
  [ "${LOCAL_HTTPS_SHOW_REPO_HINT:-1}" = "0" ] && return 0
  local repo="https://github.com/luizbizzio/local-https"
  printf '%b\n' "\033[90mDocumentation, source code, and issue tracker:\033[0m $repo"
  printf '%b\n' "\033[90mIf this tool helped you, consider starring the repository.\033[0m"
  echo ""
}

write_state() {
  install -d -m 755 "$STATE_DIR" >/dev/null 2>&1 || true

  local ts applied tailscale="no" ca_fp="" srv_end_raw="" srv_end_epoch="" srv_end_utc="" method="" installed_at

  ts="$(date -Is 2>/dev/null || date 2>/dev/null || echo unknown)"

  if command -v tailscale >/dev/null 2>&1; then
    tailscale="yes"
  fi

  if [ "${PIHOLE_PRESENT:-0}" -eq 1 ] && [ "${TECH_PRESENT:-0}" -eq 1 ]; then
    applied="pihole+technitium"
  elif [ "${PIHOLE_PRESENT:-0}" -eq 1 ]; then
    applied="pihole"
  elif [ "${TECH_PRESENT:-0}" -eq 1 ]; then
    applied="technitium"
  else
    applied="none"
  fi

  if [ -f "$CA_CRT" ]; then
    ca_fp="$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || true)"
  fi

  if [ -f "$SERVER_CRT" ]; then
    srv_end_raw="$(openssl x509 -in "$SERVER_CRT" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    if [ -n "$srv_end_raw" ]; then
      srv_end_epoch="$(date -u -d "$srv_end_raw" +%s 2>/dev/null || true)"
      if [ -n "$srv_end_epoch" ]; then
        srv_end_utc="$(date -u -d "@$srv_end_epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
      fi
    fi
  fi

  method="${AUTORENEW_METHOD:-}"
  [ -n "$method" ] || method="$(read_state_value autorenew_method)"
  [ -n "$method" ] || method="none"

  installed_at="$(read_state_value installed_at)"
  [ -n "$installed_at" ] || installed_at="$ts"

  {
    echo "installed_at=$(sh_quote "$installed_at")"
    echo "last_run_at=$(sh_quote "$ts")"
    echo "hostname=$(sh_quote "${HOSTNAME:-$(hostname 2>/dev/null || true)}")"
    echo "applied_targets=$(sh_quote "$applied")"
    echo "autorenew_method=$(sh_quote "$method")"
    echo "pihole_detected=$(sh_quote "${PIHOLE_PRESENT:-0}")"
    echo "technitium_detected=$(sh_quote "${TECH_PRESENT:-0}")"
    echo "tailscale_detected=$(sh_quote "$tailscale")"
    echo "rootca_fingerprint_sha256=$(sh_quote "$ca_fp")"
    echo "server_enddate_raw=$(sh_quote "$srv_end_raw")"
    echo "server_enddate_epoch=$(sh_quote "$srv_end_epoch")"
    echo "server_enddate_utc=$(sh_quote "$srv_end_utc")"
    echo "cert_renewed=$(sh_quote "${CERT_RENEWED:-0}")"
  } > "$STATE_FILE"

  touch "$INSTALL_MARKER" >/dev/null 2>&1 || true
}

detect_technitium_service_name() {
  TECH_SERVICE=""
  has_systemctl || return 0

  local candidates=(
    technitium-dns.service
    technitiumdns.service
    TechnitiumDnsServer.service
    dns.service
  )

  local svc=""
  for svc in "${candidates[@]}"; do
    systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$svc" || continue
    local exec=""
    exec="$(systemctl show -p ExecStart --value "$svc" 2>/dev/null || true)"
    printf '%s' "$exec" | grep -Eqi 'technitium|TechnitiumDnsServer|dnsserver' || continue
    TECH_SERVICE="$svc"
    return 0
  done

  local fallback=""
  fallback="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '{print $1}' \
    | grep -Ei '^technitium.*\.service$' \
    | head -n1 || true)"

  if [ -n "$fallback" ]; then
    TECH_SERVICE="$fallback"
  fi
}

build_renew_args() {
  echo "--renew"
}

cron_line_build() {
  if has_logger; then
    echo "0 3 * * * $INSTALL_PATH --renew 2>&1 | logger -t local-https"
    return 0
  fi
  echo "0 3 * * * $INSTALL_PATH --renew >> $CRON_LOG_PATH 2>&1"
}

install_logrotate_for_cron_log() {
  [ -f "$CRON_LOG_PATH" ] || touch "$CRON_LOG_PATH" >/dev/null 2>&1 || true
  chmod 644 "$CRON_LOG_PATH" >/dev/null 2>&1 || true

  cat > "$LOGROTATE_PATH" <<EOF
$CRON_LOG_PATH {
  weekly
  rotate 8
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF
}

upsert_block() {
  local FILE="$1"
  local BEGIN_MARK="$2"
  local END_MARK="$3"
  local CONTENT_FILE="$4"

  [ -f "$FILE" ] || touch "$FILE"

  if grep -qF "$BEGIN_MARK" "$FILE"; then
    grep -qF "$END_MARK" "$FILE" || die "Found BEGIN marker but END marker is missing in: $FILE. Fix it manually before running again."
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" -v cf="$CONTENT_FILE" '
      BEGIN{inblock=0}
      $0==b{
        print b
        while((getline line < cf)>0) print line
        close(cf)
        print e
        inblock=1
        next
      }
      $0==e{inblock=0; next}
      inblock==0{print}
    ' "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
  else
    grep -qF "$END_MARK" "$FILE" && die "Found END marker but BEGIN marker is missing in: $FILE. Fix it manually before running again."
    printf "\n%s\n" "$BEGIN_MARK" >> "$FILE"
    cat "$CONTENT_FILE" >> "$FILE"
    printf "\n%s\n" "$END_MARK" >> "$FILE"
  fi
}

remove_block() {
  local FILE="$1"
  local BEGIN_MARK="$2"
  local END_MARK="$3"

  [ -f "$FILE" ] || return 0
  grep -qF "$BEGIN_MARK" "$FILE" || return 0
  grep -qF "$END_MARK" "$FILE" || return 0

  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    BEGIN{skip=0}
    $0==b{skip=1; next}
    $0==e{skip=0; next}
    skip==0{print}
  ' "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
}

print_help() {
  echo ""
  echo "Usage:"
  echo "  $SCRIPT_CMD_NAME --install"
  echo "  $SCRIPT_CMD_NAME --renew [--force-renew]"
  echo "  $SCRIPT_CMD_NAME --check"
  echo "  $SCRIPT_CMD_NAME --status"
  echo "  $SCRIPT_CMD_NAME --print-ca"
  echo "  $SCRIPT_CMD_NAME --print-pfx-pass"
  echo "  $SCRIPT_CMD_NAME --rotate-pfx-pass"
  echo "  $SCRIPT_CMD_NAME --configure"
  echo "  $SCRIPT_CMD_NAME --uninstall [--yes] [--purge-certs]"
  echo ""
  echo "Notes:"
  echo "  - Running without args shows this help."
  echo "  - If already installed, --install will not run again."
  echo "  - Reinstall only via: --uninstall then --install"
  echo ""
}

banner() {
  local cmd="${1:-}"
  local mode="install"

  case "$cmd" in
    --install) mode="install" ;;
    --configure) mode="configure" ;;
    --rotate-pfx-pass) mode="rotate-pfx-pass" ;;
    --renew) mode="renew" ;;
    --uninstall) mode="uninstall" ;;
  esac

  printf '%b\n' "\033[36m============================================================\033[0m"
  printf '%b\n' "\033[1m\033[36m local-https\033[0m \033[90m(${mode})\033[0m"
  printf '%b\n' "\033[36m============================================================\033[0m"
  echo ""

  if [ "$BOOTSTRAP" -eq 1 ]; then
    return 0
  fi

  printf '%b\n' "\033[1mWhat this does\033[0m"
  printf '%b\n' "  - Create a local Root CA"
  printf '%b\n' "  - Issue a server cert (40 days) + build PEM and PFX"
  echo ""

  printf '%b\n' "\033[1mFiles\033[0m"
  printf '%b\n' "  - Dir: $SSL_DIR"
  printf '%b\n' "  - Root CA: $CA_CRT"
  printf '%b\n' "  - Server PEM: $SERVER_PEM"
  printf '%b\n' "  - Server PFX: $SERVER_PFX (password in $PFX_PASS_FILE)"
  echo ""

  case "$mode" in
    install)
      printf '%b\n' "\033[1mDuring install\033[0m"
      printf '%b\n' "  - Setup auto renew (systemd or cron)"
      printf '%b\n' "  - Optional: deploy to Pi-hole"
      printf '%b\n' "  - If Technitium is detected: TLS will be set to the PFX"
      echo ""
      ;;
    configure)
      printf '%b\n' "\033[1mDuring configure\033[0m"
      printf '%b\n' "  - Optional: deploy to Pi-hole"
      printf '%b\n' "  - If Technitium is detected: TLS will be set to the PFX"
      echo ""
      ;;
    rotate-pfx-pass)
      printf '%b\n' "\033[1mDuring rotate\033[0m"
      printf '%b\n' "  - Rotate PFX password and rebuild PFX"
      printf '%b\n' "  - If Technitium is detected: TLS will be updated to the new PFX password"
      echo ""
      ;;
  esac

  printf '%b\n' "\033[90mHelp:\033[0m $SCRIPT_CMD_NAME --help"
  echo ""
}

confirm_start() {
  [ "$BOOTSTRAP" -eq 1 ] && return 0
  [ "$NONINTERACTIVE" -eq 1 ] && return 0
  [ -t 0 ] || return 0

  if prompt_yn "Continue? (y/N): " "N"; then
    return 0
  fi
  printf '%b\n' "\033[31mAborted.\033[0m"
  exit 1
}

install_deps_interactive() {
  out "\033[36m[>]\033[0m Checking dependencies..."
  need_apt

  local PKGS=()
  need_cmd openssl || PKGS+=("openssl")
  need_cmd curl || PKGS+=("curl")
  need_cmd jq || PKGS+=("jq")

  if [ "${#PKGS[@]}" -gt 0 ]; then
    out "\033[34m[i]\033[0m Installing: ${PKGS[*]}"
    apt-get update >/dev/null || die "apt-get update failed"
    apt-get install -y "${PKGS[@]}" >/dev/null || die "apt-get install failed: ${PKGS[*]}"
    out "\033[32m[✓]\033[0m Dependencies installed."
  else
    out "\033[32m[✓]\033[0m Dependencies already present."
  fi
}

ensure_runtime_deps() {
  need_cmd openssl || die "Missing dependency: openssl. Run --install first."
  need_cmd hostname || die "Missing dependency: hostname."
}

install_self() {
  out "\033[36m[>]\033[0m Installing command: $INSTALL_PATH"

  local src=""
  local tmp=""
  local src_real=""
  local dst_real=""

  src="${BASH_SOURCE[0]:-}"
  [ -n "$src" ] && [ -r "$src" ] && src="$(readlink -f "$src" 2>/dev/null || echo "$src")"

  if [ -n "$src" ] && [ -r "$src" ] && [ -f "$src" ]; then
    install -d -m 755 /usr/local/sbin >/dev/null 2>&1 || true
    src_real="$(readlink -f "$src" 2>/dev/null || echo "$src")"
    dst_real="$(readlink -f "$INSTALL_PATH" 2>/dev/null || echo "$INSTALL_PATH")"
    if [ "$src_real" = "$dst_real" ]; then
      chmod 755 "$INSTALL_PATH" >/dev/null 2>&1 || true
      out "\033[32m[✓]\033[0m Installed: $INSTALL_PATH"
      return 0
    fi
    install -m 755 "$src" "$INSTALL_PATH" >/dev/null 2>&1 || die "Failed to install to $INSTALL_PATH"
    out "\033[32m[✓]\033[0m Installed: $INSTALL_PATH"
    return 0
  fi

  need_cmd curl || die "curl missing. Run --install first."
  tmp="$(mktemp -p /tmp local-https.self.XXXXXX)"
  chmod 700 "$tmp" >/dev/null 2>&1 || true

  if curl -fsSL "$SCRIPT_SOURCE_URL" -o "$tmp" >/dev/null 2>&1; then
    :
  else
    local alt=""
    alt="${SCRIPT_SOURCE_URL%.sh}"
    [ "$alt" != "$SCRIPT_SOURCE_URL" ] && curl -fsSL "$alt" -o "$tmp" >/dev/null 2>&1 || true
  fi

  [ -s "$tmp" ] || { rm -f "$tmp" >/dev/null 2>&1 || true; die "Cannot locate script source file. Set LOCAL_HTTPS_SOURCE_URL or run from a saved file."; }

  install -d -m 755 /usr/local/sbin >/dev/null 2>&1 || true
  install -m 755 "$tmp" "$INSTALL_PATH" >/dev/null 2>&1 || { rm -f "$tmp" >/dev/null 2>&1 || true; die "Failed to install to $INSTALL_PATH"; }
  rm -f "$tmp" >/dev/null 2>&1 || true

  out "\033[32m[✓]\033[0m Installed: $INSTALL_PATH"

  if [ "${LOCAL_HTTPS_BOOTSTRAP:-0}" != "1" ]; then
    exec env LOCAL_HTTPS_BOOTSTRAP=1 "$INSTALL_PATH" --install
  fi
}

technitium_detect_base_url() {
  TECH_BASE_URL=""
  TECH_PRESENT=0

  local code=""

  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:53443/" 2>/dev/null || true)"
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    TECH_BASE_URL="https://127.0.0.1:53443"
    TECH_PRESENT=1
    return 0
  fi

  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:5380/" 2>/dev/null || true)"
  if [ "$code" = "200" ]; then
    TECH_BASE_URL="http://127.0.0.1:5380"
    TECH_PRESENT=1
    return 0
  fi

  if [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "307" ] || [ "$code" = "308" ]; then
    code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:53443/" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      TECH_BASE_URL="https://127.0.0.1:53443"
      TECH_PRESENT=1
      return 0
    fi
  fi

  return 0
}

detect_pihole_and_technitium() {
  out "\033[36m[>]\033[0m Detecting Pi-hole and Technitium..."

  if command -v pihole >/dev/null 2>&1; then
    PIHOLE_PRESENT=1
    out "\033[32m[✓]\033[0m Pi-hole detected."
  else
    PIHOLE_PRESENT=0
    out "\033[33m[!]\033[0m Pi-hole not detected."
  fi

  TECH_BASE_URL=""
  TECH_PRESENT=0

  if command -v curl >/dev/null 2>&1; then
    technitium_detect_base_url
  fi

  if [ "$TECH_PRESENT" -eq 1 ]; then
    out "\033[32m[✓]\033[0m Technitium reachable at: $TECH_BASE_URL"
  else
    out "\033[33m[!]\033[0m Technitium not reachable on 127.0.0.1 (ports 5380/53443)."
  fi

  detect_technitium_service_name
  if [ -n "$TECH_SERVICE" ]; then
    vout "\033[32m[✓]\033[0m Technitium service detected: $TECH_SERVICE"
  else
    vout "\033[33m[>]\033[0m Technitium service name not detected."
  fi
}

read_host_identity() {
  out "\033[36m[>]\033[0m Reading host identity..."

  HOSTNAME="$(hostname 2>/dev/null || true)"
  [ -n "$HOSTNAME" ] || HOSTNAME="localhost"

  collect_san_ips_from_hostname_i

  local ip_count=0
  local first_ip=""
  local IP=""
  for IP in $FILTERED_IPS; do
    ip_count=$((ip_count + 1))
    [ -z "$first_ip" ] && first_ip="$IP"
  done

  out "\033[34m[i]\033[0m Hostname: $HOSTNAME"
  out "\033[34m[i]\033[0m SAN IPs: ${ip_count:-0} (example: ${first_ip:-none})"
  vout "\033[34m[i]\033[0m IPs (SAN full): ${FILTERED_IPS:-none}"

  TAILSCALE_DNS=""
  TAILSCALE_SHORT=""

  if command -v tailscale >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    TAILSCALE_DNS="$(tailscale status -json 2>/dev/null | jq -r '.Self.DNSName' 2>/dev/null | sed 's/\.$//' || true)"
    if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
      TAILSCALE_SHORT="${TAILSCALE_DNS%%.*}"
      out "\033[32m[✓]\033[0m Tailscale DNS: $TAILSCALE_DNS"
    else
      TAILSCALE_DNS=""
      TAILSCALE_SHORT=""
      vout "\033[33m[>]\033[0m Tailscale present but DNSName not available."
    fi
  else
    vout "\033[33m[>]\033[0m Tailscale not installed or jq missing."
  fi
}

prepare_dir() {
  out "\033[36m[>]\033[0m Preparing certificate directory..."
  mkdir -p "$SSL_DIR"
  cd "$SSL_DIR" || die "Failed to cd into $SSL_DIR."
  out "\033[32m[✓]\033[0m Using directory: $SSL_DIR"
  PIHOLE_FTL_CERT="$SERVER_PEM"
}

create_or_reuse_ca() {
  out "\033[36m[>]\033[0m Creating or reusing Root CA..."

  cat << EOF > ca-openssl.cnf
[ req ]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[ req_distinguished_name ]
CN = Local Server Root CA

[ v3_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

  if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
    local old_umask=""
    old_umask="$(umask 2>/dev/null || echo "")"
    umask 077
    openssl genpkey -algorithm EC -out "$CA_KEY" -pkeyopt ec_paramgen_curve:$CA_EC_CURVE -pkeyopt ec_param_enc:named_curve >/dev/null 2>&1 || die "OpenSSL failed to generate CA key."
    openssl req -x509 -new -key "$CA_KEY" -out "$CA_CRT" -days 3650 -sha256 -config ./ca-openssl.cnf >/dev/null 2>&1 || die "OpenSSL failed to create CA certificate."
    [ -n "$old_umask" ] && umask "$old_umask" >/dev/null 2>&1 || true
    out "\033[32m[✓]\033[0m Root CA created."
  else
    out "\033[32m[✓]\033[0m Root CA already exists."
  fi
}

server_cert_needs_renew() {
  if [ ! -f "$SERVER_CRT" ]; then
    return 0
  fi
  if ! openssl x509 -checkend "$RENEW_WINDOW_SECONDS" -noout -in "$SERVER_CRT" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

issue_or_renew_server_cert() {
  local QUIET=0
  if [ "$NONINTERACTIVE" -eq 1 ] && [ "$VERBOSE" -eq 0 ]; then
    QUIET=1
  fi

  [ "$QUIET" -eq 1 ] || out "\033[36m[>]\033[0m Issuing or renewing server certificate..."

  [ -n "${HOSTNAME:-}" ] || HOSTNAME="$(hostname 2>/dev/null || true)"
  [ -n "${HOSTNAME:-}" ] || HOSTNAME="localhost"

  cat << EOF > server-openssl.cnf
[ req ]
distinguished_name  = req_distinguished_name
req_extensions      = v3_req
prompt = no

[ req_distinguished_name ]
CN = $HOSTNAME

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $HOSTNAME
EOF

  local DNS_INDEX=2
  if [ "$PIHOLE_PRESENT" -eq 1 ]; then
    echo "DNS.${DNS_INDEX} = pi.hole" >> server-openssl.cnf
    DNS_INDEX=$((DNS_INDEX + 1))
  fi

  if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
    echo "DNS.${DNS_INDEX} = $TAILSCALE_DNS" >> server-openssl.cnf
    DNS_INDEX=$((DNS_INDEX + 1))
  fi

  if [ -n "$TAILSCALE_SHORT" ] && [ "$TAILSCALE_SHORT" != "$HOSTNAME" ]; then
    echo "DNS.${DNS_INDEX} = $TAILSCALE_SHORT" >> server-openssl.cnf
    DNS_INDEX=$((DNS_INDEX + 1))
  fi

  local IP_INDEX=1
  local IP=""
  for IP in $FILTERED_IPS; do
    [ -n "$IP" ] && echo "IP.${IP_INDEX} = $IP" >> server-openssl.cnf && IP_INDEX=$((IP_INDEX + 1))
  done

  local do_renew=0
  if [ "$FORCE_RENEW" -eq 1 ]; then
    do_renew=1
  else
    if server_cert_needs_renew; then
      do_renew=1
    else
      do_renew=0
    fi
  fi

  if [ "$do_renew" -eq 1 ]; then
    local old_umask=""
    old_umask="$(umask 2>/dev/null || echo "")"
    umask 077

    if [ ! -f "$SERVER_KEY" ]; then
      openssl genpkey -algorithm EC -out "$SERVER_KEY" -pkeyopt ec_paramgen_curve:$SERVER_EC_CURVE -pkeyopt ec_param_enc:named_curve >/dev/null 2>&1 || die "OpenSSL failed to generate server key."
    fi

    openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config ./server-openssl.cnf >/dev/null 2>&1 || die "OpenSSL failed to generate CSR. Check: $SSL_DIR/server-openssl.cnf"
    [ -f "$CA_KEY" ] && [ -f "$CA_CRT" ] || die "Root CA missing. Run: $SCRIPT_CMD_NAME --install"

    openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAserial "$CA_SRL" -CAcreateserial -out "$SERVER_CRT" -days 40 -sha256 -extfile ./server-openssl.cnf -extensions v3_req >/dev/null 2>&1 || die "OpenSSL failed to sign certificate."

    cat "$SERVER_CRT" "$SERVER_KEY" > "$SERVER_PEM"
    CERT_RENEWED=1

    [ -n "$old_umask" ] && umask "$old_umask" >/dev/null 2>&1 || true

    if [ "$QUIET" -eq 1 ]; then
      out "\033[32m[✓]\033[0m Server certificate renewed (40 days)."
    else
      if [ "$FORCE_RENEW" -eq 1 ]; then
        out "\033[32m[✓]\033[0m Server certificate forced renew (40 days)."
      else
        out "\033[32m[✓]\033[0m Server certificate issued or renewed (40 days)."
      fi
    fi
  else
    [ "$QUIET" -eq 1 ] || out "\033[32m[✓]\033[0m Server certificate still valid. No renewal needed."
  fi

  if [ "$QUIET" -eq 1 ]; then
    return 0
  fi

  if [ "$VERBOSE" -eq 1 ]; then
    out "\033[34m[i]\033[0m Certificate SANs:"
    openssl x509 -in "$SERVER_CRT" -noout -ext subjectAltName 2>/dev/null || true
    pause_step
  else
    local ip_count=0
    local _ip=""
    for _ip in $FILTERED_IPS; do ip_count=$((ip_count + 1)); done

    local dns_list="$HOSTNAME"
    if [ "$PIHOLE_PRESENT" -eq 1 ]; then
      dns_list="$dns_list, pi.hole"
    fi
    if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
      dns_list="$dns_list, $TAILSCALE_DNS"
    fi
    if [ -n "$TAILSCALE_SHORT" ] && [ "$TAILSCALE_SHORT" != "$HOSTNAME" ] && [ "$TAILSCALE_SHORT" != "pi" ]; then
      dns_list="$dns_list, $TAILSCALE_SHORT"
    fi

    out "\033[34m[i]\033[0m SAN: DNS: $dns_list | IPs: $ip_count"
  fi
}

generate_random_password() {
  local p=""
  p="$(openssl rand -base64 32 2>/dev/null | tr -d '\n' || true)"
  [ -n "$p" ] || p="$(openssl rand -hex 32 2>/dev/null | tr -d '\n' || true)"
  [ -n "$p" ] || die "Failed to generate random password."
  printf '%s' "$p"
}

ensure_pfx_password_file() {
  if [ -f "$PFX_PASS_FILE" ] && [ -s "$PFX_PASS_FILE" ]; then
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if [ -n "${LOCAL_HTTPS_PFX_PASSWORD:-}" ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    printf '%s' "$LOCAL_HTTPS_PFX_PASSWORD" > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if [ -n "${LOCAL_HTTPS_PFX_PASSWORD_FILE:-}" ] && [ -f "$LOCAL_HTTPS_PFX_PASSWORD_FILE" ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    cat "$LOCAL_HTTPS_PFX_PASSWORD_FILE" > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if [ "$NONINTERACTIVE" -eq 1 ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    generate_random_password > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    out "\033[32m[✓]\033[0m PFX password generated and stored: $PFX_PASS_FILE"
    return 0
  fi

  if prompt_yn_loop "Generate random PFX password and store it? (Y/n): " "Y"; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    generate_random_password > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    out "\033[32m[✓]\033[0m PFX password generated and stored: $PFX_PASS_FILE"
    out "\033[34m[i]\033[0m To print it: $SCRIPT_CMD_NAME --print-pfx-pass"
    return 0
  fi

  while true; do
    local p1="" p2=""
    read -r -s -p "Create PFX password (required): " p1
    echo ""
    read -r -s -p "Confirm PFX password: " p2
    echo ""
    if [ -n "$p1" ] && [ "$p1" = "$p2" ]; then
      install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      printf '%s' "$p1" > "$PFX_PASS_FILE"
      chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      out "\033[32m[✓]\033[0m PFX password stored: $PFX_PASS_FILE"
      return 0
    fi
    out "\033[33m[!]\033[0m Password empty or mismatch. Try again."
  done
}

rotate_pfx_password_file() {
  if [ -n "${LOCAL_HTTPS_PFX_PASSWORD:-}" ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    printf '%s' "$LOCAL_HTTPS_PFX_PASSWORD" > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if [ -n "${LOCAL_HTTPS_PFX_PASSWORD_FILE:-}" ] && [ -f "$LOCAL_HTTPS_PFX_PASSWORD_FILE" ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    cat "$LOCAL_HTTPS_PFX_PASSWORD_FILE" > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if [ "$NONINTERACTIVE" -eq 1 ]; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    generate_random_password > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    return 0
  fi

  if prompt_yn_loop "Rotate to a new random PFX password? (Y/n): " "Y"; then
    install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    generate_random_password > "$PFX_PASS_FILE"
    chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
    out "\033[32m[✓]\033[0m PFX password rotated: $PFX_PASS_FILE"
    out "\033[34m[i]\033[0m To print it: $SCRIPT_CMD_NAME --print-pfx-pass"
    return 0
  fi

  while true; do
    local p1="" p2=""
    read -r -s -p "New PFX password (required): " p1
    echo ""
    read -r -s -p "Confirm new PFX password: " p2
    echo ""
    if [ -n "$p1" ] && [ "$p1" = "$p2" ]; then
      install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      printf '%s' "$p1" > "$PFX_PASS_FILE"
      chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
      out "\033[32m[✓]\033[0m PFX password rotated: $PFX_PASS_FILE"
      return 0
    fi
    out "\033[33m[!]\033[0m Password empty or mismatch. Try again."
  done
}

create_or_update_pfx() {
  out "\033[36m[>]\033[0m Creating/Updating password-protected PFX..."

  [ -f "$CA_CRT" ] || die "Root CA missing: $CA_CRT"
  [ -f "$SERVER_CRT" ] || die "Server cert missing: $SERVER_CRT"
  [ -f "$SERVER_KEY" ] || die "Server key missing: $SERVER_KEY"

  ensure_pfx_password_file

  openssl pkcs12 -export \
    -out "$SERVER_PFX" \
    -inkey "$SERVER_KEY" \
    -in "$SERVER_CRT" \
    -certfile "$CA_CRT" \
    -passout file:"$PFX_PASS_FILE" >/dev/null 2>&1 || die "Failed to create PFX: $SERVER_PFX"

  out "\033[32m[✓]\033[0m PFX ready: $SERVER_PFX"
}

detect_pihole_stack() {
  if [ -f "/etc/lighttpd/conf-enabled/15-pihole-admin.conf" ] || [ -f "/etc/lighttpd/conf-enabled/10-pihole.conf" ]; then
    echo "lighttpd"
    return 0
  fi

  local has_pgrep=0
  command -v pgrep >/dev/null 2>&1 && has_pgrep=1

  if svc_active lighttpd >/dev/null 2>&1; then
    if [ "$PIHOLE_PRESENT" -eq 1 ]; then
      echo "lighttpd"
      return 0
    fi
  fi

  if [ "$has_pgrep" -eq 1 ]; then
    if pgrep -x lighttpd >/dev/null 2>&1; then
      if [ "$PIHOLE_PRESENT" -eq 1 ]; then
        echo "lighttpd"
        return 0
      fi
    fi
  fi

  if command -v pihole-FTL >/dev/null 2>&1; then
    echo "ftl"
    return 0
  fi
  echo "unknown"
  return 0
}

pihole_toml_set_tls() {
  local certpath="$1"
  mkdir -p /etc/pihole >/dev/null 2>&1 || true

  if [ ! -f "$PIHOLE_TOML" ]; then
    cat > "$PIHOLE_TOML" << EOF
[webserver.tls]
cert = "$certpath"
validity = 0
EOF
    return 0
  fi

  awk -v certpath="$certpath" '
    BEGIN{in_tls=0; found_tls=0; done_cert=0; done_val=0}
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/{
      if (in_tls==1) {
        if (done_cert==0) { print "cert = \"" certpath "\"" }
        if (done_val==0) { print "validity = 0" }
        in_tls=0
      }
      sec=$0
      gsub(/^[[:space:]]*\[/,"",sec)
      gsub(/\][[:space:]]*$/,"",sec)
      if (sec=="webserver.tls") { in_tls=1; found_tls=1 }
      print $0
      next
    }
    {
      if (in_tls==1) {
        if ($0 ~ /^[[:space:]]*cert[[:space:]]*=/ && done_cert==0) { print "cert = \"" certpath "\""; done_cert=1; next }
        if ($0 ~ /^[[:space:]]*validity[[:space:]]*=/ && done_val==0) { print "validity = 0"; done_val=1; next }
      }
      print $0
    }
    END{
      if (found_tls==0) {
        print ""
        print "[webserver.tls]"
        print "cert = \"" certpath "\""
        print "validity = 0"
      } else if (in_tls==1) {
        if (done_cert==0) { print "cert = \"" certpath "\"" }
        if (done_val==0) { print "validity = 0" }
      }
    }
  ' "$PIHOLE_TOML" > "${PIHOLE_TOML}.tmp" && mv "${PIHOLE_TOML}.tmp" "$PIHOLE_TOML"
}

deploy_pihole_ftl_tls() {
  out "\033[34m[i]\033[0m Pi-hole will use: $PIHOLE_FTL_CERT"

  if command -v pihole-FTL >/dev/null 2>&1; then
    pihole-FTL --config webserver.tls.cert "$PIHOLE_FTL_CERT" >/dev/null 2>&1 || true
    pihole-FTL --config webserver.tls.validity 0 >/dev/null 2>&1 || true
  fi

  pihole_toml_set_tls "$PIHOLE_FTL_CERT"
  out "\033[32m[✓]\033[0m Pi-hole TLS set to: $PIHOLE_FTL_CERT"
}

choose_preferred_dns() {
  local d=""
  if [ "${PIHOLE_PRESENT:-0}" -eq 1 ]; then
    d="pi.hole"
  fi
  if [ -z "$d" ] && [ -n "${TAILSCALE_DNS:-}" ] && [ "${TAILSCALE_DNS:-}" != "null" ]; then
    d="$TAILSCALE_DNS"
  fi
  if [ -z "$d" ]; then
    d="${HOSTNAME:-}"
    [ -n "$d" ] || d="$(hostname 2>/dev/null || true)"
  fi
  if [ -z "$d" ]; then
    d="$(printf '%s\n' "$FILTERED_IPS" | tr ' ' '\n' | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' 2>/dev/null || true)"
  fi
  [ -n "$d" ] || d="localhost"
  echo "$d"
}

test_lighttpd_config() {
  local config_file="$1"
  if command -v lighttpd >/dev/null 2>&1; then
    lighttpd -tt -f "$config_file" >/dev/null 2>&1
    return $?
  fi
  return 0
}

apply_pihole_tls_install() {
  out "\033[36m[>]\033[0m Deploying certificate to Pi-hole (optional)..."

  if [ "$PIHOLE_PRESENT" -eq 0 ]; then
    out "\033[34m[i]\033[0m Pi-hole not present. Skipping."
    return 0
  fi

  local stack=""
  local preferred=""
  local do_apply=0

  stack="$(detect_pihole_stack)"
  preferred="$(choose_preferred_dns)"

  out "\033[34m[i]\033[0m Pi-hole: stack=$stack host=$preferred"
  vout "\033[34m[i]\033[0m Certificate file: $SERVER_PEM"

  if [ "$BOOTSTRAP" -eq 1 ] || [ "$NONINTERACTIVE" -eq 1 ]; then
    do_apply="$AUTO_PIHOLE"
    if [ "$do_apply" -ne 1 ]; then
      out "\033[34m[i]\033[0m Pi-hole detected. Skipping auto config. Run: $SCRIPT_CMD_NAME --configure"
      return 0
    fi
    out "\033[34m[i]\033[0m Applying HTTPS to Pi-hole automatically..."
  else
    if prompt_yn_loop "Apply HTTPS to Pi-hole now? (y/N): " "N"; then
      do_apply=1
    else
      do_apply=0
    fi

    if [ "$do_apply" -ne 1 ]; then
      out "\033[33m[>]\033[0m Skipping Pi-hole deploy."
      return 0
    fi
  fi

  if [ "$stack" = "lighttpd" ]; then
    out "\033[34m[i]\033[0m Pi-hole: configuring Lighttpd TLS..."
    need_apt
    apt-get update >/dev/null || die "apt-get update failed"
    apt-get install -y lighttpd-mod-openssl >/dev/null || die "apt-get install failed: lighttpd-mod-openssl"

    local config_file="/etc/lighttpd/lighttpd.conf"
    [ -f "$config_file" ] || die "Lighttpd config not found: $config_file"

    local backup=""
    backup="$(mktemp -p /tmp lighttpd.conf.local-https.XXXXXX)"
    cp "$config_file" "$backup" >/dev/null 2>&1 || die "Failed to backup: $config_file"

    if ! grep -q '"mod_openssl"' "$config_file"; then
      if grep -q 'server.modules[[:space:]]*=[[:space:]]*(\s*$' "$config_file" 2>/dev/null || grep -q 'server.modules[[:space:]]*=[[:space:]]*(' "$config_file"; then
        sed -i '/server\.modules[[:space:]]*=[[:space:]]*(/a\        "mod_openssl",' "$config_file" >/dev/null 2>&1 || true
      fi
    fi

    local TMP_BLOCK=""
    TMP_BLOCK="$(mktemp)"
    cat > "$TMP_BLOCK" << EOF
\$SERVER["socket"] == ":443" {
    ssl.engine = "enable"
    ssl.pemfile = "$SERVER_PEM"
}

\$SERVER["socket"] == ":80" {
    url.redirect = ( "^/admin(.*)" => "https://$preferred/admin\$1" )
}
EOF

    upsert_block "$config_file" "# BEGIN local-https" "# END local-https" "$TMP_BLOCK"
    rm -f "$TMP_BLOCK" >/dev/null 2>&1 || true

    if ! test_lighttpd_config "$config_file"; then
      cp "$backup" "$config_file" >/dev/null 2>&1 || true
      rm -f "$backup" >/dev/null 2>&1 || true
      die "Lighttpd config test failed. Changes reverted."
    fi

    if ! restart_or_warn lighttpd "Pi-hole Lighttpd"; then
      cp "$backup" "$config_file" >/dev/null 2>&1 || true
      test_lighttpd_config "$config_file" >/dev/null 2>&1 || true
      svc_restart lighttpd >/dev/null 2>&1 || true
      rm -f "$backup" >/dev/null 2>&1 || true
      die "Lighttpd restart failed. Config reverted."
    fi

    rm -f "$backup" >/dev/null 2>&1 || true
    out "\033[32m[✓]\033[0m Open: https://$preferred/admin"
    return 0
  fi

  if [ "$stack" = "ftl" ]; then
    out "\033[34m[i]\033[0m Pi-hole: configuring FTL webserver TLS..."
    deploy_pihole_ftl_tls
    restart_or_warn pihole-FTL "Pi-hole FTL" || true

    if command -v curl >/dev/null 2>&1; then
      if curl -k -sS -o /dev/null --max-time 3 "https://127.0.0.1/admin/" 2>/dev/null; then
        out "\033[32m[✓]\033[0m HTTPS check: https://127.0.0.1/admin is reachable."
      else
        out "\033[33m[!]\033[0m HTTPS check failed on localhost. If HTTPS works from your device, ignore this."
      fi
    fi

    out "\033[32m[✓]\033[0m Open: https://$preferred/admin"
    return 0
  fi

  out "\033[33m[!]\033[0m Could not detect Pi-hole web stack. Trying FTL config anyway."
  deploy_pihole_ftl_tls || true
  restart_or_warn pihole-FTL "Pi-hole FTL" || true
  out "\033[32m[✓]\033[0m Open: https://$preferred/admin"
}

apply_pihole_tls_renew_noninteractive() {
  if [ "$PIHOLE_PRESENT" -eq 0 ]; then
    return 0
  fi

  local stack=""
  stack="$(detect_pihole_stack)"

  if [ "$stack" = "ftl" ]; then
    deploy_pihole_ftl_tls || true
    restart_or_warn pihole-FTL "Pi-hole FTL" || true
    return 0
  fi

  if [ "$stack" = "lighttpd" ]; then
    restart_or_warn lighttpd "Pi-hole Lighttpd" || true
    return 0
  fi

  return 0
}

restart_pihole_after_renew() {
  [ "$PIHOLE_PRESENT" -eq 1 ] || return 0

  local stack=""
  stack="$(detect_pihole_stack)"

  if [ "$stack" = "ftl" ]; then
    restart_or_warn pihole-FTL "Pi-hole FTL" || true
    return 0
  fi

  if [ "$stack" = "lighttpd" ]; then
    restart_or_warn lighttpd "Pi-hole Lighttpd" || true
    return 0
  fi

  restart_or_warn pihole-FTL "Pi-hole FTL" || true
  restart_or_warn lighttpd "Pi-hole Lighttpd" || true
  return 0
}

tech_curl_tls_flags() {
  if [[ "$TECH_BASE_URL" == https://* ]]; then
    if [ "$TECH_INSECURE_TLS" -eq 1 ]; then
      echo "-k"
      return 0
    fi

    if [ -f "$CA_CRT" ] && curl -sS --max-time 2 --cacert "$CA_CRT" "$TECH_BASE_URL/" >/dev/null 2>&1; then
      echo "--cacert" "$CA_CRT"
      return 0
    fi

    echo "-k"
    return 0
  fi
  return 0
}

configure_technitium_required_install() {
  out "\033[36m[>]\033[0m Technitium configuration (required if detected)..."

  if [ "$TECH_PRESENT" -eq 0 ]; then
    out "\033[33m[>]\033[0m Technitium not detected. Skipping."
    return 0
  fi

  need_cmd curl || die "Technitium detected but curl missing."
  need_cmd jq || die "Technitium detected but jq missing."

  TECH_TLS_FLAGS=()
  read -r -a TECH_TLS_FLAGS < <(tech_curl_tls_flags || true) || true

  local TECH_USER="${LOCAL_HTTPS_TECH_USER:-admin}"
  local TECH_PASS="${LOCAL_HTTPS_TECH_PASS:-}"
  local TECH_PASS_FILE_SRC="${LOCAL_HTTPS_TECH_PASS_FILE:-}"
  local TOTP="${LOCAL_HTTPS_TECH_TOTP:-}"

  if [ -z "$TECH_PASS" ] && [ -n "$TECH_PASS_FILE_SRC" ] && [ -f "$TECH_PASS_FILE_SRC" ]; then
    TECH_PASS="$(cat "$TECH_PASS_FILE_SRC" 2>/dev/null || true)"
  fi

  if [ "$NONINTERACTIVE" -eq 1 ]; then
    [ -n "$TECH_PASS" ] || die "Technitium detected. Password is required. Use LOCAL_HTTPS_TECH_PASS or LOCAL_HTTPS_TECH_PASS_FILE."
  else
    if [ -t 0 ]; then
      local INPUT_USER=""
      read -r -p "Technitium username (default: ${TECH_USER}): " INPUT_USER
      [ -n "$INPUT_USER" ] && TECH_USER="$INPUT_USER"

      if [ -z "$TECH_PASS" ]; then
        read -r -s -p "Technitium password (hidden, required): " TECH_PASS
        echo ""
      fi

      if [ -z "$TOTP" ]; then
        read -r -p "TOTP (2FA) code if enabled (optional): " TOTP
      fi
    fi
  fi

  [ -n "$TECH_PASS" ] || die "Technitium detected. Password is required."

  [ -f "$SERVER_PFX" ] || die "PFX missing: $SERVER_PFX"
  [ -f "$PFX_PASS_FILE" ] && [ -s "$PFX_PASS_FILE" ] || die "PFX password file missing/empty: $PFX_PASS_FILE"

  local max_tries=5
  local try=1
  local LOGIN_JSON=""
  local STATUS=""
  local TOKEN=""

  while true; do
    LOGIN_JSON="$(curl -fsSL "${TECH_TLS_FLAGS[@]}" --max-time 10 -X POST \
      --data-urlencode "user=$TECH_USER" \
      --data-urlencode "pass=$TECH_PASS" \
      --data-urlencode "includeInfo=true" \
      ${TOTP:+--data-urlencode "totp=$TOTP"} \
      "${TECH_BASE_URL}/api/user/login" 2>/dev/null || true)"

    STATUS="$(printf '%s' "$LOGIN_JSON" | jq -r '.status' 2>/dev/null || echo "error")"

    if [ -n "$LOGIN_JSON" ] && [ "$STATUS" = "ok" ]; then
      TOKEN="$(printf '%s' "$LOGIN_JSON" | jq -r '.token' 2>/dev/null || echo "")"
      [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || die "Technitium token missing."
      break
    fi

    if [ "$NONINTERACTIVE" -eq 1 ]; then
      die "Technitium login failed."
    fi

    local REASON=""
    REASON="$(printf '%s' "$LOGIN_JSON" | jq -r '.errorMessage // .message // empty' 2>/dev/null || true)"
    if [ -n "$REASON" ]; then
      out "\033[31m[✗]\033[0m Technitium login failed (try ${try}/${max_tries}): $REASON"
    else
      out "\033[31m[✗]\033[0m Technitium login failed (try ${try}/${max_tries})."
    fi

    if [ "$try" -ge "$max_tries" ]; then
      if prompt_yn_loop "Skip Technitium config for now and continue install? (y/N): " "N"; then
        out "\033[33m[!]\033[0m Skipped Technitium config. Run later: $SCRIPT_CMD_NAME --configure"
        return 0
      fi
      try=1
    else
      try=$((try + 1))
    fi

    if [ -t 0 ]; then
      local INPUT_USER2=""
      read -r -p "Technitium username (default: ${TECH_USER}): " INPUT_USER2
      [ -n "$INPUT_USER2" ] && TECH_USER="$INPUT_USER2"

      local NEWPASS=""
      read -r -s -p "Technitium password (hidden, required): " NEWPASS
      echo ""
      [ -n "$NEWPASS" ] && TECH_PASS="$NEWPASS"

      local NEWTOTP=""
      read -r -p "TOTP (2FA) code if enabled (optional): " NEWTOTP
      TOTP="$NEWTOTP"
    fi
  done

  local SET_JSON=""
  SET_JSON="$(curl -fsSL "${TECH_TLS_FLAGS[@]}" --max-time 12 -X POST \
    --data-urlencode "token=$TOKEN" \
    --data-urlencode "webServiceEnableTls=true" \
    --data-urlencode "webServiceUseSelfSignedTlsCertificate=false" \
    --data-urlencode "webServiceTlsCertificatePath=$SERVER_PFX" \
    --data-urlencode "webServiceTlsCertificatePassword=$(cat "$PFX_PASS_FILE")" \
    "${TECH_BASE_URL}/api/settings/set" 2>/dev/null || true)"

  [ -n "$SET_JSON" ] || die "Technitium settings/set failed (empty response)."

  local SET_STATUS=""
  SET_STATUS="$(printf '%s' "$SET_JSON" | jq -r '.status' 2>/dev/null || echo "error")"
  [ "$SET_STATUS" = "ok" ] || die "Technitium settings/set failed."

  out "\033[32m[✓]\033[0m Technitium TLS settings applied."
  out "\033[34m[i]\033[0m On renew, local-https updates: $SERVER_PFX"

  curl -fsSL "${TECH_TLS_FLAGS[@]}" --max-time 6 --get \
      --data-urlencode "token=$TOKEN" \
      "${TECH_BASE_URL}/api/user/logout" >/dev/null 2>&1 || true
}

apply_permissions() {
  out "\033[36m[>]\033[0m Setting permissions (root + group '${CERT_GROUP}')..."

  getent group "$CERT_GROUP" >/dev/null 2>&1 || groupadd "$CERT_GROUP" >/dev/null 2>&1 || true

  if id -u www-data >/dev/null 2>&1; then
    usermod -aG "$CERT_GROUP" "www-data" >/dev/null 2>&1 || true
  fi

  if id -u pihole >/dev/null 2>&1; then
    usermod -aG "$CERT_GROUP" "pihole" >/dev/null 2>&1 || true
  fi

  if [ "$ADD_SUDO_USER_TO_CERT_GROUP" -eq 1 ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
      id -u "$SUDO_USER" >/dev/null 2>&1 && usermod -aG "$CERT_GROUP" "$SUDO_USER" >/dev/null 2>&1 || true
    fi
  fi

  chown -R root:root "$SSL_DIR" >/dev/null 2>&1 || true
  chgrp -R "$CERT_GROUP" "$SSL_DIR" >/dev/null 2>&1 || true

  chmod 750 "$SSL_DIR" >/dev/null 2>&1 || true
  chmod 644 "$CA_CRT" "$SERVER_CRT" >/dev/null 2>&1 || true
  [ -f "$CA_SRL" ] && chmod 644 "$CA_SRL" >/dev/null 2>&1 || true
  chmod 600 "$CA_KEY" >/dev/null 2>&1 || true
  [ -f "$SERVER_KEY" ] && chmod 640 "$SERVER_KEY" >/dev/null 2>&1 || true
  [ -f "$SERVER_PEM" ] && chmod 640 "$SERVER_PEM" >/dev/null 2>&1 || true
  [ -f "$SERVER_PFX" ] && chmod 640 "$SERVER_PFX" >/dev/null 2>&1 || true
  [ -f "$PFX_PASS_FILE" ] && chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true

  out "\033[32m[✓]\033[0m Permissions applied."
}

install_systemd_timer() {
  local args=""
  args="$(build_renew_args)"

  cat > "$SYSTEMD_SERVICE_PATH" <<EOF
[Unit]
Description=Local HTTPS certificate renew

[Service]
Type=oneshot
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$INSTALL_PATH $args
EOF

  cat > "$SYSTEMD_TIMER_PATH" << 'EOF'
[Unit]
Description=Daily Local HTTPS certificate renew

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || return 1
  systemctl enable --now local-https-renew.timer >/dev/null 2>&1 || return 1
  systemctl is-enabled --quiet local-https-renew.timer >/dev/null 2>&1 || return 1
  systemctl is-active --quiet local-https-renew.timer >/dev/null 2>&1 || return 1
  return 0
}

install_cron_job() {
  if ! command -v crontab >/dev/null 2>&1; then
    need_apt
    apt-get update >/dev/null || die "apt-get update failed"
    apt-get install -y cron >/dev/null || die "apt-get install failed: cron"
  fi

  local line=""
  line="$(cron_line_build)"

  (crontab -l 2>/dev/null | grep -Fqx "$line") && return 0
  { crontab -l 2>/dev/null; echo "$line"; } | crontab -

  if ! has_logger; then
    install_logrotate_for_cron_log
  fi
}

enable_autorenew_menu_install() {
  out "\033[36m[>]\033[0m Auto renew"

  if [ "$BOOTSTRAP" -eq 1 ] || [ "$NONINTERACTIVE" -eq 1 ]; then
    if has_systemctl; then
      AUTORENEW_METHOD="systemd"
      if install_systemd_timer; then
        out "\033[32m[✓]\033[0m Enabled systemd timer: local-https-renew.timer"
        return 0
      fi
    fi

    AUTORENEW_METHOD="cron"
    install_cron_job
    if has_logger; then
      out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> syslog."
    else
      out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> $CRON_LOG_PATH (logrotate enabled)."
    fi
    return 0
  fi

  echo ""
  echo "Your server certificate expires every 40 days."
  echo "Auto renew keeps HTTPS stable."
  echo ""
  echo "Choose auto renew method:"
  echo "1) systemd timer (recommended)"
  echo "2) cron (fallback)"
  echo "3) skip (not recommended)"
  local RSEL=""
  read -r -p "Choose (1-3): " RSEL
  pause_step

  case "$RSEL" in
    1|2|3) ;;
    *) RSEL="1" ;;
  esac

  if [ "$RSEL" = "3" ]; then
    local CONF=""
    read -r -p "Skip auto renew? Type SKIP to confirm: " CONF
    [ "$CONF" = "SKIP" ] || RSEL="1"
    pause_step
  fi

  if [ "$RSEL" = "1" ] && ! has_systemctl; then
    out "\033[31m[✗]\033[0m systemctl not found. Falling back to cron."
    RSEL="2"
  fi

  if [ "$RSEL" = "1" ]; then
    AUTORENEW_METHOD="systemd"
    out "\033[34m[i]\033[0m Installing systemd timer..."
    if install_systemd_timer; then
      out "\033[32m[✓]\033[0m Enabled systemd timer: local-https-renew.timer"
    else
      out "\033[31m[✗]\033[0m systemd timer failed. Falling back to cron."
      AUTORENEW_METHOD="cron"
      install_cron_job
      if has_logger; then
        out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> syslog."
      else
        out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> $CRON_LOG_PATH (logrotate enabled)."
      fi
    fi
  elif [ "$RSEL" = "2" ]; then
    AUTORENEW_METHOD="cron"
    out "\033[34m[i]\033[0m Installing cron job..."
    install_cron_job
    if has_logger; then
      out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> syslog."
    else
      out "\033[32m[✓]\033[0m Enabled cron job (daily at 03:00) -> $CRON_LOG_PATH (logrotate enabled)."
    fi
  else
    AUTORENEW_METHOD="none"
    out "\033[33m[>]\033[0m Auto renew not enabled."
  fi
}

final_output_install() {
  out "\033[36m[>]\033[0m Root CA + install guide + PEM output..."

  echo ""
  echo "Files in: $SSL_DIR"
  echo "  - Root CA:                $CA_CRT"
  echo "  - Server PEM (cert+key):  $SERVER_PEM"
  echo "  - Server cert:            $SERVER_CRT"
  echo "  - Server key:             $SERVER_KEY"
  echo "  - Server PFX:             $SERVER_PFX"
  echo "  - PFX password file:      $PFX_PASS_FILE"
  echo "  - Print PFX password:     $SCRIPT_CMD_NAME --print-pfx-pass"
  echo ""

  printf '%b\n' "\033[36m==================== Device install guide ====================\033[0m"
  printf '%b\n' "\033[90mGoal:\033[0m Install \033[1mrootCA.crt\033[0m as a \033[1mTrusted Root CA\033[0m on your devices."
  echo ""

  printf '%b\n' "\033[1m\033[34m[Windows]\033[0m"
  printf '%b\n' "  Win + R -> mmc"
  printf '%b\n' "  Add Certificates snap-in -> Computer account"
  printf '%b\n' "  Import rootCA.crt into Trusted Root Certification Authorities"
  echo ""

  printf '%b\n' "\033[1m\033[35m[macOS]\033[0m"
  printf '%b\n' "  Keychain Access -> System keychain"
  printf '%b\n' "  Import rootCA.crt and set Trust to Always Trust"
  echo ""

  printf '%b\n' "\033[1m\033[36m[iOS / iPadOS]\033[0m"
  printf '%b\n' "  Install profile, then enable Full Trust in Certificate Trust Settings"
  echo ""

  printf '%b\n' "\033[1m\033[32m[Android]\033[0m"
  printf '%b\n' "  Settings -> Security -> Encryption & credentials -> Install CA certificate"
  printf '%b\n' "  Note: some apps ignore user-installed CAs."
  echo ""

  printf '%b\n' "\033[1m\033[37m[Linux]\033[0m"
  printf '%b\n' "  Debian/Ubuntu: copy to /usr/local/share/ca-certificates/ then run: sudo update-ca-certificates"
  printf '%b\n' "\033[36m==============================================================\033[0m"
  echo ""

  out "\033[34m[i]\033[0m Root CA SHA-256 fingerprint:"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$CA_CRT" | awk '{print $1}'
  else
    openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || true
  fi
  pause_step
  echo ""
  printf '%b\n' "\033[36m==================== rootCA.crt (copy/paste) ====================\033[0m"
  [ -f "$CA_CRT" ] || die "Root CA not found: $CA_CRT"
  cat "$CA_CRT"
  printf '%b\n' "\033[36m=================================================================\033[0m"
  echo ""
  pause_step
}

status() {
  echo ""
  echo "==================== local-https status ===================="
  echo ""

  echo "[Install]"
  if [ -f "$INSTALL_MARKER" ] || [ -f "$INSTALL_PATH" ]; then
    echo "- Installed: yes"
    [ -f "$INSTALL_MARKER" ] && echo "- Marker: $INSTALL_MARKER"
    [ -f "$INSTALL_PATH" ] && echo "- Command: $INSTALL_PATH"
  else
    echo "- Installed: no (run: $SCRIPT_CMD_NAME --install)"
  fi
  echo ""

  echo "[Host]"
  local h ips
  h="$(hostname 2>/dev/null || true)"
  ips="$(hostname -I 2>/dev/null || true)"
  ips="$(printf '%s' "$ips" | tr -s ' ' | sed 's/[[:space:]]*$//' || true)"
  echo "- Hostname: ${h:-unknown}"
  echo "- IPs: ${ips:-unknown}"
  echo ""

  echo "[State]"
  if [ -f "$STATE_FILE" ]; then
    echo "- State file: present ($STATE_FILE)"
    echo "- Installed at: $(read_state_value installed_at)"
    echo "- Last run at: $(read_state_value last_run_at)"
    echo "- Applied targets: $(read_state_value applied_targets)"
    echo "- Auto renew method: $(read_state_value autorenew_method)"
    echo "- Cert renewed last run: $(read_state_value cert_renewed)"
    echo "- Server enddate (UTC): $(read_state_value server_enddate_utc)"
  else
    echo "- State file: missing ($STATE_FILE)"
  fi
  echo ""
}

print_ca() {
  require_installed
  [ -f "$CA_CRT" ] || die "Root CA not found: $CA_CRT"
  cat "$CA_CRT"
  exit 0
}

print_pfx_pass() {
  require_installed
  require_root
  [ -f "$PFX_PASS_FILE" ] && [ -s "$PFX_PASS_FILE" ] || die "PFX password file missing/empty: $PFX_PASS_FILE"
  cat "$PFX_PASS_FILE"
  exit 0
}

remove_cron_entry() {
  command -v crontab >/dev/null 2>&1 || return 0
  local tmp
  tmp="$(mktemp)"
  if crontab -l 2>/dev/null > "$tmp"; then
    awk -v ip="$INSTALL_PATH" '
      {
        has_renew = index($0, "--renew") > 0
        has_path = index($0, ip) > 0
        has_cmd  = index($0, "local-https") > 0
        if (has_renew && (has_path || has_cmd)) next
        print
      }
    ' "$tmp" | crontab - >/dev/null 2>&1 || true
  fi
  rm -f "$tmp"
}

uninstall() {
  require_root

  echo ""
  echo "==================== local-https uninstall ===================="
  echo ""
  echo "This will remove:"
  echo "- $INSTALL_PATH"
  echo "- systemd units: local-https-renew.service and local-https-renew.timer (if installed)"
  echo "- cron entry (if installed)"
  echo "- $CRON_LOG_PATH (if present)"
  echo "- $LOGROTATE_PATH (if present)"
  echo "- $STATE_DIR (marker + state)"
  echo "- Lighttpd block markers (# BEGIN local-https) (if present)"
  echo ""
  if [ "$UNINSTALL_PURGE" -eq 1 ]; then
    echo "Also requested:"
    echo "- Remove certificate directory: $SSL_DIR"
    echo ""
  fi

  if [ "$UNINSTALL_YES" -ne 1 ]; then
    read -r -p "Type UNINSTALL to continue: " c
    [ "$c" = "UNINSTALL" ] || die "Cancelled."
    if [ "$UNINSTALL_PURGE" -eq 1 ]; then
      read -r -p "Type PURGE to remove $SSL_DIR too: " p
      [ "$p" = "PURGE" ] || die "Cancelled (purge)."
    fi
  fi

  if has_systemctl; then
    systemctl disable --now local-https-renew.timer >/dev/null 2>&1 || true
    systemctl stop local-https-renew.service >/dev/null 2>&1 || true
  fi

  rm -f "$SYSTEMD_TIMER_PATH" "$SYSTEMD_SERVICE_PATH" >/dev/null 2>&1 || true

  if has_systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  remove_cron_entry
  rm -f "$CRON_LOG_PATH" >/dev/null 2>&1 || true
  rm -f "$LOGROTATE_PATH" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR" >/dev/null 2>&1 || true

  local lt="/etc/lighttpd/lighttpd.conf"
  if [ -f "$lt" ]; then
    if grep -qF "# BEGIN local-https" "$lt" 2>/dev/null && grep -qF "# END local-https" "$lt" 2>/dev/null; then
      remove_block "$lt" "# BEGIN local-https" "# END local-https"
      svc_restart lighttpd >/dev/null 2>&1 || true
    fi
  fi

  if [ "$UNINSTALL_PURGE" -eq 1 ]; then
    rm -rf "$SSL_DIR" >/dev/null 2>&1 || true
  fi

  rm -f "$INSTALL_PATH" >/dev/null 2>&1 || true

  echo ""
  echo "[✓] Uninstall completed."
  echo ""
}

check_only() {
  require_installed
  ensure_runtime_deps

  if [ ! -f "$SERVER_CRT" ]; then
    echo "[!] server.crt missing. Run: $SCRIPT_CMD_NAME --install"
    exit 10
  fi

  if server_cert_needs_renew; then
    echo "[>] Renew needed."
    exit 10
  fi

  echo "[✓] Certificate still valid. No renewal needed."
  exit 0
}

renew_flow() {
  NONINTERACTIVE=1
  BOOTSTRAP=0
  VERBOSE=0

  require_installed
  require_root
  ensure_runtime_deps

  [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || die "Root CA missing. Run: $SCRIPT_CMD_NAME --install"

  PIHOLE_PRESENT=0
  command -v pihole >/dev/null 2>&1 && PIHOLE_PRESENT=1

  TECH_PRESENT=0
  TECH_BASE_URL=""
  TECH_SERVICE=""
  
  if command -v curl >/dev/null 2>&1; then
    technitium_detect_base_url
  fi

  detect_technitium_service_name

  HOSTNAME="$(hostname 2>/dev/null || true)"
  [ -n "$HOSTNAME" ] || HOSTNAME="localhost"

  collect_san_ips_from_hostname_i

  TAILSCALE_DNS=""
  TAILSCALE_SHORT=""
  if command -v tailscale >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    TAILSCALE_DNS="$(tailscale status -json 2>/dev/null | jq -r '.Self.DNSName' 2>/dev/null | sed 's/\.$//' || true)"
    if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
      TAILSCALE_SHORT="${TAILSCALE_DNS%%.*}"
    else
      TAILSCALE_DNS=""
      TAILSCALE_SHORT=""
    fi
  fi

  mkdir -p "$SSL_DIR"
  cd "$SSL_DIR" || die "Failed to cd into $SSL_DIR."
  PIHOLE_FTL_CERT="$SERVER_PEM"

  CERT_RENEWED=0
  issue_or_renew_server_cert

  if [ "$CERT_RENEWED" -eq 0 ] && [ "$FORCE_RENEW" -eq 0 ]; then
    out "\033[32m[✓]\033[0m No renewal needed. Skipping PFX/deploy."
    write_state
    exit 0
  fi

  create_or_update_pfx
  
  apply_permissions
  restart_pihole_after_renew

  
  if [ "$CERT_RENEWED" -eq 1 ] && [ "$TECH_PRESENT" -eq 1 ]; then
    if [ -n "${TECH_SERVICE:-}" ]; then
      restart_or_warn "$TECH_SERVICE" "Technitium DNS"
    else
      out "\033[33m[!]\033[0m Technitium detected but service name not found. Restart manually."
    fi
  fi
  
  write_state
  
  echo "[✓] Renew completed."
  exit 0
}

rotate_pfx_flow() {
  require_installed
  require_root
  ensure_runtime_deps

  BOOTSTRAP=0

  banner
  confirm_start
  pause_step

  detect_pihole_and_technitium
  read_host_identity
  prepare_dir

  if [ "$TECH_PRESENT" -eq 1 ] && [ "$NONINTERACTIVE" -eq 1 ]; then
    if [ -z "${LOCAL_HTTPS_TECH_PASS:-}" ]; then
      if [ -z "${LOCAL_HTTPS_TECH_PASS_FILE:-}" ] || [ ! -f "${LOCAL_HTTPS_TECH_PASS_FILE:-}" ]; then
        die "Technitium detected. For noninteractive rotate, set LOCAL_HTTPS_TECH_PASS or LOCAL_HTTPS_TECH_PASS_FILE."
      fi
    fi
  fi

  [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || die "Root CA missing. Run: $SCRIPT_CMD_NAME --install"
  [ -f "$SERVER_CRT" ] && [ -f "$SERVER_KEY" ] || FORCE_RENEW=1
  issue_or_renew_server_cert

  out "\033[36m[>]\033[0m Rotating PFX password..."
  rotate_pfx_password_file

  out "\033[36m[>]\033[0m Rebuilding PFX with new password..."
  openssl pkcs12 -export \
    -out "$SERVER_PFX" \
    -inkey "$SERVER_KEY" \
    -in "$SERVER_CRT" \
    -certfile "$CA_CRT" \
    -passout file:"$PFX_PASS_FILE" >/dev/null 2>&1 || die "Failed to create PFX: $SERVER_PFX"

  apply_permissions
  configure_technitium_required_install

  print_repo_hint
  write_state
  out "\033[32m[✓]\033[0m PFX password rotation completed."
  exit 0
}

configure_flow() {
  require_installed
  require_root
  ensure_runtime_deps

  BOOTSTRAP=0

  banner
  confirm_start
  pause_step

  detect_pihole_and_technitium
  read_host_identity
  prepare_dir

  [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || create_or_reuse_ca
  [ -f "$SERVER_CRT" ] || FORCE_RENEW=1
  issue_or_renew_server_cert
  create_or_update_pfx

  apply_permissions
  apply_pihole_tls_install
  configure_technitium_required_install
  final_output_install

  print_repo_hint
  write_state
  out "\033[32m[✓]\033[0m Configure completed."
}

install_flow() {
  require_root

  if [ "${LOCAL_HTTPS_BOOTSTRAP:-0}" != "1" ]; then
    if [ -f "$INSTALL_MARKER" ] || [ -f "$STATE_FILE" ]; then
      echo ""
      echo "[✓] Already installed."
      [ -f "$INSTALL_PATH" ] && echo "- Command: $INSTALL_PATH"
      [ -f "$STATE_FILE" ] && echo "- State: $STATE_FILE"
      echo ""
      echo "Use:"
      echo "  $SCRIPT_CMD_NAME --renew"
      echo "  $SCRIPT_CMD_NAME --status"
      echo "  $SCRIPT_CMD_NAME --configure"
      echo "Reinstall only via:"
      echo "  $SCRIPT_CMD_NAME --uninstall --yes --purge-certs"
      echo "  $SCRIPT_CMD_NAME --install"
      echo ""
      exit 0
    fi
  fi

  banner
  confirm_start
  pause_step

  install_deps_interactive

  if [ "${LOCAL_HTTPS_BOOTSTRAP:-0}" = "1" ] && [ -x "$INSTALL_PATH" ]; then
    :
  else
    install_self
  fi

  detect_pihole_and_technitium
  read_host_identity
  prepare_dir
  create_or_reuse_ca
  issue_or_renew_server_cert
  create_or_update_pfx
  apply_permissions
  enable_autorenew_menu_install
  apply_pihole_tls_install
  configure_technitium_required_install
  final_output_install
  print_repo_hint

  write_state
  out "\033[32m[✓]\033[0m Done."
  echo ""
}

parse_cli() {
  [ "$#" -ge 1 ] || { print_help; exit 0; }

  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --install)
      shift
      install_flow
      exit 0
      ;;
    --renew)
      shift
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --force-renew) FORCE_RENEW=1 ;;
          *) ;;
        esac
        shift
      done
      renew_flow
      ;;
    --rotate-pfx-pass)
      shift
      rotate_pfx_flow
      ;;
    --check)
      shift
      check_only
      ;;
    --status)
      shift
      status
      exit 0
      ;;
    --print-ca)
      shift
      print_ca
      ;;
    --print-pfx-pass)
      shift
      print_pfx_pass
      ;;
    --configure)
      shift
      configure_flow
      exit 0
      ;;
    --uninstall)
      shift
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --yes) UNINSTALL_YES=1 ;;
          --purge-certs) UNINSTALL_PURGE=1 ;;
          *) ;;
        esac
        shift
      done
      uninstall
      exit 0
      ;;
    *)
      print_help
      exit 0
      ;;
  esac
}

parse_cli "$@"
