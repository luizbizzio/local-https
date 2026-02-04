#!/bin/bash
set -e
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

STEP_DELAY="${STEP_DELAY:-1.0}"
NONINTERACTIVE=0

pause_step() { [ "$NONINTERACTIVE" -eq 1 ] && return 0; sleep "$STEP_DELAY"; }

out() { echo -e "$1"; pause_step; }
die() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

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

AUTORENEW_METHOD="none"
CERT_RENEWED=0
FORCE_RENEW=0
UNINSTALL_YES=0
UNINSTALL_PURGE=0

TECH_RESTART_ON_RENEW=1
TECH_RESTART_CLI_SET=0

has_systemctl() { command -v systemctl >/dev/null 2>&1; }
has_service_cmd() { command -v service >/dev/null 2>&1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

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
    out "\033[32m[OK]\033[0m ${label} restarted."
    return 0
  fi
  out "\033[33m[WARN]\033[0m Failed to restart ${label}. Run: $(svc_restart_cmd_hint "$name")"
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
      out "\033[33m[WARN]\033[0m Invalid input. Type y or n."
    fi
  done
}

read_state_value() {
  local key="$1"
  [ -f "$STATE_FILE" ] || return 0
  grep -E "^${key}=" "$STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true
}

write_state() {
  install -d -m 755 "$STATE_DIR" >/dev/null 2>&1 || true
  local ts applied tailscale="no" ca_fp="" srv_end="" method="" tr=""
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
    srv_end="$(openssl x509 -in "$SERVER_CRT" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
  fi

  method="${AUTORENEW_METHOD:-}"
  [ -n "$method" ] || method="$(read_state_value autorenew_method)"
  [ -n "$method" ] || method="none"

  tr="${TECH_RESTART_ON_RENEW:-}"
  [ -n "$tr" ] || tr="$(read_state_value tech_restart_on_renew)"
  [ -n "$tr" ] || tr="1"

  cat > "$STATE_FILE" <<EOF
installed_at=$(read_state_value installed_at)
last_run_at=$ts
hostname=${HOSTNAME:-$(hostname 2>/dev/null || true)}
applied_targets=$applied
autorenew_method=$method
tech_restart_on_renew=$tr
pihole_detected=${PIHOLE_PRESENT:-0}
technitium_detected=${TECH_PRESENT:-0}
tailscale_detected=$tailscale
rootca_fingerprint_sha256=$ca_fp
server_enddate=$srv_end
cert_renewed=${CERT_RENEWED:-0}
EOF

  touch "$INSTALL_MARKER" >/dev/null 2>&1 || true

  if [ -z "$(read_state_value installed_at)" ]; then
    sed -i "s/^installed_at=$/installed_at=$ts/" "$STATE_FILE" >/dev/null 2>&1 || true
  fi
}

detect_technitium_service_name() {
  TECH_SERVICE=""
  if ! has_systemctl; then
    return 0
  fi

  local unit=""
  unit="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '^technitium.*\.service$' | head -n1 || true)"
  if [ -n "$unit" ]; then
    TECH_SERVICE="$unit"
    return 0
  fi

  unit="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '(^|-)technitium(-|).*\.service$' | head -n1 || true)"
  [ -n "$unit" ] && TECH_SERVICE="$unit" || true
}

build_renew_args() {
  echo "--renew"
}

cron_line_build() {
  echo "0 3 * * * $INSTALL_PATH --renew >> $CRON_LOG_PATH 2>&1"
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
  echo "  $SCRIPT_CMD_NAME --renew [--force-renew] [--no-tech-restart]"
  echo "  $SCRIPT_CMD_NAME --check"
  echo "  $SCRIPT_CMD_NAME --status"
  echo "  $SCRIPT_CMD_NAME --uninstall [--yes] [--purge-certs]"
  echo ""
  echo "Notes:"
  echo "  - Running without args shows this help."
  echo "  - If already installed, --install will not run again."
  echo "  - Reinstall only via: --uninstall then --install"
  echo ""
}

banner() {
  echo -e "\033[36m============================================================\033[0m"
  echo -e "\033[1m\033[36m Local HTTPS Certificate Manager\033[0m \033[90m(local CA + renew + deploy)\033[0m"
  echo -e "\033[36m============================================================\033[0m"
  echo ""
  echo -e "\033[1mCommands\033[0m"
  echo -e "  - $SCRIPT_CMD_NAME --install"
  echo -e "  - $SCRIPT_CMD_NAME --renew [--force-renew] [--no-tech-restart]"
  echo -e "  - $SCRIPT_CMD_NAME --check | --status | --uninstall"
  echo ""
}

confirm_start() {
  if prompt_yn "Continue? (y/N): " "N"; then
    return 0
  fi
  echo -e "\033[31mAborted.\033[0m"
  exit 1
}

install_deps_interactive() {
  out "\033[36m[STAGE 1/11]\033[0m Checking dependencies..."
  need_apt

  PKGS=()
  need_cmd openssl || PKGS+=("openssl")
  need_cmd curl || PKGS+=("curl")
  need_cmd jq || PKGS+=("jq")

  if [ "${#PKGS[@]}" -gt 0 ]; then
    out "\033[34m[INFO]\033[0m Installing: ${PKGS[*]}"
    apt-get update >/dev/null || die "apt-get update failed"
    apt-get install -y "${PKGS[@]}" >/dev/null || die "apt-get install failed: ${PKGS[*]}"
    out "\033[32m[OK]\033[0m Dependencies installed."
  else
    out "\033[32m[OK]\033[0m Dependencies already present."
  fi
}

ensure_runtime_deps() {
  need_cmd openssl || die "Missing dependency: openssl. Run --install first."
  need_cmd hostname || die "Missing dependency: hostname."
}

install_self() {
  out "\033[36m[STEP]\033[0m Installing command: $INSTALL_PATH"

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
      out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"
      return 0
    fi
    install -m 755 "$src" "$INSTALL_PATH" >/dev/null 2>&1 || die "Failed to install to $INSTALL_PATH"
    out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"
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

  out "\033[32m[OK]\033[0m Installed: $INSTALL_PATH"

  if [ "${LOCAL_HTTPS_BOOTSTRAP:-0}" != "1" ]; then
    exec env LOCAL_HTTPS_BOOTSTRAP=1 "$INSTALL_PATH" --install
  fi
}

detect_pihole_and_technitium() {
  out "\033[36m[STAGE 2/11]\033[0m Detecting Pi-hole and Technitium..."

  if command -v pihole >/dev/null 2>&1; then
    PIHOLE_PRESENT=1
    out "\033[32m[OK]\033[0m Pi-hole detected."
  else
    PIHOLE_PRESENT=0
    out "\033[33m[WARN]\033[0m Pi-hole not detected."
  fi

  TECH_BASE_URL=""
  TECH_PRESENT=0

  if command -v curl >/dev/null 2>&1; then
    if curl -k -sS -o /dev/null --max-time 3 "https://127.0.0.1:53443/" 2>/dev/null; then
      TECH_BASE_URL="https://127.0.0.1:53443"
      TECH_PRESENT=1
    elif curl -sS -o /dev/null --max-time 3 "http://127.0.0.1:5380/" 2>/dev/null; then
      TECH_BASE_URL="http://127.0.0.1:5380"
      TECH_PRESENT=1
    fi
  fi

  if [ "$TECH_PRESENT" -eq 1 ]; then
    out "\033[32m[OK]\033[0m Technitium reachable at: $TECH_BASE_URL"
  else
    out "\033[33m[WARN]\033[0m Technitium not reachable on 127.0.0.1 (ports 5380/53443)."
  fi

  detect_technitium_service_name
  if [ -n "$TECH_SERVICE" ]; then
    out "\033[32m[OK]\033[0m Technitium service detected: $TECH_SERVICE"
  else
    out "\033[33m[INFO]\033[0m Technitium service name not detected."
  fi
}

read_host_identity() {
  out "\033[36m[STAGE 3/11]\033[0m Reading host identity..."

  HOSTNAME="$(hostname 2>/dev/null || true)"
  [ -n "$HOSTNAME" ] || HOSTNAME="localhost"

  ALL_IPS="$(hostname -I 2>/dev/null || true)"
  ALL_IPS="$(printf '%s' "$ALL_IPS" | tr -s ' ' | sed 's/[[:space:]]*$//' || true)"

  FILTERED_IPS=""
  for IP in $ALL_IPS; do
    case "$IP" in
      *%*) continue ;;
      *:*) FILTERED_IPS="$FILTERED_IPS $IP" ;;
      *.*.*.*) FILTERED_IPS="$FILTERED_IPS $IP" ;;
      *) continue ;;
    esac
  done
  FILTERED_IPS="$(echo "$FILTERED_IPS" | xargs || true)"

  out "\033[34m[INFO]\033[0m Hostname: $HOSTNAME"
  out "\033[34m[INFO]\033[0m IPs (raw): ${ALL_IPS:-none}"
  out "\033[34m[INFO]\033[0m IPs (SAN): ${FILTERED_IPS:-none}"

  TAILSCALE_DNS=""
  TAILSCALE_SHORT=""

  if command -v tailscale >/dev/null 2>&1; then
    out "\033[34m[INFO]\033[0m Tailscale detected, reading DNS name..."
    if command -v jq >/dev/null 2>&1; then
      TAILSCALE_DNS="$(tailscale status -json 2>/dev/null | jq -r '.Self.DNSName' 2>/dev/null | sed 's/\.$//' || true)"
    else
      TAILSCALE_DNS=""
    fi

    if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
      TAILSCALE_SHORT="${TAILSCALE_DNS%%.*}"
      out "\033[32m[OK]\033[0m Tailscale DNS: $TAILSCALE_DNS"
      out "\033[32m[OK]\033[0m Tailscale short name: $TAILSCALE_SHORT"
    else
      TAILSCALE_DNS=""
      TAILSCALE_SHORT=""
      out "\033[33m[WARN]\033[0m Tailscale present but DNSName not available (jq missing or DNSName empty)."
    fi
  else
    out "\033[33m[INFO]\033[0m Tailscale not installed. Skipping."
  fi
}

prepare_dir() {
  out "\033[36m[STAGE 4/11]\033[0m Preparing certificate directory..."
  mkdir -p "$SSL_DIR"
  cd "$SSL_DIR" || die "Failed to cd into $SSL_DIR."
  out "\033[32m[OK]\033[0m Using directory: $SSL_DIR"
  PIHOLE_FTL_CERT="$SERVER_PEM"
}

create_or_reuse_ca() {
  out "\033[36m[STAGE 5/11]\033[0m Creating or reusing Root CA..."

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
    out "\033[32m[OK]\033[0m Root CA created."
  else
    out "\033[32m[OK]\033[0m Root CA already exists."
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
  out "\033[36m[STAGE 6/11]\033[0m Issuing or renewing server certificate..."

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

  DNS_INDEX=2
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

  IP_INDEX=1
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

    if [ "$FORCE_RENEW" -eq 1 ]; then
      out "\033[32m[OK]\033[0m Server certificate forced renew (40 days)."
    else
      out "\033[32m[OK]\033[0m Server certificate issued or renewed (40 days)."
    fi
  else
    out "\033[32m[OK]\033[0m Server certificate still valid. No renewal needed."
  fi

  out "\033[34m[INFO]\033[0m Certificate SANs:"
  openssl x509 -in "$SERVER_CRT" -noout -ext subjectAltName 2>/dev/null || true
  pause_step
}

detect_pihole_stack() {
  if [ -f "/etc/lighttpd/conf-enabled/15-pihole-admin.conf" ] || [ -f "/etc/lighttpd/conf-enabled/10-pihole.conf" ]; then
    echo "lighttpd"
    return 0
  fi
  if svc_active lighttpd >/dev/null 2>&1 || pgrep -x lighttpd >/dev/null 2>&1; then
    if [ "$PIHOLE_PRESENT" -eq 1 ]; then
      echo "lighttpd"
      return 0
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
  out "\033[34m[INFO]\033[0m Pi-hole will use: $PIHOLE_FTL_CERT"

  if command -v pihole-FTL >/dev/null 2>&1; then
    pihole-FTL --config webserver.tls.cert "$PIHOLE_FTL_CERT" >/dev/null 2>&1 || true
    pihole-FTL --config webserver.tls.validity 0 >/dev/null 2>&1 || true
  fi

  pihole_toml_set_tls "$PIHOLE_FTL_CERT"
  out "\033[32m[OK]\033[0m Pi-hole TLS set to: $PIHOLE_FTL_CERT"
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
  out "\033[36m[STAGE 7/11]\033[0m Deploying certificate to Pi-hole (optional)..."

  if [ "$PIHOLE_PRESENT" -eq 0 ]; then
    out "\033[33m[INFO]\033[0m Pi-hole not present. Skipping."
    return 0
  fi

  local stack=""
  stack="$(detect_pihole_stack)"
  local preferred=""
  preferred="$(choose_preferred_dns)"

  echo ""
  out "\033[34m[INFO]\033[0m Pi-hole detected."
  out "\033[34m[INFO]\033[0m Web stack: $stack"
  out "\033[34m[INFO]\033[0m Certificate file: $SERVER_PEM"
  out "\033[34m[INFO]\033[0m Redirect host: $preferred"
  echo ""

  if ! prompt_yn_loop "Apply HTTPS to Pi-hole now? (y/N): " "N"; then
    out "\033[33m[INFO]\033[0m Skipping Pi-hole deploy."
    return 0
  fi

  if [ "$stack" = "lighttpd" ]; then
    out "\033[34m[INFO]\033[0m Pi-hole: configuring Lighttpd TLS..."
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

    out "\033[32m[OK]\033[0m Open: https://$preferred/admin"
    return 0
  fi

  if [ "$stack" = "ftl" ]; then
    out "\033[34m[INFO]\033[0m Pi-hole: configuring FTL webserver TLS..."
    deploy_pihole_ftl_tls
    restart_or_warn pihole-FTL "Pi-hole FTL" || true

    if command -v curl >/dev/null 2>&1; then
      if curl -k -sS -o /dev/null --max-time 3 "https://127.0.0.1/admin/" 2>/dev/null; then
        out "\033[32m[OK]\033[0m HTTPS check: https://127.0.0.1/admin is reachable."
      else
        out "\033[33m[WARN]\033[0m HTTPS check failed on localhost. If HTTPS works from your device, ignore this."
      fi
    fi

    out "\033[32m[OK]\033[0m Open: https://$preferred/admin"
    return 0
  fi

  out "\033[33m[WARN]\033[0m Could not detect Pi-hole web stack. Trying FTL config anyway."
  deploy_pihole_ftl_tls || true
  restart_or_warn pihole-FTL "Pi-hole FTL" || true
  out "\033[32m[OK]\033[0m Open: https://$preferred/admin"
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

maybe_update_pfx_on_renew() {
  [ -f "$PFX_PASS_FILE" ] || return 0
  [ -s "$PFX_PASS_FILE" ] || return 0
  [ -f "$SERVER_KEY" ] && [ -f "$SERVER_CRT" ] && [ -f "$CA_CRT" ] || return 0
  chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
  chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true

  if openssl pkcs12 -export -out "$SERVER_PFX" -inkey "$SERVER_KEY" -in "$SERVER_CRT" -certfile "$CA_CRT" -passout file:"$PFX_PASS_FILE" >/dev/null 2>&1; then
    out "\033[32m[OK]\033[0m PFX updated: $SERVER_PFX"
    return 0
  fi

  out "\033[33m[WARN]\033[0m Failed to update PFX: $SERVER_PFX"
  return 1
}

restart_technitium_after_renew_if_needed() {
  [ "${TECH_PRESENT:-0}" -eq 1 ] || return 0
  [ "${CERT_RENEWED:-0}" -eq 1 ] || return 0
  [ "${TECH_RESTART_ON_RENEW:-1}" -eq 1 ] || return 0

  detect_technitium_service_name

  if [ -n "$TECH_SERVICE" ]; then
    restart_or_warn "$TECH_SERVICE" "Technitium" || true
    return 0
  fi

  out "\033[33m[WARN]\033[0m Technitium detected, but service name not found. You may need to restart it manually."
  return 0
}

configure_technitium_optional_install() {
  out "\033[36m[STAGE 8/11]\033[0m Technitium configuration (optional)..."

  if [ "$TECH_PRESENT" -eq 0 ]; then
    out "\033[33m[INFO]\033[0m Technitium not detected or not reachable. Skipping."
    return 0
  fi

  if ! prompt_yn_loop "Configure Technitium TLS now? (y/N): " "N"; then
    out "\033[33m[INFO]\033[0m Skipping Technitium TLS config."
    return 0
  fi
  pause_step

  TECH_USER="admin"
  if [ "$NONINTERACTIVE" -eq 0 ]; then
    read -r -p "Technitium username (default: admin): " INPUT_USER
    [ -n "$INPUT_USER" ] && TECH_USER="$INPUT_USER"
  fi
  pause_step

  TECH_PASS=""
  if [ "$NONINTERACTIVE" -eq 0 ]; then
    read -r -s -p "Technitium password (hidden): " TECH_PASS
    echo ""
  fi
  pause_step

  TOTP=""
  if [ "$NONINTERACTIVE" -eq 0 ]; then
    read -r -p "TOTP (2FA) code if enabled (optional): " TOTP
  fi
  pause_step

  PFX_PASSWORD=""
  if [ "$NONINTERACTIVE" -eq 0 ]; then
    read -r -s -p "Create PFX password (required): " PFX_PASSWORD
    echo ""
  fi
  pause_step

  PFX_PASSWORD_CONFIRM=""
  if [ "$NONINTERACTIVE" -eq 0 ]; then
    read -r -s -p "Confirm PFX password: " PFX_PASSWORD_CONFIRM
    echo ""
  fi
  pause_step

  if [ -z "$PFX_PASSWORD" ] || [ "$PFX_PASSWORD" != "$PFX_PASSWORD_CONFIRM" ]; then
    out "\033[33m[WARN]\033[0m PFX password empty or mismatch. Skipping Technitium."
    return 0
  fi

  install -m 600 -o root -g root /dev/null "$PFX_PASS_FILE" >/dev/null 2>&1 || true
  printf '%s' "$PFX_PASSWORD" > "$PFX_PASS_FILE"
  chmod 600 "$PFX_PASS_FILE" >/dev/null 2>&1 || true
  chown root:root "$PFX_PASS_FILE" >/dev/null 2>&1 || true
  out "\033[32m[OK]\033[0m PFX password stored for auto renew: $PFX_PASS_FILE"

  openssl pkcs12 -export -out "$SERVER_PFX" -inkey "$SERVER_KEY" -in "$SERVER_CRT" -certfile "$CA_CRT" -passout file:"$PFX_PASS_FILE" >/dev/null 2>&1 || die "Failed to create PFX."
  out "\033[32m[OK]\033[0m PFX created: $SERVER_PFX"

  if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    out "\033[33m[WARN]\033[0m curl/jq missing. Skipping Technitium API config."
    return 0
  fi

  local tech_pass_file=""
  tech_pass_file="$(mktemp)"
  chmod 600 "$tech_pass_file" >/dev/null 2>&1 || true
  printf '%s' "$TECH_PASS" > "$tech_pass_file"

  LOGIN_JSON=""
  LOGIN_JSON="$(curl -kfsSL --max-time 10 -X POST \
    --data-urlencode "user=$TECH_USER" \
    --data-urlencode "pass@${tech_pass_file}" \
    --data-urlencode "includeInfo=true" \
    ${TOTP:+--data-urlencode "totp=$TOTP"} \
    "${TECH_BASE_URL}/api/user/login" 2>/dev/null || true)"

  rm -f "$tech_pass_file" >/dev/null 2>&1 || true

  [ -n "$LOGIN_JSON" ] || { out "\033[33m[WARN]\033[0m Technitium login empty."; return 0; }

  STATUS="$(printf '%s' "$LOGIN_JSON" | jq -r '.status' 2>/dev/null || echo "error")"
  [ "$STATUS" = "ok" ] || { out "\033[33m[WARN]\033[0m Technitium login failed."; return 0; }

  TOKEN="$(printf '%s' "$LOGIN_JSON" | jq -r '.token' 2>/dev/null || echo "")"
  [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { out "\033[33m[WARN]\033[0m Technitium token missing."; return 0; }

  SET_JSON=""
  SET_JSON="$(curl -kfsSL --max-time 12 -X POST \
    --data-urlencode "token=$TOKEN" \
    --data-urlencode "webServiceEnableTls=true" \
    --data-urlencode "webServiceUseSelfSignedTlsCertificate=false" \
    --data-urlencode "webServiceTlsCertificatePath=$SERVER_PFX" \
    --data-urlencode "webServiceTlsCertificatePassword@${PFX_PASS_FILE}" \
    "${TECH_BASE_URL}/api/settings/set" 2>/dev/null || true)"

  if [ -n "$SET_JSON" ]; then
    SET_STATUS="$(printf '%s' "$SET_JSON" | jq -r '.status' 2>/dev/null || echo "error")"
    if [ "$SET_STATUS" = "ok" ]; then
      out "\033[32m[OK]\033[0m Technitium TLS settings applied."
    else
      out "\033[33m[WARN]\033[0m Technitium settings/set failed."
    fi
  else
    out "\033[33m[WARN]\033[0m Technitium settings/set empty."
  fi

  curl -kfsSL --max-time 6 --get --data-urlencode "token=$TOKEN" "${TECH_BASE_URL}/api/user/logout" >/dev/null 2>&1 || true
}

apply_permissions() {
  out "\033[36m[STAGE 9/11]\033[0m Setting permissions (root + group '${CERT_GROUP}')..."

  getent group "$CERT_GROUP" >/dev/null 2>&1 || groupadd "$CERT_GROUP" >/dev/null 2>&1 || true

  if id -u www-data >/dev/null 2>&1; then
    usermod -aG "$CERT_GROUP" "www-data" >/dev/null 2>&1 || true
  fi

  if id -u pihole >/dev/null 2>&1; then
    usermod -aG "$CERT_GROUP" "pihole" >/dev/null 2>&1 || true
  fi

  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    id -u "$SUDO_USER" >/dev/null 2>&1 && usermod -aG "$CERT_GROUP" "$SUDO_USER" >/dev/null 2>&1 || true
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

  out "\033[32m[OK]\033[0m Permissions applied."
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
  touch "$CRON_LOG_PATH" >/dev/null 2>&1 || true
  chmod 644 "$CRON_LOG_PATH" >/dev/null 2>&1 || true
}

enable_autorenew_menu_install() {
  out "\033[36m[STAGE 10/11]\033[0m Auto renew (strongly recommended)"
  echo ""
  echo "Your server certificate expires every 40 days."
  echo "Auto renew keeps HTTPS stable."
  echo ""

  if [ "$TECH_PRESENT" -eq 1 ]; then
    echo "Technitium detected: recommended to restart it after renew."
    echo ""
  fi

  echo "Choose auto renew method:"
  echo "1) systemd timer (recommended)"
  echo "2) cron (fallback)"
  echo "3) skip (not recommended)"
  local RSEL=""
  if [ "$NONINTERACTIVE" -eq 1 ]; then
    RSEL="1"
  else
    read -r -p "Choose (1-3): " RSEL
  fi
  pause_step

  case "$RSEL" in
    1|2|3) ;;
    *) RSEL="1" ;;
  esac

  if [ "$RSEL" = "3" ]; then
    local CONF=""
    if [ "$NONINTERACTIVE" -eq 1 ]; then
      CONF="SKIP"
    else
      read -r -p "Skip auto renew? Type SKIP to confirm: " CONF
    fi
    [ "$CONF" = "SKIP" ] || RSEL="1"
    pause_step
  fi

  if [ "$TECH_PRESENT" -eq 1 ] && [ "$RSEL" != "3" ]; then
    if prompt_yn_loop "Restart Technitium after cert renew? (Y/n): " "Y"; then
      TECH_RESTART_ON_RENEW=1
    else
      TECH_RESTART_ON_RENEW=0
    fi
    pause_step
  fi

  if [ "$RSEL" = "1" ] && ! has_systemctl; then
    out "\033[33m[WARN]\033[0m systemctl not found. Falling back to cron."
    RSEL="2"
  fi

  if [ "$RSEL" = "1" ]; then
    AUTORENEW_METHOD="systemd"
    out "\033[34m[INFO]\033[0m Installing systemd timer..."
    if install_systemd_timer; then
      out "\033[32m[OK]\033[0m Enabled systemd timer: local-https-renew.timer"
    else
      out "\033[33m[WARN]\033[0m systemd timer failed. Falling back to cron."
      AUTORENEW_METHOD="cron"
      install_cron_job
      out "\033[32m[OK]\033[0m Enabled cron job (daily at 03:00)."
    fi
  elif [ "$RSEL" = "2" ]; then
    AUTORENEW_METHOD="cron"
    out "\033[34m[INFO]\033[0m Installing cron job..."
    install_cron_job
    out "\033[32m[OK]\033[0m Enabled cron job (daily at 03:00)."
  else
    AUTORENEW_METHOD="none"
    out "\033[33m[INFO]\033[0m Auto renew not enabled."
  fi
}

final_export_install() {
  out "\033[36m[STAGE 11/11]\033[0m Root CA export and install guide..."

  echo ""
  echo "Files in: $SSL_DIR"
  echo "  - Root CA:                $CA_CRT"
  echo "  - Server PEM (cert+key):  $SERVER_PEM"
  echo "  - Server cert:            $SERVER_CRT"
  echo "  - Server key:             $SERVER_KEY"
  [ -f "$SERVER_PFX" ] && echo "  - Server PFX:             $SERVER_PFX"
  echo ""
  pause_step

  out "\033[34m[INFO]\033[0m Root CA SHA-256 fingerprint:"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$CA_CRT" | awk '{print $1}'
  else
    openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || true
  fi
  pause_step

  out "\033[34m[INFO]\033[0m Root CA PEM:"
  echo ""
  cat "$CA_CRT"
  echo ""
  pause_step
}

final_device_guide_install() {
  echo ""
  echo -e "\033[36m==================== Device install guide ====================\033[0m"
  echo -e "\033[90mGoal:\033[0m Install \033[1mrootCA.crt\033[0m as a \033[1mTrusted Root CA\033[0m on your devices."
  echo ""

  echo -e "\033[1m\033[34m[Windows]\033[0m"
  echo -e "  Win + R -> mmc"
  echo -e "  Add Certificates snap-in -> Computer account"
  echo -e "  Import rootCA.crt into Trusted Root Certification Authorities"
  echo ""

  echo -e "\033[1m\033[35m[macOS]\033[0m"
  echo -e "  Keychain Access -> System keychain"
  echo -e "  Import rootCA.crt and set Trust to Always Trust"
  echo ""

  echo -e "\033[1m\033[36m[iOS / iPadOS]\033[0m"
  echo -e "  Install profile, then enable Full Trust in Certificate Trust Settings"
  echo ""

  echo -e "\033[1m\033[32m[Android]\033[0m"
  echo -e "  Settings -> Security -> Encryption & credentials -> Install CA certificate"
  echo -e "  Note: some apps ignore user-installed CAs."
  echo ""

  echo -e "\033[1m\033[37m[Linux]\033[0m"
  echo -e "  Debian/Ubuntu: copy to /usr/local/share/ca-certificates/ then run: sudo update-ca-certificates"
  echo ""

  echo -e "\033[36m==============================================================\033[0m"
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
    echo "- Technitium restart on renew: $(read_state_value tech_restart_on_renew)"
    echo "- Cert renewed last run: $(read_state_value cert_renewed)"
  else
    echo "- State file: missing ($STATE_FILE)"
  fi
  echo ""
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
  echo "[OK] Uninstall completed."
  echo ""
}

check_only() {
  require_installed
  ensure_runtime_deps

  if [ ! -f "$SERVER_CRT" ]; then
    echo "[WARN] server.crt missing. Run: $SCRIPT_CMD_NAME --install"
    exit 10
  fi

  if server_cert_needs_renew; then
    echo "[INFO] Renew needed."
    exit 10
  fi

  echo "[OK] Certificate still valid. No renewal needed."
  exit 0
}

renew_flow() {
  NONINTERACTIVE=1
  require_installed
  require_root
  ensure_runtime_deps

  if [ "$TECH_RESTART_CLI_SET" -eq 0 ]; then
    local v=""
    v="$(read_state_value tech_restart_on_renew)"
    if [ "$v" = "0" ]; then
      TECH_RESTART_ON_RENEW=0
    elif [ "$v" = "1" ]; then
      TECH_RESTART_ON_RENEW=1
    fi
  fi

  [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || die "Root CA missing. Run: $SCRIPT_CMD_NAME --install"

  PIHOLE_PRESENT=0
  command -v pihole >/dev/null 2>&1 && PIHOLE_PRESENT=1

  TECH_PRESENT=0
  TECH_BASE_URL=""
  if command -v curl >/dev/null 2>&1; then
    if curl -k -sS -o /dev/null --max-time 2 "https://127.0.0.1:53443/" 2>/dev/null; then
      TECH_PRESENT=1
      TECH_BASE_URL="https://127.0.0.1:53443"
    elif curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:5380/" 2>/dev/null; then
      TECH_PRESENT=1
      TECH_BASE_URL="http://127.0.0.1:5380"
    fi
  fi

  HOSTNAME="$(hostname 2>/dev/null || true)"
  [ -n "$HOSTNAME" ] || HOSTNAME="localhost"

  ALL_IPS="$(hostname -I 2>/dev/null || true)"
  ALL_IPS="$(printf '%s' "$ALL_IPS" | tr -s ' ' | sed 's/[[:space:]]*$//' || true)"

  FILTERED_IPS=""
  for IP in $ALL_IPS; do
    case "$IP" in
      *%*) continue ;;
      *:*) FILTERED_IPS="$FILTERED_IPS $IP" ;;
      *.*.*.*) FILTERED_IPS="$FILTERED_IPS $IP" ;;
      *) continue ;;
    esac
  done
  FILTERED_IPS="$(echo "$FILTERED_IPS" | xargs || true)"

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
    write_state
    exit 0
  fi

  apply_permissions
  maybe_update_pfx_on_renew || true
  apply_pihole_tls_renew_noninteractive
  restart_technitium_after_renew_if_needed
  write_state

  echo "[OK] Renew completed."
  exit 0
}

install_flow() {
  require_root

  if [ "${LOCAL_HTTPS_BOOTSTRAP:-0}" != "1" ]; then
    if [ -f "$INSTALL_MARKER" ] || [ -f "$STATE_FILE" ]; then
      echo ""
      echo "[OK] Already installed."
      [ -f "$INSTALL_PATH" ] && echo "- Command: $INSTALL_PATH"
      [ -f "$STATE_FILE" ] && echo "- State: $STATE_FILE"
      echo ""
      echo "Use:"
      echo "  $SCRIPT_CMD_NAME --renew"
      echo "  $SCRIPT_CMD_NAME --status"
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
  install_self

  detect_pihole_and_technitium
  read_host_identity
  prepare_dir
  create_or_reuse_ca
  issue_or_renew_server_cert
  apply_permissions
  apply_pihole_tls_install
  configure_technitium_optional_install
  enable_autorenew_menu_install
  final_export_install
  final_device_guide_install

  write_state

  out "\033[32m[OK]\033[0m Done."
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
          --no-tech-restart) TECH_RESTART_ON_RENEW=0; TECH_RESTART_CLI_SET=1 ;;
          --tech-restart) TECH_RESTART_ON_RENEW=1; TECH_RESTART_CLI_SET=1 ;;
          *) ;;
        esac
        shift
      done
      renew_flow
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
