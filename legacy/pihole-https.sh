#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
  echo -e "\033[31m[ERROR] This script must be run as root (sudo).\033[0m"
  exit 1
fi

if ! command -v pihole &>/dev/null; then
  echo -e "\033[31m[ERROR] Pi-hole not detected. Please install Pi-hole before running this script.\033[0m"
  exit 1
fi

echo -e "\033[32m[OK] Running with administrative privileges.\033[0m"

if ! command -v openssl &>/dev/null; then
  apt-get update
  apt-get install -y openssl
fi

HOSTNAME=$(hostname)
echo -e "\033[34m[INFO] Detected hostname: $HOSTNAME\033[0m"

ALL_IPS=$(hostname -I)
echo -e "\033[34m[INFO] Detected IP addresses: $ALL_IPS\033[0m"

TAILSCALE_DNS=""
if command -v tailscale &>/dev/null; then
    echo -e "\033[34m[INFO] Tailscale detected, attempting to retrieve DNS...\033[0m"
    TAILSCALE_DNS=$(tailscale status -json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//')
    if [ -n "$TAILSCALE_DNS" ]; then
        echo -e "\033[32m[OK] Tailscale DNS retrieved: $TAILSCALE_DNS\033[0m"
    else
        echo -e "\033[33m[WARN] Tailscale found, but no DNS info available.\033[0m"
    fi
else
    echo -e "\033[31m[INFO] Tailscale is not installed or not configured. Skipping Tailscale DNS.\033[0m"
fi

SSL_DIR="/etc/ssl/mycerts"
mkdir -p "$SSL_DIR"
echo -e "\033[32m[OK] Created certificate directory at: $SSL_DIR\033[0m"
cd "$SSL_DIR"

cat << EOF > openssl.cnf
[ req ]
default_bits        = 2048
default_keyfile     = $HOSTNAME.key
distinguished_name  = req_distinguished_name
req_extensions      = v3_req
prompt = no

[ req_distinguished_name ]
CN = $HOSTNAME

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = CA:TRUE, pathlen:0
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[ alt_names ]
DNS.1 = $HOSTNAME
DNS.2 = pi.hole
EOF

if [ -n "$TAILSCALE_DNS" ]; then
    echo "DNS.3 = $TAILSCALE_DNS" >> openssl.cnf
fi

IP_INDEX=1
for IP in $ALL_IPS; do
    echo "IP.$IP_INDEX = $IP" >> openssl.cnf
    IP_INDEX=$((IP_INDEX + 1))
done

echo -e "\033[32m[OK] openssl.cnf file created in $SSL_DIR.\033[0m"

openssl genpkey -algorithm RSA -out "$HOSTNAME.key" -pkeyopt rsa_keygen_bits:2048
echo -e "\033[32m[OK] Private key generated: $HOSTNAME.key\033[0m"

openssl req -new -x509 -key "$HOSTNAME.key" -out "$HOSTNAME.crt" -config ./openssl.cnf -extensions v3_req -nodes -days 3650
echo -e "\033[32m[OK] Certificate created: $HOSTNAME.crt\033[0m"

cat "$HOSTNAME.key" "$HOSTNAME.crt" > "$HOSTNAME.pem"
echo -e "\033[32m[OK] PEM file created: $HOSTNAME.pem\033[0m"

chown root:root "$HOSTNAME."*
chmod 644 "$HOSTNAME."*
echo -e "\033[32m[OK] Ownership set to root:root, permissions set to 644.\033[0m"

LIGHTTPD_ACTIVE=false
if systemctl is-active --quiet lighttpd; then
    LIGHTTPD_ACTIVE=true
fi

if [ "$LIGHTTPD_ACTIVE" = true ]; then
    echo -e "\033[32m[OK] Lighttpd detected and running. Configuring SSL...\033[0m"
    apt-get update
    apt-get install -y lighttpd-mod-openssl
    echo -e "\033[32m[OK] lighttpd-mod-openssl installed.\033[0m"

    CONFIG_FILE="/etc/lighttpd/lighttpd.conf"
    PEM_PATH="$SSL_DIR/$HOSTNAME.pem"

    if ! grep -q '"mod_openssl"' "$CONFIG_FILE"; then
        sed -i '/server.modules = (/a\        "mod_openssl",' "$CONFIG_FILE"
        echo -e "\033[32m[OK] 'mod_openssl' added to $CONFIG_FILE.\033[0m"
    else
        echo -e "\033[33m[WARN] 'mod_openssl' is already present in $CONFIG_FILE.\033[0m"
    fi

    if ! grep -q 'ssl.engine = "enable"' "$CONFIG_FILE"; then
        cat << EOF >> "$CONFIG_FILE"
\$SERVER["socket"] == ":443" {
    ssl.engine = "enable"
    ssl.pemfile = "$PEM_PATH"
}

\$SERVER["socket"] == ":80" {
    url.redirect = ( "^/admin(.*)" => "https://$HOSTNAME/admin\$1" )
}
EOF
        echo -e "\033[32m[OK] SSL block appended to $CONFIG_FILE.\033[0m"
    else
        echo -e "\033[33m[WARN] SSL configuration already exists in $CONFIG_FILE.\033[0m"
    fi

    systemctl restart lighttpd
    if [ $? -eq 0 ]; then
        echo -e "\033[32m[OK] Lighttpd successfully restarted.\033[0m"
    else
        echo -e "\033[31m[ERROR] Failed to restart Lighttpd. Check logs.\033[0m"
    fi
else
    echo -e "\033[32m[OK] Lighttpd is not active. Assuming Pi-hole 6.0 FTL webserver.\033[0m"
    TOML_FILE="/etc/pihole/pihole.toml"
    PEM_PATH="$SSL_DIR/$HOSTNAME.pem"

    # 1) Make sure the file exists
    if [ ! -f "$TOML_FILE" ]; then
        touch "$TOML_FILE"
    fi

    # 2) Update or append [webserver] block
    if grep -q '^\[webserver\]' "$TOML_FILE"; then
        # Remove only the existing webserver block (and subsequent webserver.tls) if present
        sed -i '/^\[webserver\]/,/^\[/{/^\[webserver.tls\]/!d}' "$TOML_FILE"
        # If that fails to remove lines, they might be after a [webserver.tls]
        sed -i '/^\[webserver.tls\]/,/^\[/{/^\[webserver.paths\]/!d}' "$TOML_FILE"
    fi

    # 3) Insert the new [webserver] & [webserver.tls] lines if not found
    if ! grep -q '^\[webserver\]' "$TOML_FILE"; then
      cat << EOF >> "$TOML_FILE"

[webserver]
portssl = 443
EOF
    fi

    if grep -q '^\[webserver.tls\]' "$TOML_FILE"; then
        # Replace only cert = ... in the existing webserver.tls block
        sed -i '/^\[webserver.tls\]/,/^\[/{/^\s*cert\s*=/s|=.*|= "'"$PEM_PATH"'"|}' "$TOML_FILE"
    else
      cat << EOF >> "$TOML_FILE"

[webserver.tls]
cert = "$PEM_PATH"
EOF
    fi

    chown root:root "$TOML_FILE"
    chmod 644 "$TOML_FILE"
    echo -e "\033[32m[OK] Wrote TLS config to $TOML_FILE.\033[0m"
    sudo systemctl restart pihole-FTL
    echo -e "\033[32m[OK] pihole-FTL restarted.\033[0m"
fi

WEB_DIR="/var/www/html/admin"
CRT_FILE="$SSL_DIR/$HOSTNAME.crt"

if [ -d "$WEB_DIR" ]; then
    cp "$CRT_FILE" "$WEB_DIR/"
    chmod 644 "$WEB_DIR/$HOSTNAME.crt"
    echo -e "\033[32m[OK] Certificate copied to $WEB_DIR. Accessible via URL.\033[0m"
    if command -v hostname -I &>/dev/null; then
        IP_ADDRESS=$(hostname -I | awk '{print $1}')
        CERT_URL="http://$IP_ADDRESS/admin/$HOSTNAME.crt"
        echo -e "\033[34m[INFO] Download the certificate at:\033[0m"
        echo -e "\033[4;32m$CERT_URL\033[0m"
    else
        echo -e "\033[33m[WARN] Could not detect IP automatically.\033[0m"
        echo -e "\033[34mPlease manually retrieve $HOSTNAME.crt if needed.\033[0m"
    fi
else
    echo -e "\033[33m[WARN] $WEB_DIR does not exist. Certificate is not available via URL.\033[0m"
    echo -e "\033[34m[INFO] Certificate content (copy into a file named $HOSTNAME.crt):\033[0m"
    cat "$CRT_FILE"
fi

echo -e "\033[34m[INFO] Install this certificate as a Trusted Root CA on your devices.\033[0m"
echo -e "\033[34mSteps:\033[0m"
echo -e "\033[34m1. Download or copy the .crt file.\033[0m"
echo -e "\033[34m2. Open your OS certificate manager (Windows, Linux, Android, macOS).\033[0m"
echo -e "\033[34m3. Import it into 'Trusted Root Certification Authorities'.\033[0m"
echo -e "\033[34m4. Restart your browser or device if necessary.\033[0m"
echo -e "\033[32m[OK] Script completed!\033[0m\n"
echo -e "\033[33m⭐ If this script helped you, consider starring the repo:\n→ https://github.com/luizbizzio/pihole-https\033[0m"
