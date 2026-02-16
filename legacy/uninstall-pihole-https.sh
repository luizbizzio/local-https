#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2024-2026 Luiz Bizzio

RED='\033[31m'; GREEN='\033[32m'; BLUE='\033[34m'; YELLOW='\033[33m'; NC='\033[0m'

echo -e "${BLUE}[INFO] Starting Pi-hole HTTPS uninstall...${NC}"

# 1. Remove the certificate directory
CERT_DIR="/etc/ssl/mycerts"
if [ -d "$CERT_DIR" ]; then
  rm -rf "$CERT_DIR"
  echo -e "${GREEN}[OK] Removed certificate directory: $CERT_DIR${NC}"
else
  echo -e "${YELLOW}[WARN] Certificate directory not found: $CERT_DIR${NC}"
fi

# Optional: Remove certificate copy from /var/www/html
WEB_DIR="/var/www/html"
CRT_FILE="$WEB_DIR/$(hostname).crt"
if [ -f "$CRT_FILE" ]; then
  rm -f "$CRT_FILE"
  echo -e "${GREEN}[OK] Removed public certificate copy from $CRT_FILE${NC}"
fi

# 2. Check for Pi-hole v6+ config (FTL Webserver)
TOML_FILE="/etc/pihole/pihole.toml"
if [ -f "$TOML_FILE" ]; then
  echo -e "${BLUE}[INFO] Found $TOML_FILE. Reverting cert path to default...${NC}"

  # Replace cert line with default
  sed -i 's|^\s*cert\s*=.*|cert = "/etc/pihole/tls.pem"|' "$TOML_FILE"

  if systemctl list-units --type=service | grep -q pihole-FTL; then
    systemctl restart pihole-FTL && \
      echo -e "${GREEN}[OK] Restarted pihole-FTL.${NC}" || \
      echo -e "${RED}[ERROR] Failed to restart pihole-FTL.${NC}"
  fi

else
  # 3. Fallback to Lighttpd config (Pi-hole < v6)
  LIGHTTPD_CONF="/etc/lighttpd/lighttpd.conf"
  if [ -f "$LIGHTTPD_CONF" ]; then
    echo -e "${BLUE}[INFO] Reverting changes in $LIGHTTPD_CONF...${NC}"

    # Remove mod_openssl from module list
    sed -i '/"mod_openssl",/d' "$LIGHTTPD_CONF"

    # Remove SSL blocks added by the original script
    sed -i '/\$SERVER\["socket"\] == ":443"/,/\}/d' "$LIGHTTPD_CONF"
    sed -i '/\$SERVER\["socket"\] == ":80"/,/\}/d'  "$LIGHTTPD_CONF"

    if systemctl list-units --type=service | grep -q lighttpd; then
      systemctl restart lighttpd && \
        echo -e "${GREEN}[OK] Restarted Lighttpd.${NC}" || \
        echo -e "${RED}[ERROR] Failed to restart Lighttpd.${NC}"
    fi
  else
    echo -e "${YELLOW}[WARN] No configuration file found to update.${NC}"
  fi
fi

echo -e "${YELLOW}[INFO] Don't forget to remove the certificate manually from your devices if you installed it.${NC}"
echo -e "${GREEN}[✅] HTTPS uninstallation complete.${NC}"
