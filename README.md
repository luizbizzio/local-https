<h1 align="center">Local HTTPS 🔒</h1>
<h4 align="center">(Previously pihole-https)</h4>
<p align="center">
Local Root CA and auto-renewed HTTPS certificates for private networks and services<br>
with automatic deployment to Pi-hole, Technitium, and Tailscale
</p>

`local-https` creates a local Root CA and issues a server certificate for your machine, so you can access web UIs over HTTPS without browser warnings (after trusting the Root CA on your devices).

It can automatically deploy certificates and reload supported services:
- ✅ **Pi-hole** (FTL webserver or Lighttpd)
- ✅ **Technitium DNS** (uses a password-protected `.pfx`)
- ✅ **Tailscale** (adds your Tailscale DNS name to the certificate SANs)

-----

It is officially supported on Debian-based distributions (Debian, Ubuntu, Raspberry Pi OS, Armbian). Other Linux distributions may work but are not officially supported.

## 🚀 One-Step Automated Install

```bash
curl -fsSL https://raw.githubusercontent.com/luizbizzio/local-https/main/install.sh | sudo bash
```

That installs the command to:

- `/usr/local/sbin/local-https`

Then it runs the setup flow (`local-https --install`) and offers auto-renew (systemd timer recommended).

During the interactive install you are asked for a **domain name** to add to the certificate (default `pi.hole`). Pick whatever your network uses (e.g. `home.lan`, `dns.home`). To set it non-interactively, pass it as an environment variable:

```bash
curl -fsSL https://raw.githubusercontent.com/luizbizzio/local-https/main/install.sh | sudo LOCAL_HTTPS_DOMAIN=home.lan bash
```

-----

## ✨ What it does

- 🔐 Creates (or reuses) a **local Root CA** (`rootCA.crt`)
- 🪪 Issues a **server certificate** (default: **40 days**) with SANs for:
  - hostname
  - relevant LAN IPs (filtered)
  - a configurable **domain name** (default `pi.hole`)
  - Tailscale DNS name when available
- 📦 Generates:
  - `server.pem` (cert + key, for services like Pi-hole)
  - `server.pfx` (password-protected, for services like Technitium)
- 🔁 Can enable **automatic renewal** via **systemd timer** (or cron fallback)
- 🧠 On renewal, it only “deploys/restarts” if a new cert was actually created (unless forced)

-----

## 🧭 Usage

| Command | What it does |
|---|---|
| `sudo local-https --install` | Full setup (Root CA, server cert, PEM/PFX, permissions, auto-renew, optional Pi-hole deploy, Technitium TLS if detected) |
| `sudo local-https --renew` | Renew if needed (near expiry window). If nothing to do, exits fast |
| `sudo local-https --renew --force-renew` | Forces a new server certificate + rebuilds PFX + restarts detected services |
| `sudo local-https --status` | Shows current status and last run info |
| `sudo local-https --check` | Exit code indicates if renewal is needed |
| `sudo local-https --configure` | Re-run deploy steps for Pi-hole / Technitium without reinstalling everything |
| `sudo local-https --print-ca` | Prints `rootCA.crt` (useful to copy to devices) |
| `sudo local-https --print-pfx-pass` | Prints the PFX password (stored in a root-only file) |
| `sudo local-https --rotate-pfx-pass` | Rotates PFX password, rebuilds PFX, updates Technitium TLS settings |
| `sudo local-https --uninstall [--yes] [--purge-certs]` | Removes installed files and optionally deletes generated certs |

-----

## 🌐 Custom domain

The certificate includes a friendly domain name (default `pi.hole`). If your network uses a different local domain, you can configure it. The chosen domain is added to the certificate SANs and is remembered across renewals (stored in the state file).

The domain is resolved with the following precedence (highest first):

1. **CLI flag** – `--domain` (works with `--install`, `--configure`, and `--renew`):
   ```bash
   sudo local-https --install --domain home.lan
   sudo local-https --configure --domain dns.home
   sudo local-https --renew --force-renew --domain home.lan
   ```
2. **Environment variable** – `LOCAL_HTTPS_DOMAIN`:
   ```bash
   sudo LOCAL_HTTPS_DOMAIN=home.lan local-https --install
   ```
3. **Persisted state** – whatever was chosen on the previous run (so renewals stay consistent).
4. **Pi-hole auto-detection** – on a fresh install, if Pi-hole is detected the script reads its configured `webserver.domain` (via `pihole-FTL --config`, falling back to `/etc/pihole/pihole.toml`) and uses that as the default.
5. **Default** – `pi.hole`.

During an interactive `--install`/`--configure` you are also prompted, pre-filled with the resolved value (press Enter to keep it).

To change the domain on an existing install, run `sudo local-https --configure --domain <name>` (or `sudo local-https --renew --force-renew --domain <name>`). The Root CA stays the same, so there is nothing new to trust on your devices.

-----

## 🔁 Auto-renew (how it works)

- 📅 The server certificate is issued for **40 days**.
- ⏳ `--renew` only renews when the cert is close to expiry (default window: **7 days**).
- 🧩 If you enable systemd timer, it runs daily (with randomized delay).

Check the timer:

```bash
systemctl list-timers | grep local-https
systemctl status local-https-renew.timer --no-pager
```

See logs:

```bash
journalctl -u local-https-renew.service -n 100 --no-pager
```

Force-run via systemd (without editing unit files):

```bash
sudo systemd-run --unit=local-https-renew-force --service-type=oneshot   /usr/local/sbin/local-https --renew --force-renew
```

-----

## 🧩 Service support

### 🟦 Pi-hole

- Detects Pi-hole automatically.
- Supports:
  - **FTL webserver TLS** (Pi-hole 6+)
  - **Lighttpd TLS** (older setups)
- On renew (when a new cert is created), it restarts the correct service so the new cert is used.

### 🟩 Technitium DNS

- If Technitium is detected, the script can configure Technitium Web UI TLS to use:
  - `server.pfx` + the stored password
- On renew (when a new cert is created), it restarts the Technitium service so the new cert is loaded.

### 🟪 Tailscale

- If `tailscale` and `jq` are available, the script adds your Tailscale DNS name (like `host.ts.net`) to the certificate SANs.

-----

### ⚙️ Other services (Grafana, Nginx, etc.)

Any service that needs to read the certificate files can be granted access by adding its user to the `certs` group:
````bash
sudo usermod -aG certs grafana
sudo usermod -aG certs nginx
````

Group membership is preserved across renewals, once added, the service will continue to have access after every certificate rotation without any manual intervention.

-----

## 📦 Files created

Default folder:

- `/etc/ssl/servercerts`

Main files:

- `rootCA.crt` and `rootCA.key` (local Root CA)
- `server.crt`, `server.key`, `server.pem`
- `server.pfx` and `.pfx-pass` (password file)

State:

- `/var/lib/local-https/state.env`

-----

## 📱💻 Install the Root CA on your devices

You must trust `rootCA.crt` on your device to avoid HTTPS warnings.

Get the certificate from the server:

- Print in terminal: `sudo local-https --print-ca`
- Or copy the file: `/etc/ssl/servercerts/rootCA.crt`

### 🪟 Windows

1. Copy `rootCA.crt` to your PC.
2. Double-click it → **Install Certificate**
3. Choose **Local Machine**
4. Put it in **Trusted Root Certification Authorities**
5. Reopen the browser.

### 🍏 macOS

1. Open **Keychain Access**
2. Drag `rootCA.crt` into **System** keychain
3. Open the cert → set **Trust** to **Always Trust**

### 📱 iOS / iPadOS

1. AirDrop/email the `rootCA.crt` to the device, open it
2. Settings → **General** → **VPN & Device Management** → install profile
3. Settings → **General** → **About** → **Certificate Trust Settings** → enable full trust

### 🤖 Android

1. Copy `rootCA.crt` to the phone
2. Settings → Security → Encryption & credentials → **Install a certificate** → **CA certificate**
3. Note: some apps ignore user-installed CAs.

### 🐧 Linux (Debian/Ubuntu)

```bash
sudo cp rootCA.crt /usr/local/share/ca-certificates/local-https-rootCA.crt
sudo update-ca-certificates
```

-----

### Why 40-day certificates

Public TLS Certificate Authorities and browser policies now favor shorter lifetimes (around 40–45 days) for security reasons. Our default 40-day validity matches this industry trend and avoids issues with browser trust and automated renewals. See SSL.com’s discussion on ~47-day certificates:
https://www.ssl.com/article/preparing-for-47-day-ssl-tls-certificates/

-----

## 📝 Notes

- 🧱 This is a **local CA**. It is for your own network and devices, not public HTTPS.
- 🧪 If you are testing renew: use `sudo local-https --renew --force-renew` and confirm the new `notAfter` date with OpenSSL.
- 🔧 Pi-hole Lighttpd mode may install `lighttpd-mod-openssl` via `apt-get`.
- 🐳 Not intended for container-based TLS termination or Docker ingress setups.
- 🧷 The PFX password is stored in a root-only file. Treat it as a secret.
- 🔄 The `certs` group membership is preserved on every renew, any user or service manually added to the group (e.g. `grafana`, `nginx`) will automatically retain access after certificate rotation.

-----

## 📄 License

This repository is licensed under the [Mozilla Public License Version 2.0](./LICENSE)
