# Security Policy

## Supported versions

Security updates are provided for the latest stable release of `local-https`.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Older versions | No |

If you are using an older version, update before reporting a bug unless the issue also affects the latest release.

## Project scope

`local-https` is a local HTTPS helper for private networks. It creates a local Root CA, generates server certificates, builds PEM/PFX files, and can deploy them to supported services like Pi-hole, Technitium DNS, and Tailscale-based hostnames.

This project is not a public Certificate Authority. It is not meant to provide public internet TLS, public domain validation, or managed PKI for organizations.

## Security model

This tool assumes:

- You control the machine where `local-https` is installed.
- You run it with root privileges because it writes under `/etc/ssl/servercerts`, `/usr/local/sbin`, `/var/lib/local-https`, and system service locations.
- You understand that trusting `rootCA.crt` on a device allows certificates signed by this local CA to be trusted on that device.
- You keep `rootCA.key`, `server.key`, `server.pfx`, and `.pfx-pass` private.
- You do not expose generated private keys, PFX files, or the PFX password in logs, screenshots, issues, backups, or public repositories.

If the Root CA private key is leaked, every device that trusts that CA should remove it, and you should regenerate the CA and all server certificates.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues.

Use GitHub Private Vulnerability Reporting if it is available for this repository.

If private reporting is not available, open a public issue with only a minimal message, for example:

> I would like to report a security issue privately.

Do not include exploit details, secrets, keys, logs with private data, or reproduction steps in the public issue.

When reporting, include:

- Affected version or commit.
- Operating system and distribution.
- Installation method.
- Clear impact.
- Minimal reproduction steps.
- Whether the issue exposes private keys, weakens certificate generation, changes file permissions, bypasses prompts, or affects service deployment.

## What counts as a security issue

Please report issues such as:

- Private keys or PFX passwords being written with unsafe permissions.
- Generated certificates using unsafe cryptographic parameters.
- Command injection, path injection, or unsafe shell handling.
- Unsafe handling of service names, hostnames, SAN values, paths, or environment variables.
- Unintended exposure of `rootCA.key`, `server.key`, `server.pfx`, or `.pfx-pass`.
- Auto-renew logic that weakens permissions or exposes secrets.
- Installer behavior that can be abused to execute unexpected code.
- Incorrect trust guidance that could put users at risk.
- Service deployment behavior that exposes HTTPS files to the wrong user or group.

## What is not a security issue

The following are usually not security vulnerabilities in this project:

- Browser warnings before you install and trust `rootCA.crt`.
- Apps that ignore user-installed CAs.
- A device trusting the local CA because the user manually installed it.
- A public service being exposed to the internet by user configuration.
- Local network access risks caused by unrelated firewall, router, or DNS settings.
- Loss of local files due to user backup, sync, or permission changes outside this tool.
- Problems caused by modifying generated files manually.

## Sensitive data

Do not share:

- `rootCA.key`
- `server.key`
- `server.pfx`
- `.pfx-pass`
- Full private logs with hostnames, internal IPs, or Tailscale names unless required
- Screenshots that show secrets or private infrastructure details

For debugging, redact private values where possible.

## Installation risk

The one-line installer uses `curl` and `sudo bash`. That is convenient, but it requires trust in the repository and the network path used to download the script.

For a more reviewable install flow, download the script first, inspect it, then run it manually.

## Disclosure process

After a valid report is received:

1. The issue will be reviewed.
2. If confirmed, a fix will be prepared.
3. A patched release will be published when possible.
4. The vulnerability may be documented after users have had a reasonable chance to update.

There is currently no paid bug bounty program for this project.

## Hardening recommendations for users

- Keep `/etc/ssl/servercerts` readable only by root and the intended service group.
- Do not add normal user accounts to the `certs` group unless they really need certificate access.
- Rotate the PFX password if you think it was exposed.
- Regenerate the Root CA if `rootCA.key` may have been exposed.
- Remove old trusted Root CAs from devices when you reinstall or rotate the CA.
- Avoid copying generated private keys to desktops, phones, chat apps, or cloud drives.
- Keep the host updated with security patches.
- Review systemd timers, cron entries, and service permissions after installation.
