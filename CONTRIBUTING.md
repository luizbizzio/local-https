# Contributing to Local HTTPS

[`local-https.sh`](local-https.sh) contains the main flow and [`install.sh`](install.sh) handles installation. The [README](README.md) describes the supported service integrations and certificate renewal.

## Review a change

- Check shell syntax with `bash -n local-https.sh` and `bash -n install.sh`.
- Exercise certificate and trust-store changes on a disposable Linux host with a test CA and a sample hostname. Check creation, a second run, renewal, and service reload for the integration you touched.
- Verify that existing service settings survive a retry or failure, and describe any manual recovery needed after a partially completed run.

Include the distribution and service versions, install or renewal path, and a sanitized summary of the output. Keep test CA private keys and machine-specific trust-store material out of the pull request.
