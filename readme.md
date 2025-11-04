# Caddy LAN Reverse Proxy (Alpine/OpenRC)
[![Made with Shell](https://img.shields.io/badge/Made%20with-Shell-4EAA25?logo=gnu-bash&logoColor=white)](#-requirements)
[![Platform](https://img.shields.io/badge/Platform-Alpine%20Linux-blue?logo=alpinelinux&logoColor=white)](#-requirements)
[![Headless Ready](https://img.shields.io/badge/Headless-Ready-success)](#-what-you-get)
[![LAN TLS](https://img.shields.io/badge/TLS-Internal%20CA-informational)](#-security-model)

Single-command setup for a **home LAN reverse proxy** on **Alpine Linux (OpenRC)** using **Caddy** with its **internal CA** (no public ACME, no Namecheap).
It installs Caddy, creates a clean **per-vhost layout**, adds **`caddy-add` / `caddy-del`** helpers, prints **AdGuard** DNS rewrites, and survives reboots.

---

## Table of contents
- [What you get](#-what-you-get)
- [Read this first](#️-read-this-first)
- [Requirements](#-requirements)
- [Quick start](#-quick-start)
- [What the script does](#-what-the-script-does)
- [Security model](#-security-model)
- [Network & DNS](#-network--dns)
- [Add / remove hosts](#-add--remove-hosts)
- [Trust the internal CA](#-trust-the-internal-ca)
- [Verify & manage](#-verify--manage)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)

---

## ✨ What you get
- **Caddy** running on Alpine with **OpenRC** (enabled at boot).
- **Internal TLS** (Caddy’s local CA) for `home.<domain>` and `*.home.<domain>`.
- **Per-vhost Caddyfiles** in `/etc/caddy/sites/*.caddy` + a shared snippet `(lan-common)`.
- **Helpers**
  - `caddy-add <host> <ip> [port] [path_prefix]`
  - `caddy-del <host>`
- Proper **bind caps** (`cap_net_bind_service`) so no root ports hackery.
- A copy of the **CA root** at `/root/caddy-internal-ca-root.crt`.
- Idempotent: safe to **re-run**; optional **purge** of old installs.

---

## ⚠️ Read this first
- Designed for **Alpine Linux** (e.g., an **LXC** or VM). Uses **apk** + **OpenRC**.
- Intended for **LAN use**. Browsers will warn until you **trust the CA** on your devices.
- You’ll need **AdGuard Home** (or equivalent) to point DNS at the proxy.
- The script writes/overwrites:
  - `/etc/caddy/Caddyfile`, `/etc/caddy/sites/`, `/etc/conf.d/caddy`
  - ensures `/var/lib/caddy` & `/var/log/caddy` exist
- Re-run friendly. If Caddy is already present, it will **ask to purge** (or honor `PURGE=1/0`).

---

## ✅ Requirements
- Alpine Linux (root or `sudo`).
- Network where **AdGuard Home** can serve your clients’ DNS.
- The script installs needed packages automatically: `caddy libcap iproute2 curl ca-certificates coreutils`.

---

## 🚀 Quick start
Run with your domain/email (defaults shown):

```bash
curl -fsSL https://YOUR.URL/caddy-setup.sh \
| sudo sh -s -- DOMAIN=cordele.xyz HOME_LABEL=home ADMIN_EMAIL=you@cordele.xyz
