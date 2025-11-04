# Caddy LAN Reverse Proxy (Alpine/OpenRC)
[![Made with Shell](https://img.shields.io/badge/Made%20with-Shell-4EAA25?logo=gnu-bash&logoColor=white)](#-requirements)
[![Platform](https://img.shields.io/badge/Platform-Alpine%20Linux-blue?logo=alpinelinux&logoColor=white)](#-requirements)
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
curl -fsSL https://raw.githubusercontent.com/Tsadoq/setup-caddy-on-alpine/refs/heads/main/caddy-setup.sh | sudo sh -s -- DOMAIN=cordele.xyz HOME_LABEL=home ADMIN_EMAIL=you@cordele.xyz
```

Non-interactive purge of any prior install:

```bash
curl -fsSL [https://YOUR.URL/caddy-setup.sh](https://raw.githubusercontent.com/Tsadoq/setup-caddy-on-alpine/refs/heads/main/caddy-setup.sh) | sudo PURGE=1 sh -s -- DOMAIN=cordele.xyz HOME_LABEL=home ADMIN_EMAIL=you@cordele.xyz
```

After it finishes, add two AdGuard DNS rewrites pointing to your LXC IP:
```bash
home.cordele.xyz     → A → 192.168.1.51
*.home.cordele.xyz   → A → 192.168.1.51
```
Then add your first host:
```bash
caddy-add adguard.home.cordele.xyz 192.168.1.19 80
```

Test from a client that uses AdGuard DNS:
```bash
curl -I https://home.cordele.xyz
curl -I https://adguard.home.cordele.xyz
```

⸻

🛠 What the script does
	•	Installs Caddy (apk) and grants cap_net_bind_service.
	•	Writes a Caddyfile with a shared (lan-common) snippet (internal CA, compression, headers), a minimal base host for home.<domain>, and import /etc/caddy/sites/*.caddy.
	•	Drops helpers caddy-add / caddy-del for vhost lifecycle.
	•	Configures OpenRC to run Caddy with /etc/caddy/Caddyfile, enables on boot, restarts.
	•	Triggers first cert issuance (loopback) and copies CA to /root/caddy-internal-ca-root.crt.
	•	Prints AdGuard rewrite instructions.

⸻

🔐 Security model
	•	TLS is issued by Caddy’s internal CA (LAN-trusted once you install the CA on your devices).
	•	No public exposure or DNS-01 needed.
	•	No auth by default; add Caddy middlewares (basic auth/OIDC) per host if desired.
	•	Port binding via capabilities, not root.

⸻

🌐 Network & DNS
	•	Use AdGuard Home → Filters → DNS rewrites:
	•	home.<domain> → A → <CADDY_LXC_IP>
	•	*.home.<domain> → A → <CADDY_LXC_IP>
	•	Add AAAA if your LAN uses IPv6 and the LXC has one.
	•	Ensure clients actually use AdGuard as their DNS (via DHCP).

⸻

➕ Add / remove hosts

Add:

# bare host → reverse proxy to IP:PORT
caddy-add grafana.home.cordele.xyz 192.168.1.20 3000

# app behind a path prefix (strips /gitea before proxy)
caddy-add gitea.home.cordele.xyz 192.168.1.42 3000 /gitea

Remove:

caddy-del grafana.home.cordele.xyz

Each host becomes a self-contained vhost file at /etc/caddy/sites/<host>.caddy, and the helpers validate config before reload.

⸻

🧾 Trust the internal CA

The CA root is placed at /root/caddy-internal-ca-root.crt on the server.

Install it on your devices:
	•	macOS: Keychain Access → System → Certificates → Import → set Always Trust.
	•	iOS/iPadOS: AirDrop/email file → install profile → Settings → General → About → Certificate Trust Settings → enable.
	•	Windows: certmgr.msc → Trusted Root Certification Authorities → Certificates → Import.
	•	Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate.

⸻

🔍 Verify & manage

# Validate whole config
caddy validate --config /etc/caddy/Caddyfile

# Reload service (OpenRC)
rc-service caddy reload   # or: rc-service caddy restart

# Check listening sockets
ss -lntp | grep -E ':80|:443' || netstat -lnt | grep -E ':80|:443'


⸻

🧯 Troubleshooting
	•	Browser warns about cert → Install the CA root on that device.
	•	404 for a hostname → Did you caddy-add that host? Is the backend IP/port reachable from the LXC?
	•	Name resolves to wrong IP → Confirm AdGuard rewrites; make sure the client uses AdGuard DNS.
	•	Caddy fails to start → caddy validate for syntax; check /etc/conf.d/caddy; try rc-service caddy restart.
	•	Binding errors → If you replaced the binary, re-run setcap 'cap_net_bind_service=+ep' /usr/bin/caddy.

⸻

❓ FAQ

Is this Alpine-only?
Yes—this script targets Alpine + OpenRC. Ask if you want a cross-distro version (systemd, apt/dnf).

Can I bypass Caddy for a host?
Sure—add an exact DNS rewrite in AdGuard for that hostname pointing directly to the service IP. You’ll lose Caddy’s TLS/middlewares for that host.

Where are files?
Main: /etc/caddy/Caddyfile
Vhosts: /etc/caddy/sites/*.caddy
Helpers: /usr/local/bin/caddy-{add,del}
CA copy: /root/caddy-internal-ca-root.crt


