#!/bin/sh
# caddy-setup.sh — Alpine (OpenRC) Caddy with INTERNAL TLS (LAN-only)
# - Interactive by default; or pass flags (no env).
# - Robust install: uses apk when available, otherwise downloads official Caddy binary.
# - Per-vhost layout in /etc/caddy/sites/*.caddy (one site block per hostname).
# - Helpers: caddy-add / caddy-del (use absolute caddy path, validate before reload).
# - Optional purge of an existing Caddy install (with backup).
#
# Usage (interactive):
#   sudo sh caddy-setup.sh
#
# Usage (flags; prompts for anything missing):
#   sudo sh caddy-setup.sh --domain cordele.xyz --home-label home --admin-email you@cordele.xyz [--purge yes|no]

set -eu

# -------------------------- utils --------------------------
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }
die()  { err "$1"; exit 1; }

usage() {
  cat <<EOF
Usage:
  sudo sh $0 [--domain example.com] [--home-label home] [--admin-email you@example.com] [--purge yes|no]

If flags are omitted, you will be interactively prompted.

Flags:
  --domain        Your base domain (e.g., example.com)
  --home-label    Sub-zone label (default: home) -> serves home.<domain> and subdomains
  --admin-email   Email for Caddy metadata (internal CA)
  --purge         If Caddy is already installed: yes|no (if omitted you'll be asked)
EOF
}

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."; }

# ----------------------- preflight -------------------------
require_root

# Ensure Alpine
if [ -r /etc/os-release ]; then
  . /etc/os-release
  [ "${ID:-}" = "alpine" ] || die "This script targets Alpine Linux (OpenRC). Detected: ${ID:-unknown}"
else
  die "Cannot detect OS. This script targets Alpine Linux."
fi

# CLI inputs (no env)
DOMAIN=""; HOME_LABEL=""; ADMIN_EMAIL=""; PURGE=""

# ---------------------- parse flags ------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --domain=*)      DOMAIN="${1#*=}"; shift ;;
    --domain)        [ $# -gt 1 ] || die "Missing value for --domain"; DOMAIN="$2"; shift 2 ;;
    --home-label=*)  HOME_LABEL="${1#*=}"; shift ;;
    --home-label)    [ $# -gt 1 ] || die "Missing value for --home-label"; HOME_LABEL="$2"; shift 2 ;;
    --admin-email=*) ADMIN_EMAIL="${1#*=}"; shift ;;
    --admin-email)   [ $# -gt 1 ] || die "Missing value for --admin-email"; ADMIN_EMAIL="$2"; shift 2 ;;
    --purge=*)       PURGE="$(printf '%s' "${1#*=}" | tr '[:upper:]' '[:lower:]')"; shift ;;
    --purge)         [ $# -gt 1 ] || die "Missing value for --purge"; PURGE="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"; shift 2 ;;
    *) usage; die "Unknown flag: $1" ;;
  esac
done

# ----------------- interactive prompts ---------------------
ask() {
  # $1=prompt  $2=default -> sets REPLY_VAR
  local prompt="$1" def="${2:-}" ans
  if [ -n "$def" ]; then
    printf "%s [%s]: " "$prompt" "$def"
  else
    printf "%s: " "$prompt"
  fi
  IFS= read -r ans || true
  [ -n "$ans" ] || ans="$def"
  REPLY_VAR="$ans"
}

if [ -z "$DOMAIN" ]; then
  ask "Enter your domain (e.g., cordele.xyz)" ""
  DOMAIN="$REPLY_VAR"
fi
[ -n "$DOMAIN" ] || die "Domain is required."

if [ -z "$HOME_LABEL" ]; then
  ask "Enter the sub-zone label (creates <label>.$DOMAIN). Recommended: home" "home"
  HOME_LABEL="$REPLY_VAR"
fi

if [ -z "$ADMIN_EMAIL" ]; then
  ask "Admin email (for Caddy metadata, e.g., you@$DOMAIN)" "you@$DOMAIN"
  ADMIN_EMAIL="$REPLY_VAR"
fi

ZONE="${HOME_LABEL}.${DOMAIN}"

# --------- detect existing Caddy and maybe purge -----------
if command -v caddy >/dev/null 2>&1 || [ -x /usr/bin/caddy ] || [ -x /usr/local/bin/caddy ]; then
  CADDY_BIN="$(command -v caddy 2>/dev/null || { [ -x /usr/bin/caddy ] && echo /usr/bin/caddy || echo /usr/local/bin/caddy; })"
  say "Detected existing Caddy at: ${CADDY_BIN}"
  if [ -z "$PURGE" ]; then
    printf "Do you want to purge the old Caddy install before continuing? [y/N]: "
    read -r ans || true
    case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
      y|yes) PURGE="yes" ;;
      *)     PURGE="no" ;;
    esac
  fi
  case "$PURGE" in
    yes)
      say "Purging existing Caddy..."
      rc-service caddy stop >/dev/null 2>&1 || true
      rc-update del caddy default >/dev/null 2>&1 || true
      TS="$(date +%Y%m%d-%H%M%S)"
      BK="/root/caddy-backup-${TS}"
      mkdir -p "$BK"
      for d in /etc/caddy /var/lib/caddy /var/log/caddy /etc/conf.d/caddy /etc/init.d/caddy; do
        if [ -e "$d" ]; then
          cp -a "$d" "$BK/" 2>/dev/null || true
          rm -rf "$d"
        fi
      done
      rm -f /usr/local/bin/caddy-add /usr/local/bin/caddy-del
      if apk info -e caddy >/dev/null 2>&1; then
        apk del caddy >/dev/null 2>&1 || true
      fi
      # Remove any leftover binary
      rm -f "${CADDY_BIN}" 2>/dev/null || true
      say "Backup saved at: $BK"
      ;;
    no|"") : ;;
    *) die "--purge must be yes or no (got: $PURGE)" ;;
  esac
fi

# ---------------- install deps -----------------------------
say "Installing base packages..."
apk add --no-cache libcap iproute2 curl ca-certificates coreutils >/dev/null

# ---------------- try apk caddy ----------------------------
CADDY_BIN=""
APK_INSTALLED=0
if apk add --no-cache caddy >/dev/null 2>&1; then
  APK_INSTALLED=1
  if [ -x /usr/bin/caddy ]; then
    CADDY_BIN="/usr/bin/caddy"
  fi
fi

# -------- fallback: download official caddy binary ----------
if [ -z "$CADDY_BIN" ]; then
  say "apk caddy unavailable or binary not at /usr/bin/caddy — fetching official Caddy binary..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)   DL_ARCH="amd64" ;;
    aarch64)  DL_ARCH="arm64" ;;
    armv7l|armv7) DL_ARCH="armv7" ;;
    *) die "Unsupported architecture: $ARCH" ;;
  esac
  URL="https://caddyserver.com/api/download?os=linux&arch=${DL_ARCH}"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "$URL" -o "$TMP/caddy.tgz"
  tar -xzf "$TMP/caddy.tgz" -C "$TMP"
  install -m 0755 "$TMP/caddy" /usr/local/bin/caddy
  CADDY_BIN="/usr/local/bin/caddy"
fi

say "Caddy binary: $CADDY_BIN"
# Capabilities for low ports
if command -v setcap >/dev/null 2>&1; then
  setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" 2>/dev/null || true
fi

# ----------------- dirs & ownership ------------------------
say "Creating /etc/caddy /etc/caddy/sites /var/lib/caddy /var/log/caddy..."
mkdir -p /etc/caddy /etc/caddy/sites /var/lib/caddy /var/log/caddy
if id caddy >/dev/null 2>&1; then
  chown -R caddy:caddy /var/lib/caddy /var/log/caddy || true
fi

# --------------- write main Caddyfile ----------------------
say "Writing /etc/caddy/Caddyfile for ${ZONE} (internal CA)..."
if [ -f /etc/caddy/Caddyfile ]; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
fi
cat > /etc/caddy/Caddyfile <<EOF
{
  email ${ADMIN_EMAIL}
  # debug
}

# Shared LAN snippet: internal CA + compression + safe headers
(lan-common) {
  tls internal
  encode zstd gzip
  header {
    X-Content-Type-Options nosniff
    Referrer-Policy        no-referrer-when-downgrade
  }
}

# Base host for the zone (kept minimal so subdomains don't get shadowed)
${ZONE} {
  import lan-common
  respond "Caddy (tls internal) for ${ZONE} is up" 200
}

# Load per-host virtual hosts (only *.caddy files are imported)
import /etc/caddy/sites/*.caddy
EOF

# Optional: format file
"$CADDY_BIN" fmt -w /etc/caddy/Caddyfile >/dev/null 2>&1 || true

# ------------------- helpers -------------------------------
say "Installing helpers: caddy-add / caddy-del..."
cat > /usr/local/bin/caddy-add <<'EOF'
#!/bin/sh
# Usage: caddy-add <host.fqdn> <backend_ip> [port] [path_prefix]
set -eu
CADDY="$(command -v caddy 2>/dev/null || true)"
[ -x "$CADDY" ] || CADDY="/usr/bin/caddy"
[ -x "$CADDY" ] || CADDY="/usr/local/bin/caddy"

[ $# -ge 2 ] || { echo "Usage: $0 <host.fqdn> <backend_ip> [port] [path_prefix]" >&2; exit 1; }
host="$1"; ip="$2"; port="${3:-}"; prefix="${4:-}"
name=$(echo "$host" | tr '.' '-')
file="/etc/caddy/sites/${name}.caddy"
up="$ip"; [ -n "$port" ] && up="$ip:$port"

if [ -n "$prefix" ]; then
  cat >"$file" <<EOT
${host} {
  import lan-common
  handle_path ${prefix}* {
    reverse_proxy ${up}
  }
  @root path /
  redir @root ${prefix}/ 308
}
EOT
else
  cat >"$file" <<EOT
${host} {
  import lan-common
  reverse_proxy ${up}
}
EOT
fi

if ! "$CADDY" validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
  echo "Config invalid; leaving file in place: $file" >&2
  exit 1
fi

if command -v rc-service >/dev/null 2>&1; then
  rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
fi
echo "Added vhost: https://${host} -> http://${up}"
echo "File: $file"
EOF
chmod +x /usr/local/bin/caddy-add

cat > /usr/local/bin/caddy-del <<'EOF'
#!/bin/sh
# Usage: caddy-del <host.fqdn>
set -eu
CADDY="$(command -v caddy 2>/dev/null || true)"
[ -x "$CADDY" ] || CADDY="/usr/bin/caddy"
[ -x "$CADDY" ] || CADDY="/usr/local/bin/caddy"

[ $# -eq 1 ] || { echo "Usage: $0 <host.fqdn>" >&2; exit 1; }
name=$(echo "$1" | tr '.' '-')
file="/etc/caddy/sites/${name}.caddy"

if [ ! -f "$file" ]; then
  echo "Not found: $file" >&2
  exit 1
fi
rm -f "$file"

if ! "$CADDY" validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
  echo "Config invalid after removal!" >&2
  exit 1
fi

if command -v rc-service >/dev/null 2>&1; then
  rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
fi
echo "Removed vhost: https://$1"
EOF
chmod +x /usr/local/bin/caddy-del

# ----------------- OpenRC service --------------------------
if [ "$APK_INSTALLED" -eq 1 ] && [ -f /etc/init.d/caddy ]; then
  say "Using packaged OpenRC service."
  cat > /etc/conf.d/caddy <<EOF
# Ensure Caddy writes its data (including internal CA) to /var/lib/caddy
export XDG_DATA_HOME="/var/lib/caddy"
export XDG_CONFIG_HOME="/etc/caddy"
# Pass our config file explicitly
command_args="run --environ --config /etc/caddy/Caddyfile"
EOF
else
  say "Creating custom OpenRC service..."
  cat > /etc/init.d/caddy <<EOF
#!/sbin/openrc-run
name="Caddy"
description="Caddy (LAN reverse proxy with internal TLS)"
command="${CADDY_BIN}"
command_args="\${command_args:-run --environ --config /etc/caddy/Caddyfile}"
supervisor="supervise-daemon"
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/\${RC_SVCNAME}.log"
error_log="/var/log/\${RC_SVCNAME}.log"

depend() {
  need net
  use dns logger
}

start_pre() {
  export XDG_DATA_HOME="/var/lib/caddy"
  export XDG_CONFIG_HOME="/etc/caddy"
}
EOF
  chmod +x /etc/init.d/caddy
  # Minimal conf.d
  cat > /etc/conf.d/caddy <<'EOF'
# Extra args (override if needed)
command_args="run --environ --config /etc/caddy/Caddyfile"
EOF
fi

rc-update add caddy default >/dev/null 2>&1 || true
rc-service caddy restart >/dev/null 2>&1 || rc-service caddy start >/dev/null 2>&1 || true
sleep 1

# ------------- detect IP & trigger issuance ----------------
IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}' || true)"
LXC_IP="$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
[ -n "${LXC_IP:-}" ] || LXC_IP="<LXC_IP>"

say "Triggering internal TLS issuance (loopback)..."
"$CADDY_BIN" validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || true
curl -skI --resolve "${ZONE}:443:127.0.0.1" "https://${ZONE}/" >/dev/null 2>&1 || true

# Copy internal CA root for convenience and try to trust it on the server
CA_ROOT=""
for p in \
  /var/lib/caddy/pki/authorities/local/root.crt \
  /root/.local/share/caddy/pki/authorities/local/root.crt \
  /home/caddy/.local/share/caddy/pki/authorities/local/root.crt
do
  [ -f "$p" ] && CA_ROOT="$p" && break
done
if [ -n "$CA_ROOT" ]; then
  cp -f "$CA_ROOT" /root/caddy-internal-ca-root.crt 2>/dev/null || true
  install -m 0644 /root/caddy-internal-ca-root.crt /usr/local/share/ca-certificates/caddy-internal-ca.crt 2>/dev/null || true
  update-ca-certificates >/dev/null 2>&1 || true
fi

# ------------------------ summary --------------------------
cat <<EOF

==============================================================
✅ Caddy is running with INTERNAL TLS for:
   ${ZONE}  and  *.${ZONE}

➡️  In AdGuard Home add TWO DNS rewrites (Filters → DNS rewrites):
   1) ${ZONE}           → A → ${LXC_IP}
   2) *.${ZONE}         → A → ${LXC_IP}
   (Add AAAA as well if your LAN uses IPv6 and this host has v6.)

🧪 Test from a LAN client that uses AdGuard DNS:
   curl -I https://${ZONE}

➕ Add / remove hosts:
   caddy-add pihole.${ZONE} 192.168.1.19 80
   caddy-del pihole.${ZONE}

🔐 Trust Caddy's local CA on your devices for no warnings:
   - Server copy: /root/caddy-internal-ca-root.crt
     (Install it as a Trusted Root on macOS/Windows/iOS/Android.)

📂 Edit config:
   - Main:  /etc/caddy/Caddyfile
   - Hosts: /etc/caddy/sites/*.caddy   (one file per host)
   - Reload: rc-service caddy reload   (or restart)
==============================================================
EOF
