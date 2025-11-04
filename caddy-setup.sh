#!/bin/sh
# Alpine (OpenRC): Caddy + internal TLS (LAN-only HTTPS)
# - Optional purge of existing Caddy (with backups)
# - Per-host vhosts in /etc/caddy/sites/*.caddy
# - Shared snippet (lan-common) with internal CA + compression + headers
# - Helpers: caddy-add / caddy-del
# - Idempotent; safe to re-run

set -eu

# ---- Config via env or:  -s -- DOMAIN=... HOME_LABEL=... ADMIN_EMAIL=... ----
DOMAIN="${DOMAIN:-cordele.xyz}"
HOME_LABEL="${HOME_LABEL:-home}"              # serves home.$DOMAIN and subdomains
ADMIN_EMAIL="${ADMIN_EMAIL:-you@cordele.xyz}"
# PURGE behavior if Caddy already present: (unset = ask) 1=yes, 0=no
PURGE="${PURGE:-}"
# ------------------------------------------------------------------------------

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*"; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."; }
require_root

ZONE="${HOME_LABEL}.${DOMAIN}"

# ---- Optional purge path if Caddy already exists ----
if command -v caddy >/dev/null 2>&1; then
  CADDY_BIN="$(command -v caddy)"
  say "Detected existing Caddy at: ${CADDY_BIN}"
  if [ -z "${PURGE}" ]; then
    printf "Do you want to remove the old Caddy and clean config before continuing? [y/N]: "
    read -r ans || true
    case "$ans" in
      y|Y|yes|YES) PURGE=1 ;;
      *) PURGE=0 ;;
    esac
  fi

  if [ "${PURGE}" = "1" ]; then
    say "Stopping Caddy service (if running)..."
    rc-service caddy stop >/dev/null 2>&1 || true
    rc-update del caddy default >/dev/null 2>&1 || true

    say "Backing up and removing old Caddy files..."
    TS="$(date +%Y%m%d-%H%M%S)"
    BK="/root/caddy-backup-${TS}"
    mkdir -p "$BK"

    for d in /etc/caddy /var/lib/caddy /var/log/caddy /etc/conf.d/caddy; do
      if [ -e "$d" ]; then
        cp -a "$d" "$BK/" 2>/dev/null || true
        rm -rf "$d"
      fi
    done

    # Remove helpers if present
    rm -f /usr/local/bin/caddy-add /usr/local/bin/caddy-del

    # If installed via apk, remove package; else remove standalone binary
    if apk info -e caddy >/dev/null 2>&1; then
      say "Removing apk package: caddy"
      apk del caddy >/dev/null 2>&1 || true
    else
      warn "Caddy not owned by apk; removing ${CADDY_BIN}"
      rm -f "${CADDY_BIN}" || true
    fi

    say "Old Caddy removed. Backup saved under: ${BK}"
  else
    warn "Keeping existing Caddy install; proceeding to (re)configure."
  fi
fi

# ---- Install fresh Caddy + deps ----
say "Installing packages..."
apk add --no-cache caddy libcap iproute2 curl ca-certificates coreutils >/dev/null

say "Allowing Caddy to bind :80/:443 without root (cap_net_bind_service)..."
setcap 'cap_net_bind_service=+ep' /usr/bin/caddy 2>/dev/null || true

say "Creating directories..."
mkdir -p /etc/caddy /etc/caddy/sites /var/lib/caddy /var/log/caddy

# Ensure correct ownership for Alpine's packaged service (if user exists)
if id caddy >/dev/null 2>&1; then
  chown -R caddy:caddy /var/lib/caddy /var/log/caddy || true
fi

# ---- Main Caddyfile (per-vhost import, internal TLS) ----
say "Writing /etc/caddy/Caddyfile..."
if [ -f /etc/caddy/Caddyfile ]; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
fi
cat > /etc/caddy/Caddyfile <<EOF
{
  email ${ADMIN_EMAIL}
  # debug
}

# Shared LAN snippet: internal CA + compression + a couple of safe headers
(lan-common) {
  tls {
    issuer internal
  }
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

# Load per-host virtual hosts
import /etc/caddy/sites/*.caddy
EOF

# ---- Helpers ----
say "Installing helpers: caddy-add / caddy-del..."
cat > /usr/local/bin/caddy-add <<'EOF'
#!/bin/sh
# Usage: caddy-add <host.fqdn> <backend_ip> [port] [path_prefix]
set -eu
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

if caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
  echo "Added vhost: https://${host} -> http://${up}"
  echo "File: $file"
else
  echo "Config invalid; leaving file in place: $file" >&2
  exit 1
fi
EOF
chmod +x /usr/local/bin/caddy-add

cat > /usr/local/bin/caddy-del <<'EOF'
#!/bin/sh
# Usage: caddy-del <host.fqdn>
set -eu
[ $# -eq 1 ] || { echo "Usage: $0 <host.fqdn>" >&2; exit 1; }
name=$(echo "$1" | tr '.' '-')
file="/etc/caddy/sites/${name}.caddy"
if [ ! -f "$file" ]; then
  echo "Not found: $file" >&2
  exit 1
fi
rm -f "$file"
if caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
  echo "Removed vhost: https://$1"
else
  echo "Config invalid after removal!" >&2
  exit 1
fi
EOF
chmod +x /usr/local/bin/caddy-del

# ---- OpenRC service config ----
say "Configuring OpenRC service..."
cat > /etc/conf.d/caddy <<'EOF'
# Ensure Caddy writes its data (including internal CA) to /var/lib/caddy
export XDG_DATA_HOME="/var/lib/caddy"
export XDG_CONFIG_HOME="/etc/caddy"
# Pass our config file explicitly
command_args="run --environ --config /etc/caddy/Caddyfile"
EOF

rc-update add caddy default >/dev/null 2>&1 || true
rc-service caddy restart >/dev/null 2>&1 || rc-service caddy start >/dev/null 2>&1 || true
sleep 1

# ---- Detect container IP to suggest AdGuard rewrites ----
IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}' || true)"
LXC_IP="$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
[ -n "${LXC_IP:-}" ] || LXC_IP="<LXC_IP>"

# ---- Trigger internal TLS issuance (loopback) ----
say "Triggering internal TLS issuance (loopback)..."
curl -skI --resolve "${ZONE}:443:127.0.0.1" "https://${ZONE}/" >/dev/null 2>&1 || true

# ---- Copy/install internal CA root into server trust (best-effort) ----
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

cat <<EOF

==============================================================
✅ Caddy is running with INTERNAL TLS for:
   ${ZONE}  and  *.${ZONE}

➡️  In AdGuard Home add TWO DNS rewrites (Filters → DNS rewrites):
   1) ${ZONE}           → A → ${LXC_IP}
   2) *.${ZONE}         → A → ${LXC_IP}
   (Add AAAA as well if your LAN uses IPv6 and the LXC has v6.)

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
