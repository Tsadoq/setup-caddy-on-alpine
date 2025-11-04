#!/bin/sh
# caddy-setup.sh — Alpine (OpenRC) Caddy with INTERNAL TLS (LAN-only)
# - Interactive by default; or pass flags (no env vars are read).
# - Prefers APK install; auto-enables 'community' for your Alpine release.
# - Robust fallback to GitHub Releases (uses API to resolve latest versioned asset).
# - Per-vhost layout in /etc/caddy/sites/*.caddy (one file per hostname).
# - Helpers: caddy-add / caddy-del (validate before reload; auto-detect caddy path).
# - Optional purge of an existing Caddy install (with backup).

set -eu

# ---------- utils ----------
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }
die()  { err "$1"; exit 1; }

usage() {
  cat <<EOF
Usage:
  sudo sh $0 [--domain example.com] [--home-label home] [--admin-email you@example.com] [--purge yes|no]

Interactive if flags are omitted.

Flags:
  --domain        Your base domain (e.g., example.com)
  --home-label    Sub-zone label (default: home) -> serves home.<domain> and subdomains
  --admin-email   Email for Caddy metadata (internal CA)
  --purge         If Caddy already exists: yes|no (if omitted, you'll be asked)
EOF
}

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."; }

# ---------- preflight ----------
require_root
[ -r /etc/os-release ] || die "Cannot detect OS. This script targets Alpine Linux."
. /etc/os-release
[ "${ID:-}" = "alpine" ] || die "This script targets Alpine Linux (OpenRC). Detected: ${ID:-unknown}"

DOMAIN=""; HOME_LABEL=""; ADMIN_EMAIL=""; PURGE=""

# ---------- parse flags ----------
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

# ---------- interactive prompts ----------
ask() {
  # $1 prompt, $2 default -> REPLY_VAR
  local prompt="$1" def="${2:-}" ans
  [ -n "$def" ] && printf "%s [%s]: " "$prompt" "$def" || printf "%s: " "$prompt"
  IFS= read -r ans || true
  [ -n "$ans" ] || ans="$def"
  REPLY_VAR="$ans"
}

[ -n "$DOMAIN" ]     || { ask "Enter your domain (e.g., cordele.xyz)" ""; DOMAIN="$REPLY_VAR"; }
[ -n "$DOMAIN" ]     || die "Domain is required."
[ -n "$HOME_LABEL" ] || { ask "Enter the sub-zone label (creates <label>.$DOMAIN). Recommended: home" "home"; HOME_LABEL="$REPLY_VAR"; }
[ -n "$ADMIN_EMAIL" ]|| { ask "Admin email (e.g., you@$DOMAIN)" "you@$DOMAIN"; ADMIN_EMAIL="$REPLY_VAR"; }

ZONE="${HOME_LABEL}.${DOMAIN}"

# ---------- purge any existing install (optional) ----------
existing_caddy=""
if command -v caddy >/dev/null 2>&1; then existing_caddy="$(command -v caddy)"; fi
[ -z "$existing_caddy" ] && [ -x /usr/bin/caddy ] && existing_caddy="/usr/bin/caddy"
[ -z "$existing_caddy" ] && [ -x /usr/local/bin/caddy ] && existing_caddy="/usr/local/bin/caddy"

if [ -n "$existing_caddy" ]; then
  say "Detected existing Caddy at: ${existing_caddy}"
  if [ -z "$PURGE" ]; then
    printf "Do you want to purge the old Caddy install before continuing? [y/N]: "
    read -r ans || true
    case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in y|yes) PURGE="yes" ;; *) PURGE="no" ;; esac
  fi
  if [ "$PURGE" = "yes" ]; then
    say "Purging existing Caddy..."
    rc-service caddy stop >/dev/null 2>&1 || true
    rc-update del caddy default >/dev/null 2>&1 || true
    TS="$(date +%Y%m%d-%H%M%S)"; BK="/root/caddy-backup-${TS}"; mkdir -p "$BK"
    for d in /etc/caddy /var/lib/caddy /var/log/caddy /etc/conf.d/caddy /etc/init.d/caddy; do
      [ -e "$d" ] && cp -a "$d" "$BK/" 2>/dev/null || true
      [ -e "$d" ] && rm -rf "$d"
    done
    rm -f /usr/local/bin/caddy-add /usr/local/bin/caddy-del
    apk info -e caddy >/dev/null 2>&1 && apk del caddy >/dev/null 2>&1 || true
    rm -f "$existing_caddy" 2>/dev/null || true
    say "Backup saved at: $BK"
  fi
fi

# ---------- install base deps ----------
say "Installing base packages..."
apk add --no-cache libcap iproute2 curl tar ca-certificates coreutils >/dev/null

# ---------- ensure main+community repos for current Alpine ----------
REL="$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || true)"
if [ -n "$REL" ]; then
  REP="/etc/apk/repositories"
  grep -q "/alpine/v${REL}/main" "$REP" 2>/dev/null || \
    printf "https://dl-cdn.alpinelinux.org/alpine/v%s/main\n" "$REL" >> "$REP"
  grep -q "/alpine/v${REL}/community" "$REP" 2>/dev/null || \
    printf "https://dl-cdn.alpinelinux.org/alpine/v%s/community\n" "$REL" >> "$REP"
  apk update >/dev/null 2>&1 || true
fi

# ---------- try APK caddy ----------
APK_INSTALLED=0
if apk add --no-cache caddy >/dev/null 2>&1; then
  APK_INSTALLED=1
fi

# Detect Caddy path so far
CADDY_BIN="$(command -v caddy 2>/dev/null || true)"
[ -z "$CADDY_BIN" ] && [ -x /usr/bin/caddy ] && CADDY_BIN="/usr/bin/caddy"

# ---------- fallback: fetch versioned release asset (GitHub API) ----------
fetch_caddy_release() {
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)   DL_ARCH="amd64" ;;
    aarch64)  DL_ARCH="arm64" ;;
    armv7l|armv7) DL_ARCH="armv7" ;;
    *) echo "[x] Unsupported architecture: $ARCH" >&2; return 1 ;;
  esac

  API_URL="https://api.github.com/repos/caddyserver/caddy/releases/latest"
  JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: caddy-setup-script' "$API_URL")" || return 1
  TAG="$(printf '%s' "$JSON" | awk -F'"' '/"tag_name":/ {print $4; exit}')"
  [ -n "$TAG" ] || { echo "[x] Could not determine latest Caddy tag from GitHub API." >&2; return 1; }
  VER="${TAG#v}"
  PKG="caddy_${VER}_linux_${DL_ARCH}.tar.gz"
  URL_GH="https://github.com/caddyserver/caddy/releases/download/${TAG}/${PKG}"

  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  say "Downloading Caddy ${TAG} for ${DL_ARCH} from GitHub…"
  if ! curl -fL --retry 3 "$URL_GH" -o "$TMP/caddy.tgz"; then
    warn "GitHub download failed; trying SourceForge mirror…"
    URL_SF="https://sourceforge.net/projects/caddy.mirror/files/${TAG}/${PKG}/download"
    curl -fL --retry 3 "$URL_SF" -o "$TMP/caddy.tgz" || { echo "[x] Mirror download failed." >&2; return 1; }
  fi

  gzip -t "$TMP/caddy.tgz" 2>/dev/null || { echo "[x] Not a valid .tar.gz (network/CDN error)" >&2; return 1; }
  tar -xzf "$TMP/caddy.tgz" -C "$TMP"
  BIN_PATH="$(find "$TMP" -maxdepth 1 -type f -name caddy -perm -u+x | head -n1 || true)"
  [ -n "$BIN_PATH" ] || { echo "[x] Archive did not contain an executable 'caddy' binary." >&2; return 1; }

  install -m 0755 "$BIN_PATH" /usr/local/bin/caddy
  ln -sf /usr/local/bin/caddy /usr/bin/caddy
  CADDY_BIN="/usr/local/bin/caddy"
  return 0
}

if [ -z "${CADDY_BIN:-}" ]; then
  say "apk caddy not present — fetching Caddy from Releases…"
  fetch_caddy_release || die "Failed to obtain Caddy binary."
fi

say "Caddy binary: $CADDY_BIN"
command -v setcap >/dev/null 2>&1 && setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" 2>/dev/null || true

# ---------- dirs & ownership ----------
say "Creating /etc/caddy /etc/caddy/sites /var/lib/caddy /var/log/caddy..."
mkdir -p /etc/caddy /etc/caddy/sites /var/lib/caddy /var/log/caddy
id caddy >/dev/null 2>&1 && chown -R caddy:caddy /var/lib/caddy /var/log/caddy || true

# ---------- main Caddyfile ----------
say "Writing /etc/caddy/Caddyfile for ${ZONE} (internal CA)…"
[ -f /etc/caddy/Caddyfile ] && cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)" || true
cat > /etc/caddy/Caddyfile <<EOF
{
  email ${ADMIN_EMAIL}
  # debug
}

(lan-common) {
  tls internal
  encode zstd gzip
  header {
    X-Content-Type-Options nosniff
    Referrer-Policy        no-referrer-when-downgrade
  }
}

${ZONE} {
  import lan-common
  respond "Caddy (tls internal) for ${ZONE} is up" 200
}

import /etc/caddy/sites/*.caddy
EOF

"$CADDY_BIN" fmt -w /etc/caddy/Caddyfile >/dev/null 2>&1 || true

# ---------- helpers ----------
say "Installing helpers: caddy-add / caddy-del..."
cat > /usr/local/bin/caddy-add <<'EOF'
#!/bin/sh
set -eu
CADDY="$(command -v caddy 2>/dev/null || true)"; [ -x "$CADDY" ] || CADDY="/usr/bin/caddy"; [ -x "$CADDY" ] || CADDY="/usr/local/bin/caddy"
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
rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
echo "Added vhost: https://${host} -> http://${up}"
echo "File: $file"
EOF
chmod +x /usr/local/bin/caddy-add

cat > /usr/local/bin/caddy-del <<'EOF'
#!/bin/sh
set -eu
CADDY="$(command -v caddy 2>/dev/null || true)"; [ -x "$CADDY" ] || CADDY="/usr/bin/caddy"; [ -x "$CADDY" ] || CADDY="/usr/local/bin/caddy"
[ $# -eq 1 ] || { echo "Usage: $0 <host.fqdn>" >&2; exit 1; }
name=$(echo "$1" | tr '.' '-')
file="/etc/caddy/sites/${name}.caddy"
[ -f "$file" ] || { echo "Not found: $file" >&2; exit 1; }
rm -f "$file"
if ! "$CADDY" validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
  echo "Config invalid after removal!" >&2
  exit 1
fi
rc-service caddy reload >/dev/null 2>&1 || rc-service caddy restart >/dev/null 2>&1
echo "Removed vhost: https://$1"
EOF
chmod +x /usr/local/bin/caddy-del

# ---------- OpenRC service ----------
if [ $APK_INSTALLED -eq 1 ] && [ -f /etc/init.d/caddy ]; then
  say "Using packaged OpenRC service."
  cat > /etc/conf.d/caddy <<EOF
export XDG_DATA_HOME="/var/lib/caddy"
export XDG_CONFIG_HOME="/etc/caddy"
command_args="run --environ --config /etc/caddy/Caddyfile"
EOF
else
  say "Creating custom OpenRC service…"
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
depend() { need net; use dns logger; }
start_pre() {
  export XDG_DATA_HOME="/var/lib/caddy"
  export XDG_CONFIG_HOME="/etc/caddy"
}
EOF
  chmod +x /etc/init.d/caddy
  cat > /etc/conf.d/caddy <<'EOF'
command_args="run --environ --config /etc/caddy/Caddyfile"
EOF
fi

rc-update add caddy default >/dev/null 2>&1 || true
rc-service caddy restart >/dev/null 2>&1 || rc-service caddy start >/dev/null 2>&1 || true
sleep 1

# ---------- trigger issuance & trust CA locally ----------
IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}' || true)"
LXC_IP="$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
[ -n "${LXC_IP:-}" ] || LXC_IP="<LXC_IP>"

say "Triggering internal TLS issuance (loopback)…"
/bin/sh -c "$CADDY_BIN validate --config /etc/caddy/Caddyfile --adapter caddyfile" >/dev/null 2>&1 || true
curl -skI --resolve "${ZONE}:443:127.0.0.1" "https://${ZONE}/" >/dev/null 2>&1 || true

for p in \
  /var/lib/caddy/pki/authorities/local/root.crt \
  /root/.local/share/caddy/pki/authorities/local/root.crt \
  /home/caddy/.local/share/caddy/pki/authorities/local/root.crt
do
  if [ -f "$p" ]; then
    cp -f "$p" /root/caddy-internal-ca-root.crt 2>/dev/null || true
    install -m 0644 /root/caddy-internal-ca-root.crt /usr/local/share/ca-certificates/caddy-internal-ca.crt 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
    break
  fi
done

# ---------- summary ----------
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

📂 Edit config:
   - Main:  /etc/caddy/Caddyfile
   - Hosts: /etc/caddy/sites/*.caddy   (one file per host)
   - Reload: rc-service caddy reload   (or restart)
==============================================================
EOF
