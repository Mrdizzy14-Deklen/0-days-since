#!/usr/bin/env bash
# One-time (and re-runnable) server setup for 0 Days Since on Ubuntu 24.04.
# Run as root on the server after deploy/push.sh has copied the project to /opt/zeroday.
set -euo pipefail

DOMAIN="${DOMAIN:-zero-days-since.work}"
APP=/opt/zeroday
export DEBIAN_FRONTEND=noninteractive

echo "==> System packages"
apt-get update -qq
apt-get install -y -qq curl git ufw rsync gnupg debian-keyring debian-archive-keyring apt-transport-https >/dev/null

echo "==> Swap (Next.js builds need headroom on small servers)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "==> Caddy"
if ! command -v caddy >/dev/null; then
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy >/dev/null
fi

echo "==> Node.js 22 + pnpm"
if ! command -v node >/dev/null || [ "$(node -v | cut -c2- | cut -d. -f1)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
fi
command -v pnpm >/dev/null || npm install -g pnpm@11.5.1 >/dev/null

echo "==> uv (Python)"
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh >/dev/null

echo "==> Service user"
id -u zeroday >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/zeroday --shell /usr/sbin/nologin zeroday
chown -R zeroday:zeroday "$APP"
chmod 600 "$APP/backend/.env" 2>/dev/null || true
chmod 600 "$APP"/backend/certs/*.pem 2>/dev/null || true

echo "==> Backend"
[ -f "$APP/backend/.env" ] || { echo "Missing $APP/backend/.env (run deploy/push.sh from your laptop)"; exit 1; }
sed -i "s|^FRONTEND_ORIGIN=.*|FRONTEND_ORIGIN=https://$DOMAIN|" "$APP/backend/.env"
sudo -u zeroday -H bash -c "cd $APP/backend && { [ -x .venv/bin/python ] || uv venv -q --python 3.12 .venv; } && uv pip install -q --python .venv/bin/python -e ."

echo "==> Dashboard"
ENVF="$APP/frontend/.env.production.local"
BENV="$APP/backend/.env"
# set_kv FILE KEY VALUE: replace or append KEY=VALUE (values here never contain '|').
set_kv() { if grep -q "^$2=" "$1"; then sed -i "s|^$2=.*|$2=$3|" "$1"; else echo "$2=$3" >> "$1"; fi; }
get_kv() { grep -E "^$2=" "$1" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
if [ ! -f "$ENVF" ]; then
  cat > "$ENVF" <<ENV
ZERODAY_API_URL=http://127.0.0.1:8000
AUTH_SECRET=$(openssl rand -base64 32 | tr -d '|')
AUTH_TRUST_HOST=true
ENV
fi
# Shared server-to-server token: generated once, kept in the dashboard env (not rsynced) and
# copied into backend/.env on every deploy so the dashboard API is never open in production.
TOKEN=$(get_kv "$ENVF" ZERODAY_API_TOKEN)
[ -n "$TOKEN" ] || TOKEN=$(openssl rand -hex 32)
set_kv "$ENVF" ZERODAY_API_TOKEN "$TOKEN"
set_kv "$BENV" API_TOKEN "$TOKEN"
# GitHub sign-in uses the GitHub App's Client ID / secret, kept in backend/.env on your laptop.
set_kv "$ENVF" AUTH_GITHUB_ID "$(get_kv "$BENV" GITHUB_CLIENT_ID)"
set_kv "$ENVF" AUTH_GITHUB_SECRET "$(get_kv "$BENV" GITHUB_CLIENT_SECRET)"
set_kv "$ENVF" NEXT_PUBLIC_GITHUB_APP_SLUG "${GITHUB_APP_SLUG:-$(get_kv "$BENV" GITHUB_APP_SLUG)}"
chown zeroday:zeroday "$ENVF" "$BENV" && chmod 600 "$ENVF" "$BENV"
sudo -u zeroday -H bash -c "cd $APP/frontend && pnpm install --frozen-lockfile --silent && pnpm build"

echo "==> Services + HTTPS"
install -m 644 "$APP/deploy/zeroday-backend.service" "$APP/deploy/zeroday-frontend.service" /etc/systemd/system/
install -m 644 "$APP/deploy/Caddyfile" /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable -q zeroday-backend zeroday-frontend caddy
systemctl restart zeroday-backend zeroday-frontend
systemctl reload caddy || systemctl restart caddy

echo "==> Firewall (SSH, HTTP, HTTPS only)"
ufw allow OpenSSH >/dev/null && ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

echo "==> Health"
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8000/api/health >/dev/null && break; sleep 1; done
curl -fsS http://127.0.0.1:8000/api/health && echo
for i in $(seq 1 30); do curl -fsS -o /dev/null http://127.0.0.1:3000/ && break; sleep 1; done
curl -fsS -o /dev/null -w "dashboard HTTP %{http_code}\n" http://127.0.0.1:3000/play
echo "Done. Open https://$DOMAIN (HTTPS certificates can take a minute after DNS points here)."
