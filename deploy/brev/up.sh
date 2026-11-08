#!/usr/bin/env bash
# From your laptop: start Nemotron on a Brev GPU and switch the live backend to it.
#   deploy/brev/up.sh <brev-instance-name> <vultr-ip>
# NVIDIA's hosted API stays configured as the fallback, so scans keep working if Brev drops.
set -euo pipefail
INSTANCE="${1:?usage: deploy/brev/up.sh <brev-instance-name> <vultr-ip>}"
VULTR="${2:?usage: deploy/brev/up.sh <brev-instance-name> <vultr-ip>}"
cd "$(dirname "$0")/../.."
command -v brev >/dev/null || { echo "Install the Brev CLI: brew install brevdev/homebrew-brev/brev && brev login"; exit 1; }

# NGC key for nvcr.io: NGC_API_KEY from backend/.env, else the NVIDIA API key (nvapi-...) already there.
NGC=$(grep -E '^NGC_API_KEY=' backend/.env | cut -d= -f2- || true)
[ -n "$NGC" ] || NGC=$(grep -E '^LLM_API_KEY=' backend/.env | cut -d= -f2-)
[ -n "$NGC" ] || { echo "Put NGC_API_KEY=... in backend/.env"; exit 1; }

echo "==> Brev SSH config"; brev refresh >/dev/null
scp -q deploy/brev/nim.sh "$INSTANCE:nim.sh"

echo "==> Authorize the tunnel key on Vultr (port-forward only, nothing else)"
PUB=$(ssh "$INSTANCE" 'bash nim.sh tunnel-key')
ssh "root@$VULTR" "PUB='$PUB' bash -s" <<'REMOTE'
set -euo pipefail
id nimtunnel >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin nimtunnel
install -d -m 700 -o nimtunnel -g nimtunnel /home/nimtunnel/.ssh
echo "restrict,port-forwarding,permitlisten=\"127.0.0.1:8100\",permitopen=\"127.0.0.1:8100\",command=\"/bin/false\" $PUB" \
  > /home/nimtunnel/.ssh/authorized_keys
chown nimtunnel:nimtunnel /home/nimtunnel/.ssh/authorized_keys
chmod 600 /home/nimtunnel/.ssh/authorized_keys
REMOTE

echo "==> Start Nemotron on $INSTANCE"
printf '%s\n' "$NGC" | ssh "$INSTANCE" "VULTR_IP=$VULTR bash nim.sh start"

echo "==> Switch the backend to Brev (hosted API as fallback)"
ssh "root@$VULTR" 'bash -s' <<'REMOTE'
set -euo pipefail
cd /opt/zeroday/backend
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8100/v1/models >/dev/null && break; sleep 2; done
curl -fsS http://127.0.0.1:8100/v1/models >/dev/null || { echo "Tunnel not up yet on Vultr:8100"; exit 1; }
KEY=$(grep -E '^LLM_API_KEY=' .env | cut -d= -f2-)
MODEL=$(grep -E '^LLM_MODEL=' .env | cut -d= -f2-)
cat > .env.local <<ENV
# Written by deploy/brev/up.sh: Nemotron on a Brev GPU via the SSH tunnel, hosted API fallback.
LLM_BASE_URL=http://127.0.0.1:8100/v1
LLM_API_KEY=brev-local
LLM_MODEL=$MODEL
LLM_FALLBACK_BASE_URL=https://integrate.api.nvidia.com/v1
LLM_FALLBACK_API_KEY=$KEY
LLM_FALLBACK_MODEL=$MODEL
ENV
chown zeroday:zeroday .env.local && chmod 600 .env.local
systemctl restart zeroday-backend
sleep 3; curl -s http://127.0.0.1:8000/api/health; echo
REMOTE
echo "==> Done. Stop paying with: deploy/brev/down.sh $VULTR $INSTANCE"
