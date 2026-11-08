#!/usr/bin/env bash
# From your laptop: switch the backend back to NVIDIA's hosted API and stop the Brev instance.
#   deploy/brev/down.sh <vultr-ip> [brev-instance-name]
set -euo pipefail
VULTR="${1:?usage: deploy/brev/down.sh <vultr-ip> [brev-instance-name]}"
ssh "root@$VULTR" 'rm -f /opt/zeroday/backend/.env.local && systemctl restart zeroday-backend && echo "backend: hosted API"'
if [ -n "${2:-}" ]; then
  brev stop "$2" && echo "Brev instance $2 stopped (billing paused; the model stays cached on its disk)"
fi
