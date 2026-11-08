#!/usr/bin/env bash
# Run from your laptop: copy the project (including backend/.env and certs, never via git)
# to the server over SSH, then run setup.sh there.   Usage: deploy/push.sh <server-ip>
set -euo pipefail
HOST="${1:?usage: deploy/push.sh <server-ip>}"
cd "$(dirname "$0")/.."
[ -f backend/.env ] || { echo "backend/.env is missing"; exit 1; }
rsync -az --delete \
  --exclude '.git/' --exclude 'node_modules/' --exclude '.next/' --exclude '.next-dev/' \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  --exclude '*.db' --exclude '.DS_Store' --exclude 'frontend/.env.production.local' \
  ./ "root@${HOST}:/opt/zeroday/"
ssh "root@${HOST}" "DOMAIN=zero-days-since.work GITHUB_APP_SLUG='${GITHUB_APP_SLUG:-}' bash /opt/zeroday/deploy/setup.sh"
