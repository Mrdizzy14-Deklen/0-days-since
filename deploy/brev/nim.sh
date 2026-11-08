#!/usr/bin/env bash
# Runs ON the Brev GPU instance (copied there by deploy/brev/up.sh). Two subcommands:
#
#   bash nim.sh tunnel-key            create (once) and print the tunnel's public key
#   VULTR_IP=1.2.3.4 bash nim.sh start   (NGC_API_KEY on stdin) start Nemotron + the tunnel
#
# The NIM listens on 127.0.0.1:8000 only: nothing is exposed to the internet. A systemd service
# keeps an outbound SSH tunnel open to the Vultr server, which sees the model at 127.0.0.1:8100.
set -euo pipefail

IMAGE="nvcr.io/nim/nvidia/nemotron-3.5-super-vl-120b-a12b:2.0.13-variant-build.1"
KEY="$HOME/.ssh/nim_tunnel"
CACHE="$HOME/workspace/nim-cache"  # ~/workspace survives `brev stop`: no re-download
REMOTE_PORT=8100

tunnel_key() {
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "zeroday-nim-tunnel" -f "$KEY"
  cat "$KEY.pub"
}

pick_profile() {
  # Prefer the GPU-specific NVFP4 profile that is NOT agentX (agentX wants 200 GiB host RAM/GPU).
  local gpu count
  gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1 | tr '[:upper:]' '[:lower:]' |
    grep -oE 'gb300|gb200|b300|b200|h200|h100|a100|rtx pro 6000' | head -1 | tr ' ' '-')
  count=$(nvidia-smi -L | wc -l | tr -d ' ')
  echo "GPU: ${gpu:-unknown} x${count}" >&2
  docker run --rm --gpus=all -e NGC_API_KEY "$IMAGE" list-model-profiles > "$HOME/nim-profiles.txt" 2>&1 || true
  grep -oE 'vllm-[a-z0-9._-]+' "$HOME/nim-profiles.txt" | sort -u |
    grep -i -- "-${gpu}-" | grep -i nvfp4 | grep -i "tp${count}-" | grep -vi agentx | head -1
}

start() {
  read -r NGC_API_KEY
  export NGC_API_KEY
  : "${VULTR_IP:?set VULTR_IP}"
  command -v nvidia-smi >/dev/null || { echo "No NVIDIA driver: create the instance in VM mode."; exit 1; }
  docker info >/dev/null 2>&1 || { echo "Docker is not available on this instance."; exit 1; }

  echo "==> Logging in to nvcr.io"
  echo "$NGC_API_KEY" | docker login nvcr.io -u '$oauthtoken' --password-stdin >/dev/null

  echo "==> Pulling the Nemotron NIM image (first time: several minutes)"
  docker pull -q "$IMAGE" >/dev/null

  PROFILE="${NIM_MODEL_PROFILE:-$(pick_profile)}"
  if [ -z "$PROFILE" ]; then
    echo "No matching NVFP4 profile for this GPU. Available profiles:"; cat "$HOME/nim-profiles.txt"
    echo "Re-run with NIM_MODEL_PROFILE=<one of the ids above>, or use 1x H200 / 2x H100."
    exit 1
  fi
  echo "==> Profile: $PROFILE"

  mkdir -p "$CACHE" && sudo chgrp -R 0 "$CACHE" && sudo chmod -R g+rwX "$CACHE"
  docker rm -f nim >/dev/null 2>&1 || true
  docker run -d --name nim --restart unless-stopped --gpus=all --shm-size=16g \
    -e NGC_API_KEY -e NIM_MODEL_PROFILE="$PROFILE" \
    -v "$CACHE:/opt/nim/.cache" -p 127.0.0.1:8000:8000 "$IMAGE" >/dev/null

  echo "==> Tunnel service -> $VULTR_IP:$REMOTE_PORT"
  tunnel_key >/dev/null
  sudo tee /etc/systemd/system/nim-tunnel.service >/dev/null <<UNIT
[Unit]
Description=Reverse SSH tunnel: Vultr 127.0.0.1:${REMOTE_PORT} -> local Nemotron NIM
After=network-online.target docker.service

[Service]
User=$(id -un)
ExecStart=/usr/bin/ssh -N -i ${KEY} -o ExitOnForwardFailure=yes -o ServerAliveInterval=20 \
  -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new \
  -R 127.0.0.1:${REMOTE_PORT}:127.0.0.1:8000 nimtunnel@${VULTR_IP}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload && sudo systemctl enable --now nim-tunnel >/dev/null 2>&1
  sudo systemctl restart nim-tunnel

  echo "==> Waiting for the model to load (downloads ~80 GB the first time; up to 60 min)"
  for i in $(seq 1 360); do
    if curl -fsS http://127.0.0.1:8000/v1/health/ready >/dev/null 2>&1; then
      echo "==> Nemotron is ready"; curl -s http://127.0.0.1:8000/v1/models; echo; return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx nim; then
      echo "The NIM container stopped:"; docker logs --tail 40 nim; exit 1
    fi
    [ $((i % 6)) -eq 0 ] && echo "   ... $((i / 6)) min: $(docker logs --tail 1 nim 2>&1 | cut -c1-110)"
    sleep 10
  done
  echo "Still loading after 60 min; check: docker logs -f nim"; exit 1
}

case "${1:-}" in
  tunnel-key) tunnel_key ;;
  start) start ;;
  *) echo "usage: bash nim.sh tunnel-key | start"; exit 2 ;;
esac
