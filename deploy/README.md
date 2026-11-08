# Deploying to Vultr (zero-days-since.work)

One Ubuntu server runs everything behind Caddy (automatic HTTPS):

| URL | What | Internal |
|---|---|---|
| `https://zero-days-since.work` | Dashboard (Next.js) | `127.0.0.1:3000` |
| `https://api.zero-days-since.work/api/webhooks/github` | GitHub App webhook | `127.0.0.1:8000` |

Only the webhook and `/api/health` are public on `api.`; the dashboard API is reachable only
from the Next.js server. The database stays on Tiger Cloud; Nemotron stays on NVIDIA's API.

## 1. Create the server (Vultr)

Cloud Compute, **Ubuntu 24.04**, **2 vCPU / 4 GB**, region Dallas. Add your SSH key.

## 2. DNS (wherever zero-days-since.work is registered)

| Type | Name | Value |
|---|---|---|
| A | `@` | server IP |
| A | `www` | server IP |
| A | `api` | server IP |

## 3. Deploy (from your laptop, repo root)

```bash
deploy/push.sh <server-ip>
```

This copies the project **including `backend/.env` and `backend/certs/`** over SSH (they are
never committed), installs Caddy, Node 22, pnpm, uv and Python 3.12, builds everything, and
starts two systemd services plus Caddy. Run it again after any change to redeploy.

Check: `https://zero-days-since.work/play` and `https://api.zero-days-since.work/api/health`.

## 4. GitHub App

| Setting | Value |
|---|---|
| Homepage URL | `https://zero-days-since.work` |
| Webhook URL | `https://api.zero-days-since.work/api/webhooks/github` |
| Webhook secret | `openssl rand -hex 32` |
| Permissions | Checks, Contents, Pull requests: Read & write · Metadata: Read |
| Events | Push, Pull request |

Then put the private key at `backend/certs/github-app.pem` and add to `backend/.env`:

```
GITHUB_APP_ID=...
GITHUB_APP_SLUG=...
GITHUB_APP_PRIVATE_KEY_PATH=certs/github-app.pem
GITHUB_WEBHOOK_SECRET=...
AGENT_OPEN_FIX_PRS=true
```

and redeploy with `GITHUB_APP_SLUG=<slug> deploy/push.sh <server-ip>` (the slug is baked into
the dashboard's "Install" button at build time).

## Operating

```bash
ssh root@<ip> journalctl -u zeroday-backend -f     # backend logs
ssh root@<ip> journalctl -u zeroday-frontend -f    # dashboard logs
ssh root@<ip> systemctl restart zeroday-backend zeroday-frontend
```
