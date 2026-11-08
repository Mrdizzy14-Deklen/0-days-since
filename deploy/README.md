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
| Callback URL (sign-in) | `https://zero-days-since.work/api/auth/callback/github` |
| Setup URL (optional) | `https://zero-days-since.work/` and tick "Redirect on update" |
| Webhook URL | `https://api.zero-days-since.work/api/webhooks/github` |
| Webhook secret | `openssl rand -hex 32` |
| Permissions | Checks, Contents, Pull requests: Read & write · Metadata: Read |
| Events | Push, Pull request, Repository (so a deleted repo deletes its page and data) |

Then put the private key at `backend/certs/github-app.pem` and add to `backend/.env`:

```
GITHUB_APP_ID=...
GITHUB_APP_SLUG=...
GITHUB_APP_PRIVATE_KEY_PATH=certs/github-app.pem
GITHUB_WEBHOOK_SECRET=...
AGENT_OPEN_FIX_PRS=true
# Sign in with GitHub: the App's "Client ID" and a "Client secret" you generate (General tab)
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
# The demo team stays viewable by anyone, signed in or not
PUBLIC_TEAMS=acme-fintech
```

and redeploy with `GITHUB_APP_SLUG=<slug> deploy/push.sh <server-ip>` (the slug is baked into
the dashboard's "Install" button at build time).

Signing in uses the GitHub App itself, so people see exactly the teams whose installation
GitHub says they can access (plus any team they have pushed to). `setup.sh` also generates the
shared API token between the dashboard and the backend, so the API is never open in production.

## 5. Block faulty commits from reaching main

GitHub never lets an app reject a `git push`; checks run on commits that already exist. To
stop a failing commit from landing, make the check required on your default branch:

Repo > **Settings > Rules > Rulesets > New branch ruleset**: target the default branch, enable
**Require a pull request before merging** and **Require status checks to pass**, and add the
**0 Days Since** check (it appears in the picker once it has run on the repo). A blocked push
(conclusion `failure`) can then not be merged; warnings (`neutral`) still can.

## Operating

```bash
ssh root@<ip> journalctl -u zeroday-backend -f     # backend logs
ssh root@<ip> journalctl -u zeroday-frontend -f    # dashboard logs
ssh root@<ip> systemctl restart zeroday-backend zeroday-frontend
```
