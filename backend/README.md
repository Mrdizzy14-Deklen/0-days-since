# ZeroDay Score — Backend

FastAPI + PostgreSQL (Tiger Data / TimescaleDB) security & code-craft engine.

## Layout

```
app/
  agent.py       # Nemotron agent: plan -> code-graph tool calls -> report
  fixer.py       # agent auto-fix: patch, re-scan to verify, open PR
  config.py      # env-driven settings (DB, GitHub App, LLM endpoints, limits)
  enums.py       # shared enums (severity weights, statuses, kinds)
  models.py      # SQLModel tables (teams, repos, developers, pushes, findings, graph, snapshots)
  db.py          # async engine/session + init_db() (creates Timescale hypertable when available)
  ast_engine.py  # whole-project AST call graph, blast radius, static security & craft analysis
  llm.py         # OpenAI-compatible client (NVIDIA NIM / Nemotron primary, Gemini/Claude fallback)
  ai_scanner.py  # Pass 1 cross-file analyzer + Pass 2 adversarial skeptic verifier
  scoring.py     # average-based security score, rolling craft score, check conclusion
  github_app.py  # webhook signatures, App JWT, installation tokens, Checks/compare/tree APIs
  pipeline.py    # webhook -> graph update -> AI scan -> scoring -> Check Run orchestration
  api.py         # dashboard REST + SSE live feed
  main.py        # FastAPI app (webhook receiver + API)
```

## Setup

```bash
cd backend
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
cp .env.example .env                                 # fill in GitHub App + LLM keys
docker compose -f ../docker-compose.yml up -d db     # or point DATABASE_URL at Tiger Data
.venv/bin/uvicorn app.main:app --reload --port 8000
.venv/bin/pytest -q
```

### Demo data

```bash
.venv/bin/python seed_demo.py            # creates team "acme-fintech" (24 pushes over 21 days)
.venv/bin/python seed_demo.py --reset    # wipe and recreate it
.venv/bin/python seed_demo.py --live-llm # same commits, analyzed by your configured LLM
```

The seed replays three weeks of commits to a sample FastAPI payments service through the
**real** pipeline. GitHub is simulated in-process, so no App or network is needed. By default
the two AI passes are answered from a script and labeled `demo-replay`. The story it tells:

| Developer | What happens |
|---|---|
| maya-chen, alex-kim | consistently clean, documented pushes; alex's path-traversal false positive is rejected by the skeptic (upstream `secure_filename`) |
| oscar-diaz | cross-file SQL injection (route → service → raw `execute`), fixed two days later; later an AI-only IDOR |
| priya-natarajan | shell injection behind an admin route, then `pickle.loads` on the request body (CRITICAL), both fixed |
| sam-okafor | cross-file SSRF through the webhook sender (confirmed, then fixed with an allow-list); a deeply nested refund helper drags craft below 180 |
| jordan-blake | hardcoded Stripe live key; later an `eval` endpoint with a comment telling the AI to ignore it, which is flagged as `ZD-AI-001`, and the manipulated verifier verdict is overridden |

### GitHub App settings

- **Webhook URL:** `https://<your-host>/api/webhooks/github` (use `smee.io`/`ngrok` locally)
- **Webhook secret:** same value as `GITHUB_WEBHOOK_SECRET` (unsigned deliveries are rejected)
- **Repository permissions:** Checks: *Read & write*; Contents: *Read*; Metadata: *Read*;
  Pull requests: *Read* (set Contents and Pull requests to *Read & write* to let the agent open
  fix PRs)
- **Subscribe to events:** Push, Pull request, (Installation events are always sent)

## Tiger Data (TimescaleDB)

With `ENABLE_TIMESCALE=true` on Postgres, `init_db()` sets up:

- `score_snapshots` as a **hypertable** on `recorded_at` (every push's score, per developer)
- `team_daily_scores`, a **continuous aggregate** (`time_bucket('1 day')` per team: pushes,
  pushes with confirmed vulnerabilities, net points, average/min/max score) with real-time
  aggregation and a refresh policy every 15 minutes; it powers `GET /api/teams/{slug}/daily`
  and the "Pushes per day" chart (on SQLite the API computes the same numbers itself)
- a **compression policy** for score history older than 90 days, segmented by team

Tiger Cloud signs server certificates with its own CA (`ca.timescale.com`). Save that CA
certificate and set `DATABASE_SSL_ROOT_CERT` to its path so TLS is fully verified (CA and
hostname); public CA bundles cannot verify it.

## Nemotron agent

Pass 1 is an agent, not a single prompt. Nemotron writes a plan, then investigates the push
with tools over the cross-file call graph (`symbol`, `read_code`, `callers`, `callees`,
`trace`, `search`), one call per turn, seeing each real result before choosing the next. It
finishes with a report in the Pass 1 schema, so the adversarial verifier (Pass 2) and all
guardrails still apply. If the agent fails or never reports, the one-shot review runs instead.

For each confirmed vulnerability the agent then proposes a minimal patch. The patch must
parse and is **re-scanned**: the static rule must stop firing, or untrusted input must no
longer reach the sink, or (for AI-only findings) an adversarial reviewer must agree it is
fixed. With `AGENT_OPEN_FIX_PRS=true` (and Contents + Pull requests set to *Read & write*),
verified fixes are pushed to a `zeroday/fix-<sha>-<n>` branch and opened as a pull request
linked from the check run. The plan, every tool call and each fix are shown on the push
page's **Agent** tab.

## How a push is scored

1. `push` webhook → check run created as `in_progress`.
2. Graph loaded (memory cache → `repo_files` table → full fetch on first scan);
   `compare/{before}...{after}` gives changed `.py` files + patches; only those are re-parsed.
3. Blast radius (2 hops), deterministic findings on changed lines, cross-file taint candidates,
   craft metrics for touched symbols.
4. AI Pass 1 proposes vulnerabilities and grades readability; Pass 2 tries to disprove every
   candidate. Only verified security findings count.
5. `security = round(700 · (1 − min(1, Σweights / total_pushes)))`; craft is the exact rolling
   average of per-push sub-scores (bounded ±10 AI adjustment each).
6. Check run completed: `failure` for verified CRITICAL/HIGH, `neutral` for MEDIUM/LOW or
   craft < 180/300, else `success`; annotations sent in batches of 50.

Guardrails: LLM output is validated against the real graph (unknown files dropped, lines
clamped); the verifier can move severity by at most one level; text in a push that addresses
the AI reviewer is flagged (`ZD-AI-001`) and disables verifier rejections of deterministic
findings; without an LLM, deterministic findings count and cross-file candidates are reported
unverified. Same-repo PRs are covered by their push (scans are deduplicated by commit SHA);
fork PRs are scanned from the `pull_request` event.

## Dashboard API

| Route | Purpose |
|---|---|
| `GET /api/teams` | teams visible to the caller |
| `GET /api/teams/{slug}/leaderboard` | ranked developers with security/craft/streak/badges |
| `GET /api/teams/{slug}/pushes?limit&before_id` | live feed page |
| `GET /api/teams/{slug}/stream` | SSE: new pushes and status changes |
| `GET /api/teams/{slug}/trends?days` | per-developer score time series |
| `GET /api/teams/{slug}/stats` | totals, blocked merges, top CWEs, repos |
| `GET /api/pushes/{id}` | findings, blast radius, incident scope |
| `GET /api/developers/{id}` | profile, score history, recent pushes |

Send `Authorization: Bearer $API_TOKEN` and `X-GitHub-Login: <login>` (membership enforced).

Static rule ids: `PY-SEC-0xx` (security, CWE-tagged), `PY-SEC-100` (cross-file taint candidate),
`PY-QUAL-0xx` (readability/best practices), `AI-*` (LLM findings), `ZD-AI-001` (reviewer
manipulation attempt).
