# 0 Days Since

A GitHub App + dashboard that scans every push of a Python repository for whole-project,
cross-file vulnerabilities and code craft, then ranks developers on a 1,000-point leaderboard
(700 Security Reliability + 300 Code Craft & Readability). Critical or high findings fail the
GitHub Check, which blocks the merge.

Teams can connect a **Discord channel** (team page > gear icon > Discord alerts) by pasting a
channel webhook URL. Every faulty push is posted there: the commit and author, the days-since
counter it reset, the score change, what to fix (file:line) and any fix PR the agent opened.

```
backend/    FastAPI + PostgreSQL/Tiger Data scanning & scoring engine (Python 3.11+)
frontend/   Next.js 15 dashboard: leaderboard, live push feed, trends, blast-radius viewer
docker-compose.yml   local TimescaleDB
```

## Quick start (demo data, no GitHub App needed)

```bash
# backend
cd backend && uv venv --python 3.12 .venv && uv pip install -e ".[dev]"
export DATABASE_URL=sqlite+aiosqlite:///./zeroday_demo.db ENABLE_TIMESCALE=false
.venv/bin/python seed_demo.py --reset
.venv/bin/uvicorn app.main:app --port 8000

# frontend (another terminal)
cd frontend && pnpm install && pnpm dev
```

Open <http://localhost:3000>. For Postgres/Tiger Data, the GitHub App and OAuth, see
[backend/README.md](backend/README.md) and [frontend/README.md](frontend/README.md).
