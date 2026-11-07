# ZeroDay Score

A GitHub App + dashboard that scans every push of a Python repository for whole-project,
cross-file vulnerabilities and code craft, then ranks developers on a 1,000-point leaderboard
(700 Security Reliability + 300 Code Craft & Readability). Critical or high findings fail the
GitHub Check, which blocks the merge.

```
backend/    FastAPI + PostgreSQL/Tiger Data scanning & scoring engine (Python 3.11+)
frontend/   Next.js 15 dashboard (Phase 4)
docker-compose.yml   local TimescaleDB
```

See [backend/README.md](backend/README.md) for setup.
