# ZeroDay Score — Backend

FastAPI + PostgreSQL (Tiger Data / TimescaleDB) security & code-craft engine.

## Layout

```
app/
  config.py      # env-driven settings (DB, GitHub App, LLM endpoints)
  enums.py       # shared enums (severity weights, statuses, kinds)
  models.py      # SQLModel tables (teams, repos, developers, pushes, findings, graph, snapshots)
  db.py          # async engine/session + init_db() (creates Timescale hypertable when available)
  ast_engine.py  # whole-project AST call graph, blast radius, static security & craft analysis
tests/
  test_ast_engine.py
```

## Setup

```bash
cd backend
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
cp .env.example .env
docker compose -f ../docker-compose.yml up -d db   # local TimescaleDB (or point DATABASE_URL at Tiger Data)
.venv/bin/pytest -q
```

## AST engine quick tour

```python
from app.ast_engine import ProjectGraph, changed_lines_from_patch

graph = ProjectGraph.from_sources({"app/db.py": "...", "app/routes.py": "..."})
changed = {"app/db.py": changed_lines_from_patch(patch_from_github_compare)}

radius  = graph.blast_radius(changed, hops=2)        # upstream callers / downstream sinks / taint paths
context = graph.slice_prompt_context(radius)         # numbered source for the LLM passes
introduced, pre_existing = graph.findings_for_change(changed)   # deterministic findings
candidates = graph.cross_file_candidates(radius)     # cross-file taint candidates for the verifier
quality = graph.quality_report(changed)              # docs / readability / type-hint scores (0-100 each)
```

Static rule ids: `PY-SEC-0xx` (security, CWE-tagged), `PY-SEC-100` (cross-file taint candidate),
`PY-QUAL-0xx` (readability/best practices).
