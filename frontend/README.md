# ZeroDay Score — Dashboard

Next.js 15 (App Router) · TypeScript · Tailwind v4 · shadcn/ui · Recharts · Lucide · Auth.js
(GitHub OAuth).

## Run

```bash
cd frontend
pnpm install
cp .env.example .env.local     # fill in as needed
pnpm dev                       # http://localhost:3000
```

With the backend running and the demo team seeded (`backend/seed_demo.py`), open
<http://localhost:3000>. Without `AUTH_GITHUB_ID`/`AUTH_GITHUB_SECRET` the dashboard runs in
**local demo mode** (no sign-in) against a backend started without `API_TOKEN`.

## Pages

| Route | What it shows |
|---|---|
| `/teams/[slug]` | Stat tiles, leaderboard (composite 0–1000 with Security /700 and Craft /300 bars, pushes vs. faulty, clean streak, most frequent CWE and code smell), score trend chart, live push feed |
| `/pushes/[id]` | Check result, score movement, AI summary, **cross-file blast-radius viewer** (entry → modified function → sink, selectable taint flows, incident scope of compromised modules), security findings with the skeptic's verdict, code-craft breakdown. This is the Check Run's *Details* link. |
| `/developers/[id]` | Profile: score history (security + craft stacked to the composite), craft sub-scores, CWE and smell counts, recent pushes |

## How it talks to the backend

Pages are server components that call the FastAPI API with
`Authorization: Bearer $ZERODAY_API_TOKEN` and `X-GitHub-Login: <signed-in login>`; the backend
enforces team membership. The browser never sees the token: client-side requests (live feed,
"load older pushes") go through `/api/backend/*`, a GET-only, allow-listed proxy that adds the
same headers and streams the SSE response through unchanged.

The live feed subscribes to `/api/teams/{slug}/stream`. New pushes and status changes update
the feed in place, raise an in-dashboard toast, and refresh the server-rendered leaderboard,
stats and trend chart. All notifications stay inside the dashboard.

## Notes

- `pnpm-workspace.yaml` sets `minimumReleaseAge` so only package versions public for 14+ days
  are installed.
- Chart colors use a fixed categorical order (validated for color-vision deficiency) assigned
  by developer id, so a developer keeps their color when rankings change. Every chart has a
  legend and the trend chart has a table view.
