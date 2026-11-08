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
| `/teams/[slug]` | Overview: first-visit explainer, team stats, top-3 podium and ranked list (composite 0–1000, Security /700 and Craft /300 bars, pushes vs. faulty, clean streak, rank change over 7 days, most frequent CWE / code smell with fix tips), score-over-time chart with table view, live feed, team's top weaknesses |
| `/teams/[slug]/pushes` | Every push with result filters, developer filter and search, grouped by day |
| `/pushes/[id]` | The Check Run's *Details* link. A verdict banner that says what happened in one sentence, then tabs: **Review** (what to fix, where, why and how; dismissed false alarms), **Impact map** (cross-file blast radius: entry point → changed function → dangerous call, selectable attack paths, affected files / incident scope), **Code craft** (sub-scores and quick wins). Auto-refreshes while a scan is running. |
| `/developers/[id]` | Rank, achievements, a focus-area tip, score breakdown and stacked history, confirmed vulnerabilities, code smells, recent pushes |

"How scoring works" in the header opens a plain-language guide on every page.

## How it talks to the backend

Pages are server components that call the FastAPI API with
`Authorization: Bearer $ZERODAY_API_TOKEN` and `X-GitHub-Login: <signed-in login>`; the backend
enforces team membership. The browser never sees the token: client-side requests (live feed,
"load older pushes") go through `/api/backend/*`, a GET-only, allow-listed proxy that adds the
same headers and streams the SSE response through unchanged.

The live feed subscribes to `/api/teams/{slug}/stream`. New pushes and status changes update
the feed in place, raise an in-dashboard toast, and refresh the server-rendered leaderboard,
stats and trend chart. All notifications stay inside the dashboard.

## Design

"Zero days since": workplace-safety signage meets a stadium scoreboard.

- **Paper** (light, default) and **Night shift** (dark) themes: warm enamel paper or graphite,
  ink-black type, one hi-vis lime accent that is never used for status or chart series.
- Type: Big Shoulders (signage condensed) for headings and scoreboard numerals, Big Shoulders
  Stencil for the incident sign, Atkinson Hyperlegible Next for body text, Martian Mono for code.
- Signature pieces: the "days since last incident" board, split-flap score tiles, enamel
  "plates" for the elements that matter most, hazard tape only on blocked merges.
- One staggered reveal on page load, bars that fill in, flipping digits. All motion is
  disabled under `prefers-reduced-motion`.

## Notes

- `pnpm-workspace.yaml` sets `minimumReleaseAge` so only package versions public for 14+ days
  are installed.
- Chart colors use a fixed categorical order (validated for color-vision deficiency) assigned
  by developer id, so a developer keeps their color when rankings change. Every chart has a
  legend and the trend chart has a table view.
