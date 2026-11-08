# 0 Days Since — Dashboard

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
| `/teams/[slug]` | **Overview**: the repo name, the "days since last incident" board, the leaderboard (podium + ranked rows: composite, Security /700 and Craft /300 bars, pushes vs. faulty, streak, 7-day rank change, most frequent CWE / code smell) and the live feed of latest pushes |
| `/teams/[slug]/pushes` | **Pushes**: every push with result and developer filters, search, grouped by day |
| `/teams/[slug]/settings` | **Settings** (gear icon): connect a Discord channel that is told about every faulty push (optionally warnings too); team members only |
| `/teams/[slug]/data` | **Data**: team averages, score over time (chart + table view), top weaknesses with fix tips, connected repositories |
| `/pushes/[id]` | The Check Run's *Details* link: one-sentence verdict, then **Review** (what to fix), **Impact map** (cross-file attack paths, affected files) and **Code craft** tabs |
| `/developers/[id]` | Player card: rank, achievements, focus-area tip, score breakdown and history, recent pushes |

The **?** button in the header opens the scoring guide. Hovering the **0** logo flips it to the
team's current days-since count.

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
