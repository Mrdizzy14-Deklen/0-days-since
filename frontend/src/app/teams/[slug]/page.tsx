import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Bug, FolderGit2 } from "lucide-react";

import { CweBadge, Leaderboard } from "@/components/leaderboard";
import { PushFeed } from "@/components/push-feed";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { StatTiles } from "@/components/stat-tiles";
import { TrendChart } from "@/components/trend-chart";
import { WelcomeCard } from "@/components/welcome-card";
import { getJson } from "@/lib/backend";
import { CWE_TIPS, rankMovement } from "@/lib/insights";
import type { Leaderboard as LeaderboardData, Push, TeamStats, Trends } from "@/lib/types";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const { slug } = await params;
  return { title: slug };
}

export default async function TeamPage({ params }: Params) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, stats, pushes, trends, viewer] = await Promise.all([
    getJson<LeaderboardData>(`teams/${s}/leaderboard`),
    getJson<TeamStats>(`teams/${s}/stats`),
    getJson<Push[]>(`teams/${s}/pushes?limit=30`),
    getJson<Trends>(`teams/${s}/trends?days=30`),
    getViewer(),
  ]);
  if (!board || !stats || !pushes || !trends) notFound();
  const now = Date.now();
  const movement = rankMovement(board.developers, trends.series, now);
  const you = board.developers.find((d) => d.github_login === viewer.login);

  return (
    <>
      <SiteHeader team={board.team} section="overview" />
      <PageShell>
        <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{board.team.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Who&apos;s shipping the safest, cleanest Python. Scores update live with every push.
            </p>
          </div>
          {you && (
            <div className="card-surface flex items-center gap-3 px-4 py-2.5 text-sm">
              <span className="text-muted-foreground">Your rank</span>
              <span className="font-mono text-lg font-semibold">#{you.rank}</span>
              <span className="text-muted-foreground">·</span>
              <span className="font-mono font-semibold">{you.composite_score}</span>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <WelcomeCard />
          <StatTiles stats={stats} developers={board.developers} />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_380px]">
            <div className="min-w-0 space-y-8">
              <section aria-labelledby="board-title">
                <SectionHeader
                  id="board-title"
                  title="Leaderboard"
                  description="Score out of 1,000: Security (700) + Code craft (300). Click anyone for their breakdown."
                />
                <Leaderboard developers={board.developers} movement={movement} viewerLogin={viewer.login} />
              </section>

              <section aria-labelledby="trend-title">
                <SectionHeader
                  id="trend-title"
                  title="Score over time"
                  description="Each step is a push. Click a name to highlight one developer."
                />
                <div className="card-surface p-4 sm:p-5">
                  <TrendChart series={trends.series} developers={board.developers} now={now} />
                </div>
              </section>
            </div>

            <aside className="min-w-0 space-y-6 lg:sticky lg:top-20 lg:self-start">
              <PushFeed slug={slug} initial={pushes} variant="compact" />

              <section className="card-surface p-4" aria-labelledby="weak-title">
                <h2 id="weak-title" className="flex items-center gap-2 font-semibold">
                  <Bug className="size-4 text-muted-foreground" aria-hidden /> Team&apos;s top weaknesses
                </h2>
                {stats.top_cwes.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">No confirmed vulnerabilities yet.</p>
                ) : (
                  <ul className="mt-3 space-y-3">
                    {stats.top_cwes.slice(0, 4).map((c) => (
                      <li key={c.cwe} className="space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <CweBadge cwe={c.cwe} />
                          <span className="text-xs text-muted-foreground">
                            {c.count} {c.count === 1 ? "push" : "pushes"}
                          </span>
                        </div>
                        {CWE_TIPS[c.cwe] && <p className="text-xs text-muted-foreground">{CWE_TIPS[c.cwe]}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {stats.repositories.length > 0 && (
                <section className="card-surface p-4" aria-labelledby="repo-title">
                  <h2 id="repo-title" className="flex items-center gap-2 font-semibold">
                    <FolderGit2 className="size-4 text-muted-foreground" aria-hidden /> Connected repositories
                  </h2>
                  <ul className="mt-3 space-y-2 text-sm">
                    {stats.repositories.map((r) => (
                      <li key={r.id}>
                        <div className="truncate font-mono text-xs">{r.full_name}</div>
                        <div className="text-xs text-muted-foreground">
                          {r.files} Python files · {r.symbols} functions and classes mapped
                        </div>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </aside>
          </div>
        </div>
      </PageShell>
    </>
  );
}
