import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { FolderGit2 } from "lucide-react";

import { IncidentSign } from "@/components/incident-sign";
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

/** Stagger slot for the page-load reveal. */
const slot = (i: number) => ({ "--i": i }) as React.CSSProperties;

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
    getJson<Push[]>(`teams/${s}/pushes?limit=50`),
    getJson<Trends>(`teams/${s}/trends?days=30`),
    getViewer(),
  ]);
  if (!board || !stats || !pushes || !trends) notFound();
  const now = Date.now();
  const movement = rankMovement(board.developers, trends.series, now);
  const you = board.developers.find((d) => d.github_login === viewer.login);
  const repo = stats.repositories[0];

  return (
    <>
      <SiteHeader team={board.team} section="overview" />
      <PageShell>
        <div className="reveal space-y-8">
          <div className="grid grid-cols-1 items-end gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)]" style={slot(0)}>
            <div>
              <div className="eyebrow mb-2">
                Team scoreboard{repo ? ` · ${repo.full_name}` : ""}
              </div>
              <h1 className="font-display text-6xl font-black uppercase leading-[0.85] tracking-tight sm:text-7xl">
                {board.team.name}
              </h1>
              <p className="mt-4 max-w-xl text-base text-muted-foreground">
                Who&apos;s shipping the safest, cleanest Python. Every push is reviewed in about 30
                seconds and the board updates live.
              </p>
              {you && (
                <p className="mt-3 inline-flex items-center gap-2 rounded-[4px] border-2 border-foreground bg-brand px-3 py-1 font-display text-lg font-bold uppercase text-brand-foreground">
                  You&apos;re #{you.rank} · {you.composite_score} pts
                </p>
              )}
            </div>
            <IncidentSign pushes={pushes} now={now} />
          </div>

          <div style={slot(1)}>
            <WelcomeCard />
          </div>
          <div style={slot(2)}>
            <StatTiles stats={stats} developers={board.developers} />
          </div>

          <div className="grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,1fr)_380px]" style={slot(3)}>
            <div className="min-w-0 space-y-10">
              <section aria-labelledby="board-title">
                <SectionHeader
                  index="01"
                  id="board-title"
                  title="Leaderboard"
                  description="Out of 1,000: Security (700) + Code craft (300). Click anyone for their breakdown."
                />
                <Leaderboard developers={board.developers} movement={movement} viewerLogin={viewer.login} />
              </section>

              <section aria-labelledby="trend-title">
                <SectionHeader
                  index="02"
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
                <div className="eyebrow">Hazard log</div>
                <h2 id="weak-title" className="font-display text-2xl font-extrabold uppercase leading-tight">
                  Top weaknesses
                </h2>
                {stats.top_cwes.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">No confirmed vulnerabilities yet.</p>
                ) : (
                  <ul className="mt-3 space-y-3">
                    {stats.top_cwes.slice(0, 4).map((c) => (
                      <li key={c.cwe} className="space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <CweBadge cwe={c.cwe} />
                          <span className="font-mono text-[11px] text-muted-foreground">
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
                  <h2 id="repo-title" className="flex items-center gap-2 font-display text-xl font-extrabold uppercase">
                    <FolderGit2 className="size-4 text-muted-foreground" aria-hidden /> Connected repos
                  </h2>
                  <ul className="mt-2 space-y-2 text-sm">
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
