import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { Leaderboard } from "@/components/leaderboard";
import { PushFeed } from "@/components/push-feed";
import { PageShell, SiteHeader } from "@/components/site-header";
import { StatTiles } from "@/components/stat-tiles";
import { TrendChart } from "@/components/trend-chart";
import { getJson } from "@/lib/backend";
import type { Leaderboard as LeaderboardData, Push, TeamStats, Trends } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const { slug } = await params;
  return { title: slug };
}

export default async function TeamPage({ params }: Params) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, stats, pushes, trends] = await Promise.all([
    getJson<LeaderboardData>(`teams/${s}/leaderboard`),
    getJson<TeamStats>(`teams/${s}/stats`),
    getJson<Push[]>(`teams/${s}/pushes?limit=25`),
    getJson<Trends>(`teams/${s}/trends?days=30`),
  ]);
  if (!board || !stats || !pushes || !trends) notFound();
  const now = Date.now();

  return (
    <>
      <SiteHeader team={board.team} />
      <PageShell>
        <div className="mb-6 flex flex-wrap items-end justify-between gap-2">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{board.team.name}</h1>
            <p className="text-sm text-muted-foreground">
              Composite score out of 1,000: Security (700) and Code Craft (300), averaged over
              every scored push.
            </p>
          </div>
        </div>

        <StatTiles stats={stats} />

        <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_400px]">
          <div className="min-w-0 space-y-6">
            <section className="rounded-xl border bg-card p-4 sm:p-5" aria-labelledby="board-title">
              <h2 id="board-title" className="mb-3 font-semibold">
                Leaderboard
              </h2>
              <Leaderboard developers={board.developers} />
            </section>
            <section className="rounded-xl border bg-card p-4 sm:p-5" aria-labelledby="trend-title">
              <h2 id="trend-title" className="mb-3 font-semibold">
                Score trend
              </h2>
              <TrendChart series={trends.series} developers={board.developers} now={now} />
            </section>
          </div>
          <div className="min-w-0 lg:sticky lg:top-20 lg:self-start">
            <PushFeed slug={slug} initial={pushes} />
          </div>
        </div>
      </PageShell>
    </>
  );
}
