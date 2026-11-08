import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { IncidentSign } from "@/components/incident-sign";
import { TeamShareButton } from "@/components/share-button";
import { Leaderboard } from "@/components/leaderboard";
import { PushFeed } from "@/components/push-feed";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { getJson } from "@/lib/backend";
import { toSharePush } from "@/lib/share";
import { incidentStats, pageTitle, rankMovement } from "@/lib/insights";
import type { Leaderboard as LeaderboardData, Push, TeamStats, Trends } from "@/lib/types";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ slug: string }> };

/** Stagger slot for the page-load reveal. */
const slot = (i: number) => ({ "--i": i }) as React.CSSProperties;

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const { slug } = await params;
  const stats = await getJson<TeamStats>(`teams/${encodeURIComponent(slug)}/stats`).catch(() => null);
  return { title: pageTitle(stats, slug) };
}

export default async function TeamPage({ params }: Params) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, stats, pushes, trends, viewer] = await Promise.all([
    getJson<LeaderboardData>(`teams/${s}/leaderboard`),
    getJson<TeamStats>(`teams/${s}/stats`),
    getJson<Push[]>(`teams/${s}/pushes?limit=200`),
    getJson<Trends>(`teams/${s}/trends?days=30`),
    getViewer(),
  ]);
  if (!board || !stats || !pushes || !trends) notFound();
  const now = Date.now();
  const incidents = incidentStats(pushes, now);
  const title = pageTitle(stats, board.team.name);

  return (
    <>
      <SiteHeader team={board.team} section="overview" />
      <PageShell>
        <div className="reveal space-y-10">
          <div className="grid grid-cols-1 items-center gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)]" style={slot(0)}>
            <div className="space-y-5">
              <h1 className="break-words font-display text-6xl font-black uppercase leading-[0.85] tracking-tight sm:text-7xl">
                {title}
              </h1>
              <TeamShareButton
                title={title}
                developers={board.developers}
                pushes={pushes.map(toSharePush)}
                daysSince={incidents?.days ?? null}
                record={incidents?.record ?? null}
              />
            </div>
            <IncidentSign stats={incidents} />
          </div>

          <div className="grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,1fr)_380px]" style={slot(1)}>
            <section className="min-w-0" aria-labelledby="board-title">
              <SectionHeader id="board-title" title="Leaderboard" />
              <Leaderboard
                developers={board.developers}
                movement={rankMovement(board.developers, trends.series, now)}
                viewerLogin={viewer.login}
              />
            </section>
            <aside className="min-w-0 lg:sticky lg:top-20 lg:self-start">
              <PushFeed slug={slug} initial={pushes.slice(0, 30)} variant="compact" />
            </aside>
          </div>
        </div>
      </PageShell>
    </>
  );
}
