import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { FolderGit2 } from "lucide-react";

import { CweBadge } from "@/components/leaderboard";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { StatTiles } from "@/components/stat-tiles";
import { TrendChart } from "@/components/trend-chart";
import { getJson } from "@/lib/backend";
import { CWE_TIPS } from "@/lib/insights";
import type { Leaderboard, TeamStats, Trends } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ slug: string }> };

const slot = (i: number) => ({ "--i": i }) as React.CSSProperties;

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  return { title: `Data · ${(await params).slug}` };
}

/** Team-wide numbers: averages, score trends, recurring weaknesses and connected repos. */
export default async function TeamDataPage({ params }: Params) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, stats, trends] = await Promise.all([
    getJson<Leaderboard>(`teams/${s}/leaderboard`),
    getJson<TeamStats>(`teams/${s}/stats`),
    getJson<Trends>(`teams/${s}/trends?days=30`),
  ]);
  if (!board || !stats || !trends) notFound();
  const now = Date.now();

  return (
    <>
      <SiteHeader team={board.team} section="data" />
      <PageShell>
        <div className="reveal space-y-10">
          <h1 className="font-display text-6xl font-black uppercase leading-none tracking-tight" style={slot(0)}>
            Data
          </h1>

          <div style={slot(1)}>
            <StatTiles stats={stats} developers={board.developers} />
          </div>

          <section aria-labelledby="trend-title" style={slot(2)}>
            <SectionHeader id="trend-title" title="Score over time" />
            <div className="card-surface p-4 sm:p-5">
              <TrendChart series={trends.series} developers={board.developers} now={now} />
            </div>
          </section>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]" style={slot(3)}>
            <section aria-labelledby="weak-title">
              <SectionHeader id="weak-title" title="Top weaknesses" />
              <div className="card-surface p-4">
                {stats.top_cwes.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No confirmed vulnerabilities yet.</p>
                ) : (
                  <ul className="divide-y divide-border/60">
                    {stats.top_cwes.map((c) => (
                      <li key={c.cwe} className="space-y-1 py-3 first:pt-0 last:pb-0">
                        <div className="flex items-center justify-between gap-2">
                          <CweBadge cwe={c.cwe} />
                          <span className="font-mono text-[11px] text-muted-foreground">
                            {c.count} {c.count === 1 ? "push" : "pushes"}
                          </span>
                        </div>
                        {CWE_TIPS[c.cwe] && <p className="text-sm text-muted-foreground">{CWE_TIPS[c.cwe]}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            <section aria-labelledby="repo-title">
              <SectionHeader id="repo-title" title="Repositories" />
              <div className="card-surface p-4">
                {stats.repositories.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No repositories connected yet.</p>
                ) : (
                  <ul className="space-y-3 text-sm">
                    {stats.repositories.map((r) => (
                      <li key={r.id} className="flex gap-2.5">
                        <FolderGit2 className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
                        <div className="min-w-0">
                          <div className="truncate font-mono text-xs">{r.full_name}</div>
                          <div className="text-xs text-muted-foreground">
                            {r.files} Python files · {r.symbols} functions and classes · {r.edges} call links
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>
          </div>
        </div>
      </PageShell>
    </>
  );
}
