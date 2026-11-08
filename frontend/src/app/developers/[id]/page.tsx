import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Award, Bug, Flame, Lightbulb, ShieldCheck, Sparkles, Target } from "lucide-react";

import { DevAvatar } from "@/components/dev-avatar";
import { HistoryChart } from "@/components/history-chart";
import { PushRow } from "@/components/push-row";
import { RelativeTime } from "@/components/relative-time";
import { ScoreBar } from "@/components/score-bar";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { getJson } from "@/lib/backend";
import {
  CRAFT_COLOR,
  CRAFT_WARN_THRESHOLD,
  MAX_CRAFT,
  MAX_SECURITY,
  SECURITY_COLOR,
  cweName,
  pct,
} from "@/lib/format";
import { achievements, focusArea } from "@/lib/insights";
import type { DeveloperDetail, Leaderboard } from "@/lib/types";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ id: string }> };

async function load(id: string) {
  if (!/^\d+$/.test(id)) return null;
  return getJson<DeveloperDetail>(`developers/${id}?days=90`);
}

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const data = await load((await params).id).catch(() => null);
  return { title: data ? `@${data.developer.github_login}` : "Developer" };
}

function CountList({
  counts,
  label,
  empty,
}: {
  counts: Record<string, number>;
  label?: (k: string) => string | null;
  empty: React.ReactNode;
}) {
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  if (rows.length === 0) return <div className="text-sm text-muted-foreground">{empty}</div>;
  return (
    <ul className="space-y-3">
      {rows.map(([k, n]) => (
        <li key={k}>
          <div className="flex items-baseline justify-between gap-2 text-sm">
            <span className="truncate">
              {label?.(k) ?? k}
              {label?.(k) && <span className="ml-1.5 font-mono text-xs text-muted-foreground">{k}</span>}
            </span>
            <span className="font-mono text-xs tabular-nums text-muted-foreground">
              {n} {n === 1 ? "time" : "times"}
            </span>
          </div>
          <div className="mt-1 h-1.5 rounded-full bg-muted">
            <div className="h-full rounded-full bg-foreground/50" style={{ width: `${(n / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export default async function DeveloperPage({ params }: Params) {
  const data = await load((await params).id);
  if (!data) notFound();
  const { developer: d, team } = data;
  const board = team ? await getJson<Leaderboard>(`teams/${encodeURIComponent(team.slug)}/leaderboard`).catch(() => null) : null;
  const ranked = board?.developers.find((x) => x.id === d.id);
  const teamSize = board?.developers.length ?? null;
  const now = Date.now();
  const focus = focusArea(d);
  const badges = achievements(d);

  return (
    <>
      <SiteHeader team={team} section="overview" />
      <PageShell>
        {team && (
          <Link
            href={`/teams/${team.slug}`}
            className="mb-5 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" aria-hidden /> Leaderboard
          </Link>
        )}

        <header className="card-surface flex flex-col gap-6 p-5 sm:p-6 md:flex-row md:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-4">
            <DevAvatar login={d.github_login} src={d.avatar_url} className="size-16 ring-2 ring-brand/40" />
            <div className="min-w-0">
              <h1 className="truncate text-2xl font-semibold tracking-tight">{d.display_name}</h1>
              <p className="text-sm text-muted-foreground">
                @{d.github_login}
                {d.last_push_at && (
                  <>
                    {" "}· last push <RelativeTime iso={d.last_push_at} />
                  </>
                )}
              </p>
              {badges.length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Achievements">
                  {badges.map((b) => (
                    <li
                      key={b.id}
                      title={b.detail}
                      className="inline-flex items-center gap-1 rounded-full border bg-brand-soft px-2 py-0.5 text-xs"
                    >
                      <Award className="size-3 text-brand" aria-hidden /> {b.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <div className="flex items-center gap-8 border-t pt-5 md:border-l md:border-t-0 md:pl-8 md:pt-0">
            {ranked?.rank && (
              <div>
                <div className="text-xs text-muted-foreground">Rank</div>
                <div className="font-mono text-3xl font-semibold">
                  #{ranked.rank}
                  {teamSize && <span className="text-base text-muted-foreground"> of {teamSize}</span>}
                </div>
              </div>
            )}
            <div>
              <div className="text-xs text-muted-foreground">Score</div>
              <div className="font-mono text-3xl font-semibold tabular-nums">
                {d.composite_score}
                <span className="text-base text-muted-foreground">/1000</span>
              </div>
            </div>
          </div>
        </header>

        <section
          className={cn(
            "card-surface mt-4 flex gap-4 p-5",
            focus.kind === "security" && "border-critical/30",
            focus.kind === "none" && "border-good/30",
          )}
          aria-label="Focus area"
        >
          <span
            className={cn(
              "grid size-10 shrink-0 place-items-center rounded-full",
              focus.kind === "security" ? "bg-critical/12 text-critical" : focus.kind === "craft" ? "bg-brand-soft text-brand" : "bg-good/12 text-good",
            )}
          >
            {focus.kind === "none" ? <ShieldCheck className="size-5" aria-hidden /> : <Target className="size-5" aria-hidden />}
          </span>
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Focus area</div>
            <p className="font-medium">{focus.title}</p>
            <p className="mt-1 flex gap-1.5 text-sm text-muted-foreground">
              <Lightbulb className="mt-0.5 size-4 shrink-0" aria-hidden /> {focus.tip}
            </p>
          </div>
        </section>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <section className="card-surface space-y-5 p-5" aria-labelledby="breakdown-title">
            <h2 id="breakdown-title" className="font-semibold">
              Score breakdown
            </h2>
            <ScoreBar label="Security" value={d.security_score} max={MAX_SECURITY} color={SECURITY_COLOR} />
            <ScoreBar
              label="Code craft"
              value={d.craft_score}
              max={MAX_CRAFT}
              color={CRAFT_COLOR}
              threshold={CRAFT_WARN_THRESHOLD}
            />
            <div className="grid grid-cols-3 gap-3 border-t pt-4">
              <ScoreBar label="Docs" value={d.craft_breakdown.docs} max={100} color={CRAFT_COLOR} compact />
              <ScoreBar label="Readability" value={d.craft_breakdown.readability} max={100} color={CRAFT_COLOR} compact />
              <ScoreBar label="Type hints" value={d.craft_breakdown.type_hints} max={100} color={CRAFT_COLOR} compact />
            </div>
            <dl className="grid grid-cols-3 gap-3 border-t pt-4 text-sm">
              <div>
                <dt className="text-xs text-muted-foreground">Pushes</dt>
                <dd className="font-mono text-lg tabular-nums">{d.total_pushes}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">With vulns</dt>
                <dd className="font-mono text-lg tabular-nums">
                  {d.faulty_pushes}
                  <span className="ml-1 text-xs text-muted-foreground">{pct(d.fault_ratio)}</span>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Clean streak</dt>
                <dd className="flex items-center gap-1 font-mono text-lg tabular-nums">
                  <Flame className="size-4 fill-orange-500/25 text-orange-500" aria-hidden />
                  {d.clean_streak}
                </dd>
              </div>
            </dl>
          </section>
          <section className="card-surface p-5 lg:col-span-2" aria-labelledby="history-title">
            <h2 id="history-title" className="mb-1 font-semibold">
              Score history
            </h2>
            <p className="mb-3 text-sm text-muted-foreground">Security and craft stack up to the total score.</p>
            <HistoryChart history={data.history} now={now} />
          </section>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
          <section className="card-surface p-5" aria-labelledby="cwe-title">
            <h2 id="cwe-title" className="mb-4 flex items-center gap-2 font-semibold">
              <Bug className="size-4 text-muted-foreground" aria-hidden /> Confirmed vulnerabilities
            </h2>
            <CountList counts={d.cwe_counts} label={cweName} empty="None confirmed. Keep it up." />
          </section>
          <section className="card-surface p-5" aria-labelledby="smell-title">
            <h2 id="smell-title" className="mb-4 flex items-center gap-2 font-semibold">
              <Sparkles className="size-4 text-muted-foreground" aria-hidden /> Code smells
            </h2>
            <CountList counts={d.smell_counts} empty="No recurring smells." />
          </section>
        </div>

        <section className="mt-8" aria-labelledby="recent-title">
          <SectionHeader id="recent-title" title="Recent pushes" description="Open any push for the full review." />
          {data.recent_pushes.length === 0 ? (
            <div className="card-surface px-4 py-10 text-center text-sm text-muted-foreground">No pushes yet.</div>
          ) : (
            <ul className="card-surface divide-y divide-border/60 overflow-hidden">
              {data.recent_pushes.map((p) => (
                <PushRow key={p.id} push={p} showAuthor={false} />
              ))}
            </ul>
          )}
        </section>
      </PageShell>
    </>
  );
}
