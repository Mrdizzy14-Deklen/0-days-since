import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Bug, Flame, Sparkles } from "lucide-react";

import { DevAvatar } from "@/components/dev-avatar";
import { HistoryChart } from "@/components/history-chart";
import { PushRow } from "@/components/push-row";
import { RelativeTime } from "@/components/relative-time";
import { ScoreBar } from "@/components/score-bar";
import { PageShell, SiteHeader } from "@/components/site-header";
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
import type { DeveloperDetail } from "@/lib/types";

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
  title,
  icon: Icon,
  counts,
  label,
  empty,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  counts: Record<string, number>;
  label?: (k: string) => string | null;
  empty: string;
}) {
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <div className="rounded-xl border bg-card p-4">
      <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold">
        <Icon className="size-4" /> {title}
      </h2>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="space-y-2">
          {rows.map(([k, n]) => (
            <li key={k}>
              <div className="flex items-baseline justify-between gap-2 text-sm">
                <span className="truncate">
                  <span className="font-mono">{k}</span>
                  {label?.(k) && <span className="text-muted-foreground"> · {label(k)}</span>}
                </span>
                <span className="font-mono tabular-nums">{n}</span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-muted">
                <div className="h-full rounded-full bg-foreground/60" style={{ width: `${(n / max) * 100}%` }} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default async function DeveloperPage({ params }: Params) {
  const data = await load((await params).id);
  if (!data) notFound();
  const { developer: d, team } = data;
  const now = Date.now();

  return (
    <>
      <SiteHeader team={team} />
      <PageShell>
        {team && (
          <Link
            href={`/teams/${team.slug}`}
            className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" aria-hidden /> {team.name} leaderboard
          </Link>
        )}
        <header className="flex flex-wrap items-center gap-4">
          <DevAvatar login={d.github_login} src={d.avatar_url} className="size-14" />
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-semibold tracking-tight">{d.display_name}</h1>
            <p className="text-sm text-muted-foreground">
              @{d.github_login} · last push <RelativeTime iso={d.last_push_at} />
            </p>
          </div>
          <div className="text-right">
            <div className="font-mono text-4xl font-semibold tabular-nums">{d.composite_score}</div>
            <div className="text-xs text-muted-foreground">composite / 1000</div>
          </div>
        </header>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="space-y-4 rounded-xl border bg-card p-4">
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
                <dd className="font-mono tabular-nums">{d.total_pushes}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Faulty</dt>
                <dd className="font-mono tabular-nums">
                  {d.faulty_pushes} <span className="text-xs text-muted-foreground">({pct(d.fault_ratio)})</span>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Clean streak</dt>
                <dd className="flex items-center gap-1 font-mono tabular-nums">
                  <Flame className="size-3.5 fill-orange-500/25 text-orange-500" aria-hidden />
                  {d.clean_streak}
                  <span className="text-xs text-muted-foreground">best {d.best_clean_streak}</span>
                </dd>
              </div>
            </dl>
          </div>
          <div className="rounded-xl border bg-card p-4 lg:col-span-2">
            <h2 className="mb-3 text-sm font-semibold">Score history</h2>
            <HistoryChart history={data.history} now={now} />
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
          <CountList
            title="Verified weaknesses"
            icon={Bug}
            counts={d.cwe_counts}
            label={cweName}
            empty="No verified vulnerabilities. Nice."
          />
          <CountList title="Code smells" icon={Sparkles} counts={d.smell_counts} empty="No recurring smells." />
        </div>

        <section className="mt-6 rounded-xl border bg-card" aria-labelledby="recent-title">
          <h2 id="recent-title" className="border-b px-4 py-3 font-semibold">
            Recent pushes
          </h2>
          {data.recent_pushes.length === 0 ? (
            <p className="px-4 py-8 text-center text-sm text-muted-foreground">No pushes yet.</p>
          ) : (
            <ul className="divide-y">
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
