import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Bot, ExternalLink, FileCode, GitBranch, TriangleAlert } from "lucide-react";

import { BlastRadiusViewer } from "@/components/blast-radius/viewer";
import { DevAvatar } from "@/components/dev-avatar";
import { QualityFindingList, VulnerabilityList } from "@/components/findings";
import { QualityPanel } from "@/components/quality-panel";
import { RelativeTime } from "@/components/relative-time";
import { PageShell, SiteHeader } from "@/components/site-header";
import { CheckBadge, PointsDelta } from "@/components/status";
import { getJson } from "@/lib/backend";
import { modelLabel, pushCheckState } from "@/lib/format";
import type { PushDetail } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ id: string }> };

async function load(id: string) {
  if (!/^\d+$/.test(id)) return null;
  return getJson<PushDetail>(`pushes/${id}`);
}

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const data = await load((await params).id).catch(() => null);
  return { title: data?.push.commit_message?.split("\n")[0] ?? "Push" };
}

function ScoreMove({ label, before, after }: { label: string; before: number | null; after: number | null }) {
  if (after === null) return null;
  return (
    <div className="rounded-lg border px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="flex items-baseline gap-2 font-mono tabular-nums">
        <span className="text-muted-foreground">{before ?? "—"}</span>
        <span className="text-muted-foreground" aria-hidden>
          →
        </span>
        <span className="text-lg font-semibold">{after}</span>
        {before !== null && <PointsDelta value={after - before} suffix="" className="text-xs" />}
      </div>
    </div>
  );
}

export default async function PushPage({ params }: Params) {
  const data = await load((await params).id);
  if (!data) notFound();
  const { push, team } = data;
  const state = pushCheckState(push);
  const counted = data.vulnerabilities.filter((f) => f.counted_in_score).length;
  const rejected = data.vulnerabilities.filter((f) => f.status === "rejected").length;
  const [subject, ...body] = (push.commit_message ?? "(no commit message)").split("\n");
  const login = push.developer?.github_login ?? "unknown";

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

        <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <CheckBadge state={state} />
              <span className="text-sm text-muted-foreground">ZeroDay Score check</span>
            </div>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight">{subject}</h1>
            {body.join("\n").trim() && (
              <p className="mt-1 whitespace-pre-line text-sm text-muted-foreground">{body.join("\n").trim()}</p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
              {push.developer ? (
                <Link href={`/developers/${push.developer.id}`} className="inline-flex items-center gap-1.5 hover:text-foreground">
                  <DevAvatar login={login} src={push.developer.avatar_url} className="size-5" />@{login}
                </Link>
              ) : (
                <span>@{login}</span>
              )}
              {push.repository && <span>{push.repository.full_name}</span>}
              <span className="inline-flex items-center gap-1">
                <GitBranch className="size-3.5" aria-hidden />
                {push.pr_number ? `PR #${push.pr_number}` : push.branch}
              </span>
              {push.commit_url ? (
                <a href={push.commit_url} className="inline-flex items-center gap-1 font-mono hover:text-foreground" target="_blank" rel="noreferrer">
                  {push.short_sha} <ExternalLink className="size-3" aria-hidden />
                </a>
              ) : (
                <span className="font-mono">{push.short_sha}</span>
              )}
              <span className="inline-flex items-center gap-1">
                <FileCode className="size-3.5" aria-hidden />
                {push.files_changed.length} files · <span className="text-delta-up">+{push.additions}</span>{" "}
                <span className="text-delta-down">−{push.deletions}</span>
              </span>
              <RelativeTime iso={push.completed_at ?? push.created_at} />
            </div>
          </div>
          <div className="shrink-0 self-start rounded-xl border bg-card px-5 py-3 lg:text-right">
            <div className="text-xs text-muted-foreground">Points</div>
            <PointsDelta value={push.points_delta} className="text-3xl font-semibold" />
          </div>
        </header>

        <div className="mt-5 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <ScoreMove label="Composite" before={push.composite_before} after={push.composite_after} />
          <ScoreMove label="Security" before={push.security_before} after={push.security_after} />
          <ScoreMove label="Craft" before={push.craft_before} after={push.craft_after} />
        </div>

        {push.error && (
          <div className="mt-4 flex gap-2 rounded-xl border border-warning/50 bg-warning/10 p-4 text-sm">
            <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
            <div>
              <div className="font-medium">The scan didn&apos;t finish</div>
              <p className="text-muted-foreground">{push.error}</p>
            </div>
          </div>
        )}

        {push.ai_summary && (
          <section className="mt-4 rounded-xl border bg-card p-4">
            <div className="flex items-center gap-2 text-sm font-medium">
              <Bot className="size-4" aria-hidden /> AI summary
              {modelLabel(push.llm_model) && (
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] font-normal text-muted-foreground">
                  {modelLabel(push.llm_model)}
                </span>
              )}
            </div>
            <p className="mt-2 text-sm leading-relaxed">{push.ai_summary}</p>
          </section>
        )}

        <section className="mt-8" aria-labelledby="radius-title">
          <div className="mb-3">
            <h2 id="radius-title" className="text-lg font-semibold">
              Cross-file blast radius
            </h2>
            <p className="text-sm text-muted-foreground">
              Two hops of callers and callees around the code this push changed. Pick a flow to
              trace it from the entry point to the sink.
            </p>
          </div>
          <BlastRadiusViewer
            radius={data.blast_radius}
            vulnerabilities={data.vulnerabilities}
            scope={data.incident_scope}
          />
        </section>

        <section className="mt-8" aria-labelledby="vuln-title">
          <h2 id="vuln-title" className="text-lg font-semibold">
            Security findings
          </h2>
          <p className="mb-3 text-sm text-muted-foreground">
            {counted} counted in the score
            {rejected > 0 && ` · ${rejected} rejected as false positives by the skeptic pass`}
          </p>
          <VulnerabilityList findings={data.vulnerabilities} />
        </section>

        <section className="mt-8" aria-labelledby="craft-title">
          <h2 id="craft-title" className="mb-3 text-lg font-semibold">
            Code craft
          </h2>
          <QualityPanel push={push} metrics={data.quality_metrics} />
          {data.quality_findings.length > 0 && (
            <div className="mt-4">
              <h3 className="mb-2 text-sm font-medium">Readability &amp; best-practice notes</h3>
              <QualityFindingList findings={data.quality_findings} />
            </div>
          )}
        </section>
      </PageShell>
    </>
  );
}
