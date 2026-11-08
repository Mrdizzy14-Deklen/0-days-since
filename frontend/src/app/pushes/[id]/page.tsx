import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ArrowLeft,
  Bot,
  CircleCheck,
  CircleSlash,
  ExternalLink,
  FileCode,
  GitBranch,
  Loader2,
  OctagonX,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";

import { RichText } from "@/components/rich-text";
import { AutoRefresh } from "@/components/auto-refresh";
import { AgentPanel } from "@/components/agent-panel";
import { BlastRadiusViewer } from "@/components/blast-radius/viewer";
import { DevAvatar } from "@/components/dev-avatar";
import { FixList, NonCountedFindings, QualityFindingList } from "@/components/findings";
import { PushTabs } from "@/components/push-tabs";
import { QualityPanel } from "@/components/quality-panel";
import { RelativeTime } from "@/components/relative-time";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { PointsDelta } from "@/components/status";
import { getJson } from "@/lib/backend";
import { modelLabel, type CheckState } from "@/lib/format";
import { pushVerdict } from "@/lib/insights";
import type { PushDetail } from "@/lib/types";
import { cn } from "@/lib/utils";

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

const VERDICT_STYLE: Record<CheckState, { icon: LucideIcon; tone: string; surface: string }> = {
  failed: { icon: OctagonX, tone: "bg-critical text-white", surface: "border-critical/40 bg-critical/[0.06]" },
  warned: { icon: TriangleAlert, tone: "bg-warning text-black", surface: "border-warning/40 bg-warning/[0.06]" },
  passed: { icon: CircleCheck, tone: "bg-good text-white", surface: "border-good/40 bg-good/[0.06]" },
  scanning: { icon: Loader2, tone: "bg-muted text-foreground", surface: "" },
  errored: { icon: CircleSlash, tone: "bg-muted text-foreground", surface: "" },
  skipped: { icon: CircleSlash, tone: "bg-muted text-foreground", surface: "" },
};

function ScoreMove({ label, before, after }: { label: string; before: number | null; after: number | null }) {
  if (after === null) return null;
  return (
    <div className="flex items-baseline justify-between gap-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="flex items-baseline gap-1.5 font-mono tabular-nums">
        <span className="text-muted-foreground">{before ?? "—"}</span>
        <span className="text-muted-foreground" aria-hidden>
          →
        </span>
        <span className="font-semibold">{after}</span>
      </span>
    </div>
  );
}

export default async function PushPage({ params }: Params) {
  const data = await load((await params).id);
  if (!data) notFound();
  const { push, team } = data;
  const verdict = pushVerdict(push, data.vulnerabilities);
  const style = VERDICT_STYLE[verdict.state];
  const counted = data.vulnerabilities.filter((f) => f.counted_in_score);
  const notCounted = data.vulnerabilities.filter((f) => !f.counted_in_score);
  const [subject, ...body] = (push.commit_message ?? "(no commit message)").split("\n");
  const login = push.developer?.github_login ?? "unknown";
  const scored = verdict.state === "passed" || verdict.state === "warned" || verdict.state === "failed";
  const graphSymbols = new Set((data.blast_radius.nodes ?? []).map((n) => n.id));
  const affected = data.incident_scope.length;

  return (
    <>
      <SiteHeader team={team} section="pushes" />
      <AutoRefresh active={verdict.state === "scanning"} />
      <PageShell>
        {team && (
          <Link
            href={`/teams/${team.slug}/pushes`}
            className="mb-5 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" aria-hidden /> All pushes
          </Link>
        )}

        <header>
          <div className="eyebrow mb-2">Push review · {push.short_sha}</div>
          <h1 className="font-display text-5xl font-black leading-[0.9] tracking-tight sm:text-6xl">{subject}</h1>
          {body.join("\n").trim() && (
            <p className="mt-1 whitespace-pre-line text-sm text-muted-foreground">{body.join("\n").trim()}</p>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm text-muted-foreground">
            {push.developer ? (
              <Link href={`/developers/${push.developer.id}`} className="inline-flex items-center gap-1.5 hover:text-foreground">
                <DevAvatar login={login} src={push.developer.avatar_url} className="size-5" />@{login}
              </Link>
            ) : (
              <span>@{login}</span>
            )}
            {push.repository && <span className="font-mono text-xs">{push.repository.full_name}</span>}
            <span className="inline-flex items-center gap-1">
              <GitBranch className="size-3.5" aria-hidden />
              {push.pr_number ? `PR #${push.pr_number}` : push.branch}
            </span>
            {push.commit_url ? (
              <a
                href={push.commit_url}
                className="inline-flex items-center gap-1 font-mono text-xs hover:text-foreground"
                target="_blank"
                rel="noreferrer"
              >
                {push.short_sha} <ExternalLink className="size-3" aria-hidden />
                <span className="sr-only">(view commit on GitHub)</span>
              </a>
            ) : (
              <span className="font-mono text-xs">{push.short_sha}</span>
            )}
            <span className="inline-flex items-center gap-1">
              <FileCode className="size-3.5" aria-hidden />
              {push.files_changed.length} {push.files_changed.length === 1 ? "file" : "files"}
              <span className="font-mono text-xs text-delta-up">+{push.additions}</span>
              <span className="font-mono text-xs text-delta-down">−{push.deletions}</span>
            </span>
            <RelativeTime iso={push.completed_at ?? push.created_at} />
          </div>
        </header>

        <section
          className={cn("plate mt-6 overflow-hidden", style.surface)}
          aria-label="Check result"
        >
          {verdict.state === "failed" && <div className="hazard-tape h-3 border-b-2 border-foreground" aria-hidden />}
          <div className="flex flex-col gap-5 p-5 md:flex-row md:items-center">
            <div className="flex min-w-0 flex-1 gap-4">
              <span className={cn("grid size-14 shrink-0 place-items-center rounded-[6px] border-2 border-foreground", style.tone)}>
                <style.icon className={cn("size-6", verdict.state === "scanning" && "animate-spin")} aria-hidden />
              </span>
              <div className="min-w-0">
                <div className="eyebrow mb-1">GitHub check</div>
                <h2 className="font-display text-4xl font-black uppercase leading-none">{verdict.title}</h2>
                <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{verdict.detail}</p>
              </div>
            </div>
            {scored && (
              <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border-t pt-4 md:shrink-0 md:flex-nowrap md:border-l md:border-t-0 md:pl-6 md:pt-0">
                <div>
                  <div className="text-xs text-muted-foreground">Points</div>
                  <PointsDelta value={push.points_delta} className="font-display text-5xl font-black" />
                </div>
                <div className="min-w-0 flex-1 space-y-1 md:min-w-44 md:flex-none">
                  <ScoreMove label="Total" before={push.composite_before} after={push.composite_after} />
                  <ScoreMove label="Security" before={push.security_before} after={push.security_after} />
                  <ScoreMove label="Craft" before={push.craft_before} after={push.craft_after} />
                </div>
              </div>
            )}
          </div>
          {push.ai_summary && (
            <div className="flex gap-3 border-t bg-card/60 px-5 py-4 text-sm">
              <Bot className="mt-0.5 size-4 shrink-0 text-brand-text" aria-hidden />
              <div>
                <span className="font-medium">What changed: </span>
                <span className="leading-relaxed text-muted-foreground"><RichText text={push.ai_summary} /></span>
                {modelLabel(push.llm_model) && (
                  <span className="ml-2 whitespace-nowrap rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                    {modelLabel(push.llm_model)}
                  </span>
                )}
              </div>
            </div>
          )}
        </section>

        <div className="mt-8">
          <PushTabs
            counts={{
              issues: counted.length,
              files: affected,
              craft: push.craft_push_score !== null ? Math.round(push.craft_push_score) : null,
              agentSteps: data.agent?.investigation?.steps.length ?? 0,
              fixes: data.agent?.fixes?.length ?? 0,
            }}
            agent={<AgentPanel agent={data.agent} />}
            review={
              <div className="space-y-8">
                <section aria-labelledby="fix-title">
                  <SectionHeader
                    id="fix-title"
                    title={counted.length ? "What to fix" : "Security review"}
                    description={
                      counted.length
                        ? "Confirmed issues that count against the score, most serious first."
                        : "The code map and both AI passes found nothing that counts against the score."
                    }
                  />
                  <FixList findings={counted} graphSymbols={graphSymbols} fixedTitles={new Set((data.agent?.fixes ?? []).map((f) => f.finding_title))} />
                </section>
                {notCounted.length > 0 && (
                  <section aria-labelledby="other-title">
                    <SectionHeader
                      id="other-title"
                      title="Also reviewed"
                      description="Possible issues that don't count against the score."
                    />
                    <NonCountedFindings findings={notCounted} />
                  </section>
                )}
              </div>
            }
            impact={
              <section aria-labelledby="impact-title">
                <SectionHeader
                  id="impact-title"
                  title="Impact map"
                  description="The code this push changed, plus everything up to two calls away. Red paths show how user input can reach a dangerous call."
                />
                <BlastRadiusViewer
                  radius={data.blast_radius}
                  vulnerabilities={data.vulnerabilities}
                  scope={data.incident_scope}
                />
              </section>
            }
            craft={
              <div className="space-y-8">
                <QualityPanel push={push} metrics={data.quality_metrics} />
                {data.quality_findings.length > 0 && (
                  <section aria-labelledby="notes-title">
                    <SectionHeader id="notes-title" title="Line-by-line notes" />
                    <QualityFindingList findings={data.quality_findings} />
                  </section>
                )}
              </div>
            }
          />
        </div>
      </PageShell>
    </>
  );
}
