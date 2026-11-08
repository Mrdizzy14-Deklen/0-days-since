import {
  Bot,
  ChevronRight,
  CircleCheck,
  ExternalLink,
  FileCode,
  GitPullRequest,
  ListChecks,
  Network,
  Search,
  ShieldX,
  Sparkles,
  Workflow,
  type LucideIcon,
} from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { RichText } from "@/components/rich-text";
import { modelLabel } from "@/lib/format";
import type { AgentFix, AgentTrace, ScanTimings } from "@/lib/types";
import { cn } from "@/lib/utils";

const TOOL: Record<string, { label: string; icon: LucideIcon }> = {
  symbol: { label: "Looked up", icon: FileCode },
  read_code: { label: "Read code", icon: FileCode },
  callers: { label: "Found callers of", icon: Network },
  callees: { label: "Found callees of", icon: Network },
  trace: { label: "Traced attack paths through", icon: Workflow },
  search: { label: "Searched for", icon: Search },
  finish: { label: "Submitted report", icon: ListChecks },
};

function callLabel(action: string, args: Record<string, unknown>): string {
  if (action === "read_code") return `${args.file_path ?? "?"}:${args.start_line ?? "?"}-${args.end_line ?? "?"}`;
  if (action === "search") return `"${String(args.pattern ?? "")}"`;
  return String(args.name ?? "");
}

function Diff({ diff }: { diff: string }) {
  return (
    <pre className="overflow-x-auto rounded-md border bg-muted/40 py-2 font-mono text-[11px] leading-relaxed">
      {diff.split("\n").map((line, i) => (
        <div
          key={i}
          className={cn(
            "px-3",
            line.startsWith("+") && !line.startsWith("+++") && "bg-good/12 text-foreground",
            line.startsWith("-") && !line.startsWith("---") && "bg-critical/10 text-foreground",
            (line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++")) && "text-muted-foreground",
          )}
        >
          {line || " "}
        </div>
      ))}
    </pre>
  );
}

function FixCard({ fix }: { fix: AgentFix }) {
  return (
    <article className={cn("card-surface overflow-hidden", fix.verified ? "border-good/40" : "border-warning/40")}>
      <header className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        {fix.verified ? (
          <span className="inline-flex items-center gap-1 rounded-[3px] bg-good px-1.5 py-0.5 text-[11px] font-semibold text-white">
            <CircleCheck className="size-3.5" aria-hidden /> Verified fix
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-[3px] bg-warning px-1.5 py-0.5 text-[11px] font-semibold text-black">
            <ShieldX className="size-3.5" aria-hidden /> Not verified
          </span>
        )}
        <h4 className="card-title text-lg">{fix.commit_message || fix.finding_title}</h4>
        {fix.pr_url ? (
          <a
            href={fix.pr_url}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1.5 rounded-[4px] border-2 border-foreground bg-brand px-2.5 py-1 text-sm font-semibold text-brand-foreground"
          >
            <GitPullRequest className="size-4" aria-hidden /> Open PR #{fix.pr_number}
            <ExternalLink className="size-3" aria-hidden />
          </a>
        ) : (
          fix.verified && (
            <span className="ml-auto text-xs text-muted-foreground">
              Fix PRs are off for this repo. Copy the patch below.
            </span>
          )
        )}
      </header>
      <div className="space-y-3 p-4 text-sm">
        <p className="text-muted-foreground">
          Fixes <span className="font-medium text-foreground">{fix.cwe ?? fix.rule_id}</span>:{" "}
          <RichText text={fix.finding_title} />
        </p>
        {fix.explanation && (
          <p>
            <span className="font-medium">What it changes: </span>
            <RichText text={fix.explanation} />
          </p>
        )}
        <p className="flex gap-2">
          <ListChecks className={cn("mt-0.5 size-4 shrink-0", fix.verified ? "text-good" : "text-warning")} aria-hidden />
          <span>
            <span className="font-medium">How it was checked: </span>
            {fix.error ?? fix.verification}
          </span>
        </p>
        {fix.diff && (
          <div className="relative">
            <CopyButton value={fix.diff} label="Copy patch" className="absolute right-1.5 top-1.5 bg-card" />
            <Diff diff={fix.diff} />
          </div>
        )}
      </div>
    </article>
  );
}

function secs(ms: number | undefined) {
  return ms === undefined ? null : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
}

/** Where the scan's time went: agent and skeptic run side by side, then fixes. */
function Timings({ t }: { t: ScanTimings }) {
  const rows = [
    ["Agent investigation", t.agent_ms ?? t.one_shot_ms],
    ["Skeptic (in parallel)", t.skeptic_ms],
    ["Fixes + re-verification", t.fixes_ms],
  ] as const;
  const total = t.analysis_ms;
  return (
    <div className="card-surface p-4">
      <div className="eyebrow mb-2">Time taken</div>
      <dl className="space-y-1.5 text-sm">
        {rows.map(([label, ms]) =>
          ms === undefined ? null : (
            <div key={label} className="flex justify-between gap-3">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="font-mono tabular-nums">{secs(ms)}</dd>
            </div>
          ),
        )}
        {total !== undefined && (
          <div className="flex justify-between gap-3 border-t pt-1.5 font-medium">
            <dt>Total analysis</dt>
            <dd className="font-mono tabular-nums">{secs(total)}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

/** What the Nemotron agent did on this push: its plan, each tool call, and verified fixes. */
export function AgentPanel({ agent }: { agent: AgentTrace | undefined }) {
  const run = agent?.investigation;
  const fixes = agent?.fixes ?? [];
  const timings = agent?.timings;
  if (!run && fixes.length === 0) {
    return (
      <div className="card-surface p-6 text-sm text-muted-foreground">
        The agent didn&apos;t run on this push (no AI model was configured when it was scanned).
      </div>
    );
  }
  return (
    <div className="space-y-8">
      {run && (
        <section aria-labelledby="agent-run-title" className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,320px)_minmax(0,1fr)]">
          <div className="space-y-4">
            <div className="plate p-4">
              <div className="flex items-center gap-2">
                <span className="grid size-9 place-items-center rounded-[4px] border-2 border-foreground bg-brand text-brand-foreground">
                  <Bot className="size-5" aria-hidden />
                </span>
                <div>
                  <h3 id="agent-run-title" className="card-title">Security agent</h3>
                  <p className="font-mono text-[11px] text-muted-foreground">{modelLabel(run.model) ?? "model unknown"}</p>
                </div>
              </div>
              <p className="mt-3 text-sm text-muted-foreground">
                Instead of reading one big prompt, the agent plans, then investigates the
                code graph one tool call at a time and sees each real result before deciding
                what to check next.
              </p>
              {!run.finished && (
                <p className="mt-3 rounded-md border border-warning/50 bg-warning/10 p-2 text-xs">
                  The agent didn&apos;t finish ({run.error ?? "no report"}), so the one-shot review was used instead.
                </p>
              )}
            </div>
            {run.plan.length > 0 && (
              <div className="card-surface p-4">
                <div className="eyebrow mb-2">Plan</div>
                <ol className="space-y-2 text-sm">
                  {run.plan.map((p, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="font-display text-base font-black leading-5">{i + 1}</span>
                      <span>{p}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
            {timings && <Timings t={timings} />}
          </div>

          <ol className="relative space-y-3 before:absolute before:bottom-4 before:left-[15px] before:top-4 before:w-0.5 before:bg-border">
            {run.steps.map((s) => {
              const tool = TOOL[s.action] ?? { label: s.action, icon: Sparkles };
              const finish = s.action === "finish";
              return (
                <li key={s.step} className="relative flex gap-3">
                  <span
                    className={cn(
                      "z-10 grid size-8 shrink-0 place-items-center rounded-full border-2 border-foreground",
                      finish ? "bg-brand text-brand-foreground" : "bg-card",
                    )}
                  >
                    <tool.icon className="size-4" aria-hidden />
                  </span>
                  <div className="card-surface min-w-0 flex-1 p-3">
                    <div className="flex flex-wrap items-baseline gap-x-2">
                      <span className="eyebrow">Step {s.step}</span>
                      <span className="text-sm font-medium">{tool.label}</span>
                      {!finish && (
                        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">{callLabel(s.action, s.args)}</code>
                      )}
                      {s.ms !== undefined && (
                        <span className="ml-auto font-mono text-[11px] tabular-nums text-muted-foreground" title="Model time for this step">
                          {secs(s.ms)}
                        </span>
                      )}
                    </div>
                    {s.thought && <p className="mt-1 text-sm text-muted-foreground">{s.thought}</p>}
                    {!finish && s.observation && (
                      <details className="group mt-2">
                        <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                          What it found
                        </summary>
                        <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-[11px] leading-relaxed">
                          {s.observation}
                        </pre>
                      </details>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        </section>
      )}

      <section aria-labelledby="fixes-title">
        <div className="mb-3 flex items-end justify-between gap-2">
          <h3 id="fixes-title" className="font-display text-3xl font-extrabold uppercase leading-none">
            Auto-fixes
          </h3>
        </div>
        {fixes.length === 0 ? (
          <p className="card-surface p-4 text-sm text-muted-foreground">
            No confirmed vulnerabilities needed a fix on this push.
          </p>
        ) : (
          <div className="space-y-4">
            {fixes.map((f, i) => (
              <FixCard key={i} fix={f} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
