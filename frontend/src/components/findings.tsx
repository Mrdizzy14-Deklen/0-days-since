import { Bot, ChevronRight, Cpu, FileCode, Lightbulb, PartyPopper, ShieldCheck, ShieldQuestion } from "lucide-react";

import { RichText } from "@/components/rich-text";
import { CopyButton } from "@/components/copy-button";
import { ShowAttackPath } from "@/components/push-tabs";
import { SeverityBadge } from "@/components/status";
import { cweName } from "@/lib/format";
import type { Finding } from "@/lib/types";
import { cn } from "@/lib/utils";

function location(f: Finding): string {
  const lines = f.start_line
    ? f.end_line && f.end_line !== f.start_line
      ? `:${f.start_line}-${f.end_line}`
      : `:${f.start_line}`
    : "";
  return `${f.file_path}${lines}`;
}

function FileRef({ f }: { f: Finding }) {
  const loc = location(f);
  return (
    <span className="inline-flex min-w-0 items-center gap-1 rounded-md bg-muted px-2 py-0.5 font-mono text-xs">
      <FileCode className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
      <span className="truncate">{loc}</span>
      <CopyButton value={loc} label="Copy location" className="-mr-1 size-5" />
    </span>
  );
}

function SourceLabel({ f }: { f: Finding }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      {f.source === "ai" ? <Bot className="size-3.5" aria-hidden /> : <Cpu className="size-3.5" aria-hidden />}
      {f.source === "ai" ? "Found by AI review" : "Found by code analysis"}
    </span>
  );
}

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: "border-l-critical",
  HIGH: "border-l-serious",
  MEDIUM: "border-l-warning",
  LOW: "border-l-border",
  INFO: "border-l-border",
};

/** The actionable list: confirmed issues that count against the score. */
export function FixList({ findings, graphSymbols }: { findings: Finding[]; graphSymbols: Set<string> }) {
  if (findings.length === 0) {
    return (
      <div className="card-surface flex items-center gap-3 p-5">
        <span className="grid size-10 shrink-0 place-items-center rounded-full bg-good/12 text-good">
          <PartyPopper className="size-5" aria-hidden />
        </span>
        <div>
          <p className="font-medium">Nothing to fix</p>
          <p className="text-sm text-muted-foreground">No confirmed security issues in this push.</p>
        </div>
      </div>
    );
  }
  return (
    <ol className="space-y-3">
      {findings.map((f, i) => {
        const name = cweName(f.cwe);
        const hasPath = (f.taint_flow?.length ?? 0) > 1 || (f.symbol_node_id ? graphSymbols.has(f.symbol_node_id) : false);
        return (
          <li key={f.id} className={cn("card-surface border-l-4 p-4 sm:p-5", SEVERITY_BORDER[f.severity])}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-muted-foreground">{i + 1}.</span>
              <SeverityBadge severity={f.severity} />
              <h3 className="card-title">{name ?? <RichText text={f.title} />}</h3>
              {f.cwe && <span className="font-mono text-xs text-muted-foreground">{f.cwe}</span>}
              <span className="ml-auto">
                <SourceLabel f={f} />
              </span>
            </div>
            {name && <p className="mt-1 text-sm text-muted-foreground"><RichText text={f.title} /></p>}
            <div className="mt-3">
              <FileRef f={f} />
            </div>
            {f.description && (
              <p className="mt-3 text-sm leading-relaxed">
                <span className="font-medium">Why it matters: </span>
                <span className="text-muted-foreground"><RichText text={f.description} /></span>
              </p>
            )}
            {f.remediation && (
              <div className="mt-3 flex gap-2.5 rounded-lg border border-good/25 bg-good/5 p-3 text-sm">
                <Lightbulb className="mt-0.5 size-4 shrink-0 text-good" aria-hidden />
                <div>
                  <div className="font-medium">How to fix</div>
                  <p className="mt-0.5 leading-relaxed text-muted-foreground"><RichText text={f.remediation} /></p>
                </div>
              </div>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-3">
              {hasPath && <ShowAttackPath />}
              {f.verifier_reasoning && (
                <details className="group min-w-0 flex-1 text-sm">
                  <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                    <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                    Why the AI reviewer confirmed this
                    {f.confidence !== null && ` (${Math.round(f.confidence * 100)}% confidence)`}
                  </summary>
                  <p className="mt-2 rounded-lg bg-muted/60 p-3 leading-relaxed"><RichText text={f.verifier_reasoning} /></p>
                </details>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** Findings that don't count: dismissed false alarms, or unverified possibilities. */
export function NonCountedFindings({ findings }: { findings: Finding[] }) {
  const dismissed = findings.filter((f) => f.status === "rejected");
  const unverified = findings.filter((f) => f.status !== "rejected");
  return (
    <div className="space-y-3">
      {dismissed.length > 0 && (
        <details className="card-surface group">
          <summary className="flex cursor-pointer list-none items-center gap-2 p-4 text-sm">
            <ShieldCheck className="size-4 text-good" aria-hidden />
            <span className="font-medium">
              {dismissed.length} possible {dismissed.length === 1 ? "issue" : "issues"} dismissed as false alarms
            </span>
            <span className="hidden text-muted-foreground sm:inline">· not counted</span>
            <ChevronRight className="ml-auto size-4 text-muted-foreground transition-transform group-open:rotate-90" aria-hidden />
          </summary>
          <ul className="divide-y border-t">
            {dismissed.map((f) => (
              <li key={f.id} className="space-y-2 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} className="opacity-60" />
                  <span className="text-sm font-medium">{cweName(f.cwe) ?? <RichText text={f.title} />}</span>
                  <FileRef f={f} />
                </div>
                {f.verifier_reasoning && (
                  <p className="text-sm text-muted-foreground">
                    <span className="font-medium text-foreground">Why it&apos;s safe: </span>
                    <RichText text={f.verifier_reasoning} />
                  </p>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}
      {unverified.length > 0 && (
        <details className="card-surface group">
          <summary className="flex cursor-pointer list-none items-center gap-2 p-4 text-sm">
            <ShieldQuestion className="size-4 text-muted-foreground" aria-hidden />
            <span className="font-medium">
              {unverified.length} unverified {unverified.length === 1 ? "possibility" : "possibilities"}
            </span>
            <span className="hidden text-muted-foreground sm:inline">· worth a look, not counted</span>
            <ChevronRight className="ml-auto size-4 text-muted-foreground transition-transform group-open:rotate-90" aria-hidden />
          </summary>
          <ul className="divide-y border-t">
            {unverified.map((f) => (
              <li key={f.id} className="space-y-2 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="text-sm font-medium">{cweName(f.cwe) ?? <RichText text={f.title} />}</span>
                  <FileRef f={f} />
                </div>
                {f.description && <p className="text-sm text-muted-foreground"><RichText text={f.description} /></p>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export function QualityFindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <ul className="card-surface divide-y divide-border/60">
      {findings.map((f) => (
        <li key={f.id} className="flex flex-col gap-1 px-4 py-2.5 sm:flex-row sm:items-center sm:gap-3">
          <span className="min-w-0 flex-1 text-sm"><RichText text={f.title} /></span>
          <span className="font-mono text-xs text-muted-foreground">{location(f)}</span>
        </li>
      ))}
    </ul>
  );
}
