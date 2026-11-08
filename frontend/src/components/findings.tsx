import { Bot, Cpu, Lightbulb, Scale } from "lucide-react";

import { FindingStatusLabel, SeverityBadge } from "@/components/status";
import { cweName } from "@/lib/format";
import type { Finding } from "@/lib/types";
import { cn } from "@/lib/utils";

function Location({ f }: { f: Finding }) {
  const lines = f.start_line
    ? f.end_line && f.end_line !== f.start_line
      ? `:${f.start_line}-${f.end_line}`
      : `:${f.start_line}`
    : "";
  return (
    <span className="font-mono text-xs text-muted-foreground">
      {f.file_path}
      {lines}
    </span>
  );
}

export function VulnerabilityList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="rounded-xl border bg-card p-6 text-center text-sm text-muted-foreground">
        No security findings on this push.
      </p>
    );
  }
  return (
    <ul className="space-y-3">
      {findings.map((f) => (
        <li
          key={f.id}
          className={cn(
            "rounded-xl border bg-card p-4",
            f.status === "rejected" && "opacity-75",
            f.counted_in_score && "border-l-4 border-l-critical",
          )}
        >
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            {f.cwe && (
              <span className="font-mono text-xs">
                {f.cwe}
                {cweName(f.cwe) && <span className="text-muted-foreground"> · {cweName(f.cwe)}</span>}
              </span>
            )}
            <span className="font-mono text-[11px] text-muted-foreground">{f.rule_id}</span>
            <span className="ml-auto flex items-center gap-3">
              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                {f.source === "ai" ? <Bot className="size-3.5" aria-hidden /> : <Cpu className="size-3.5" aria-hidden />}
                {f.source === "ai" ? "AI analyzer" : "Static engine"}
              </span>
              <FindingStatusLabel status={f.status} />
            </span>
          </div>
          <h3 className={cn("mt-2 font-medium break-words", f.status === "rejected" && "line-through decoration-muted-foreground/60")}>
            {f.title}
          </h3>
          <Location f={f} />
          {f.description && <p className="mt-2 text-sm text-muted-foreground">{f.description}</p>}
          {f.verifier_reasoning && (
            <div className="mt-3 flex gap-2 rounded-lg bg-muted/60 p-3 text-sm">
              <Scale className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
              <div>
                <div className="text-xs font-medium text-muted-foreground">
                  Skeptic verdict{f.status === "rejected" ? ": false positive" : ": confirmed"}
                </div>
                <p className="mt-0.5">{f.verifier_reasoning}</p>
              </div>
            </div>
          )}
          {f.remediation && f.status !== "rejected" && (
            <div className="mt-3 flex gap-2 text-sm">
              <Lightbulb className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
              <p>{f.remediation}</p>
            </div>
          )}
          <div className="mt-3 text-[11px] text-muted-foreground">
            {f.counted_in_score ? "Counted in the security score" : "Not counted in the score"}
            {f.confidence !== null && ` · confidence ${Math.round(f.confidence * 100)}%`}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function QualityFindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <ul className="divide-y rounded-xl border bg-card">
      {findings.map((f) => (
        <li key={f.id} className="flex flex-col gap-0.5 px-4 py-2.5 sm:flex-row sm:items-baseline sm:gap-3">
          <span className="w-24 shrink-0 font-mono text-[11px] text-muted-foreground">{f.rule_id}</span>
          <span className="min-w-0 flex-1 text-sm">{f.title}</span>
          <Location f={f} />
        </li>
      ))}
    </ul>
  );
}
