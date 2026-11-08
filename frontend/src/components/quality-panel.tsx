import { CircleCheck, Lightbulb, Sparkles } from "lucide-react";

import { ScoreBar } from "@/components/score-bar";
import { CRAFT_COLOR, CRAFT_WARN_THRESHOLD, MAX_CRAFT, pct, shortSymbol } from "@/lib/format";
import type { Push, QualityMetrics } from "@/lib/types";
import { cn } from "@/lib/utils";

function quickWins(m: QualityMetrics): string[] {
  const wins: string[] = [];
  const undocumented = m.documentable - m.documented;
  if (undocumented > 0)
    wins.push(`Add docstrings to ${undocumented} ${undocumented === 1 ? "function" : "functions"} (one line each is enough).`);
  if (m.type_hint_coverage < 1)
    wins.push(`Add type hints: ${pct(m.type_hint_coverage)} of parameters and returns are annotated.`);
  if (m.deep_nesting > 0)
    wins.push(`Flatten ${m.deep_nesting} deeply nested ${m.deep_nesting === 1 ? "block" : "blocks"} with early returns.`);
  if (m.long_functions > 0)
    wins.push(`Split ${m.long_functions} long ${m.long_functions === 1 ? "function" : "functions"} into smaller helpers.`);
  if (m.max_complexity > 10)
    wins.push(`Simplify the most complex function (complexity ${m.max_complexity}; aim for 10 or less).`);
  if (m.long_lines > 0) wins.push(`Wrap ${m.long_lines} ${m.long_lines === 1 ? "line" : "lines"} longer than 100 characters.`);
  if (m.naming_violations > 0) wins.push(`Rename ${m.naming_violations} identifiers to snake_case / PascalCase.`);
  return wins;
}

function Fact({ label, value, ok }: { label: string; value: React.ReactNode; ok: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-mono tabular-nums", !ok && "font-semibold")}>{value}</span>
    </div>
  );
}

export function QualityPanel({ push, metrics: raw }: { push: Push; metrics: QualityMetrics | null }) {
  // A push whose scan hasn't finished (or failed) has `{}` here, not null: only use real metrics.
  const metrics = raw && typeof raw.avg_complexity === "number" ? raw : null;
  if (!metrics && push.craft_push_score === null) {
    return (
      <div className="card-surface p-6 text-center text-sm text-muted-foreground">
        This push didn&apos;t change any functions that can be graded.
      </div>
    );
  }
  const wins = metrics ? quickWins(metrics) : [];
  const perSymbol = metrics?.per_symbol ?? [];
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="card-surface space-y-4 p-5">
          <ScoreBar
            label="Code craft for this push"
            value={push.craft_push_score}
            max={MAX_CRAFT}
            color={CRAFT_COLOR}
            threshold={CRAFT_WARN_THRESHOLD}
          />
          <div className="grid grid-cols-3 gap-3 border-t pt-4">
            <ScoreBar label="Docs" value={push.docs_score} max={100} color={CRAFT_COLOR} compact />
            <ScoreBar label="Readability" value={push.readability_score} max={100} color={CRAFT_COLOR} compact />
            <ScoreBar label="Type hints" value={push.type_hints_score} max={100} color={CRAFT_COLOR} compact />
          </div>
          <p className="text-xs text-muted-foreground">
            The tick marks {CRAFT_WARN_THRESHOLD}/{MAX_CRAFT}. Below it, the GitHub check warns.
          </p>
        </div>

        <div className="card-surface p-5">
          <h3 className="card-title flex items-center gap-2">
            <Lightbulb className="size-4 text-brand-text" aria-hidden /> Quick wins
          </h3>
          {wins.length === 0 ? (
            <p className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
              <CircleCheck className="size-4 text-good" aria-hidden /> Nothing to improve in the changed code.
            </p>
          ) : (
            <ul className="mt-3 space-y-2 text-sm">
              {wins.map((w) => (
                <li key={w} className="flex gap-2">
                  <span className="mt-2 size-1.5 shrink-0 rounded-full bg-foreground" aria-hidden />
                  {w}
                </li>
              ))}
            </ul>
          )}
          {metrics?.ai_notes && (
            <div className="mt-4 flex gap-2 border-t pt-4 text-sm">
              <Sparkles className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
              <p>
                <span className="font-medium">Reviewer note: </span>
                <span className="text-muted-foreground">{metrics.ai_notes}</span>
              </p>
            </div>
          )}
        </div>
      </div>

      {metrics && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
          <div className="card-surface divide-y divide-border/60 self-start px-4 py-1">
            <Fact label="Functions with docstrings" value={`${metrics.documented} of ${metrics.documentable}`} ok={metrics.documented === metrics.documentable} />
            <Fact label="Type-hint coverage" value={pct(metrics.type_hint_coverage)} ok={metrics.type_hint_coverage >= 1} />
            <Fact label="Average complexity" value={metrics.avg_complexity.toFixed(1)} ok={metrics.avg_complexity <= 5} />
            <Fact label="Deeply nested blocks" value={metrics.deep_nesting} ok={metrics.deep_nesting === 0} />
            <Fact label="Long functions" value={metrics.long_functions} ok={metrics.long_functions === 0} />
            <Fact label="Lines over 100 chars" value={metrics.long_lines} ok={metrics.long_lines === 0} />
          </div>

          {perSymbol.length > 0 && (
            <div className="card-surface overflow-x-auto">
              <table className="w-full min-w-[480px] text-sm">
                <caption className="px-4 pb-1 pt-3 text-left text-xs font-medium text-muted-foreground">
                  Functions changed in this push
                </caption>
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Function</th>
                    <th className="py-2 text-right font-medium">Complexity</th>
                    <th className="py-2 text-right font-medium">Lines</th>
                    <th className="py-2 text-center font-medium">Docstring</th>
                    <th className="px-4 py-2 text-right font-medium">Readability</th>
                  </tr>
                </thead>
                <tbody className="text-xs tabular-nums">
                  {perSymbol.map((s) => (
                    <tr key={s.node_id} className="border-b border-border/60 last:border-0">
                      <td className="px-4 py-2">
                        <div className="truncate font-mono font-semibold">{shortSymbol(s.node_id)}</div>
                        <div className="truncate font-mono text-muted-foreground">
                          {s.file_path}:{s.lineno}
                        </div>
                      </td>
                      <td className="py-2 text-right font-mono">{s.complexity}</td>
                      <td className="py-2 text-right font-mono">{s.length}</td>
                      <td className="py-2 text-center">
                        {s.has_docstring ? (
                          <CircleCheck className="mx-auto size-4 text-good" aria-label="yes" />
                        ) : (
                          <span className="text-muted-foreground">missing</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right font-mono">{Math.round(s.readability)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
