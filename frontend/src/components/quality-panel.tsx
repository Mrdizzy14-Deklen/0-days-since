import { Sparkles } from "lucide-react";

import { ScoreBar } from "@/components/score-bar";
import { CRAFT_COLOR, CRAFT_WARN_THRESHOLD, MAX_CRAFT, pct, shortSymbol } from "@/lib/format";
import type { Push, QualityMetrics } from "@/lib/types";

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="font-mono text-sm tabular-nums">{value}</div>
    </div>
  );
}

export function QualityPanel({ push, metrics }: { push: Push; metrics: QualityMetrics | null }) {
  if (!metrics && push.craft_push_score === null) {
    return <p className="text-sm text-muted-foreground">No graded symbols in this push.</p>;
  }
  const perSymbol = metrics?.per_symbol ?? [];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div className="space-y-3 rounded-xl border bg-card p-4">
          <ScoreBar
            label="This push's craft score"
            value={push.craft_push_score}
            max={MAX_CRAFT}
            color={CRAFT_COLOR}
            threshold={CRAFT_WARN_THRESHOLD}
          />
          <ScoreBar label="Documentation" value={push.docs_score} max={100} color={CRAFT_COLOR} compact />
          <ScoreBar label="Readability" value={push.readability_score} max={100} color={CRAFT_COLOR} compact />
          <ScoreBar label="Type hints" value={push.type_hints_score} max={100} color={CRAFT_COLOR} compact />
          <p className="text-[11px] text-muted-foreground">
            Marker at {CRAFT_WARN_THRESHOLD}/{MAX_CRAFT}: pushes below it get a neutral check.
          </p>
        </div>
        {metrics && (
          <div className="grid grid-cols-2 gap-2 self-start sm:grid-cols-3">
            <Metric label="Docstrings" value={`${metrics.documented}/${metrics.documentable}`} />
            <Metric label="Type-hint coverage" value={pct(metrics.type_hint_coverage)} />
            <Metric label="Comment density" value={pct(metrics.comment_density)} />
            <Metric label="Avg complexity" value={metrics.avg_complexity.toFixed(1)} />
            <Metric label="Max complexity" value={metrics.max_complexity} />
            <Metric label="Deep nesting" value={metrics.deep_nesting} />
            <Metric label="Long functions" value={metrics.long_functions} />
            <Metric label="Long lines" value={metrics.long_lines} />
            <Metric label="Naming issues" value={metrics.naming_violations} />
          </div>
        )}
      </div>

      {metrics?.ai_notes && (
        <div className="flex gap-2 rounded-xl border bg-card p-4 text-sm">
          <Sparkles className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
          <div>
            <div className="text-xs font-medium text-muted-foreground">Reviewer note</div>
            <p className="mt-0.5">{metrics.ai_notes}</p>
          </div>
        </div>
      )}

      {perSymbol.length > 0 && (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full min-w-[560px] text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Symbol</th>
                <th className="py-2 text-right font-medium">Complexity</th>
                <th className="py-2 text-right font-medium">Nesting</th>
                <th className="py-2 text-right font-medium">Lines</th>
                <th className="py-2 text-right font-medium">Hints</th>
                <th className="py-2 text-center font-medium">Doc</th>
                <th className="px-4 py-2 text-right font-medium">Readability</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs tabular-nums">
              {perSymbol.map((s) => (
                <tr key={s.node_id} className="border-b last:border-0">
                  <td className="px-4 py-2">
                    <div className="truncate font-semibold">{shortSymbol(s.node_id)}</div>
                    <div className="truncate text-muted-foreground">
                      {s.file_path}:{s.lineno}
                    </div>
                  </td>
                  <td className="py-2 text-right">{s.complexity}</td>
                  <td className="py-2 text-right">{s.nesting}</td>
                  <td className="py-2 text-right">{s.length}</td>
                  <td className="py-2 text-right">{pct(s.type_hint_coverage)}</td>
                  <td className="py-2 text-center">{s.has_docstring ? "yes" : "—"}</td>
                  <td className="px-4 py-2 text-right">{Math.round(s.readability)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
