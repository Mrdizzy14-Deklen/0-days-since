import { Gauge, OctagonX, ShieldCheck, Sparkles } from "lucide-react";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { pct } from "@/lib/format";
import type { Developer, TeamStats } from "@/lib/types";
import { cn } from "@/lib/utils";

function Tile({
  icon: Icon,
  label,
  value,
  unit,
  detail,
  help,
  tone,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  unit?: string;
  detail: React.ReactNode;
  help: string;
  tone: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="card-surface flex cursor-default flex-col gap-3 p-4" tabIndex={0}>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className={cn("grid size-7 place-items-center rounded-[4px]", tone)}>
              <Icon className="size-4" aria-hidden />
            </span>
            {label}
          </div>
          <div className="flex items-baseline gap-1">
            <span className="font-display text-5xl font-black leading-none tracking-tight tabular-nums">{value}</span>
            {unit && <span className="font-mono text-xs text-muted-foreground">{unit}</span>}
          </div>
          <div className="text-xs text-muted-foreground">{detail}</div>
        </div>
      </TooltipTrigger>
      <TooltipContent className="max-w-60">{help}</TooltipContent>
    </Tooltip>
  );
}

export function StatTiles({ stats, developers }: { stats: TeamStats; developers: Developer[] }) {
  const clean = stats.total_pushes - stats.faulty_pushes;
  const cleanRate = stats.total_pushes ? clean / stats.total_pushes : 1;
  const avg = developers.length
    ? Math.round(developers.reduce((s, d) => s + d.composite_score, 0) / developers.length)
    : null;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Tile
        icon={Gauge}
        label="Team average"
        value={avg ?? "—"}
        unit="/1000"
        detail={`${developers.length} ${developers.length === 1 ? "developer" : "developers"} ranked`}
        help="The average composite score (security + craft) across everyone on the team."
        tone="bg-brand-soft text-brand-text"
      />
      <Tile
        icon={ShieldCheck}
        label="Clean pushes"
        value={pct(cleanRate)}
        detail={`${clean} of ${stats.total_pushes} pushes had no confirmed vulnerability`}
        help="Share of scanned pushes with no verified security issue."
        tone="bg-good/12 text-good"
      />
      <Tile
        icon={OctagonX}
        label="Merges blocked"
        value={stats.blocked_merges}
        detail="Critical or high issues stopped before merge"
        help="Pushes whose GitHub check failed because a critical or high-severity vulnerability was confirmed."
        tone="bg-critical/12 text-critical"
      />
      <Tile
        icon={Sparkles}
        label="False alarms filtered"
        value={stats.false_positives_rejected}
        detail="Dismissed by the AI reviewer, not counted"
        help="Possible issues the second AI pass proved were safe. They never count against anyone's score."
        tone="bg-muted text-foreground"
      />
    </div>
  );
}
