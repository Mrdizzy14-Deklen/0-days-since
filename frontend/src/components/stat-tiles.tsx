import { GitCommitHorizontal, Network, OctagonX, ShieldCheck, TriangleAlert } from "lucide-react";

import { cweName, pct } from "@/lib/format";
import type { TeamStats } from "@/lib/types";

function Tile({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="size-3.5" aria-hidden />
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div>
      {detail && <div className="mt-1 text-xs text-muted-foreground">{detail}</div>}
    </div>
  );
}

export function StatTiles({ stats }: { stats: TeamStats }) {
  const faultRate = stats.total_pushes ? stats.faulty_pushes / stats.total_pushes : 0;
  const repo = stats.repositories[0];
  const graph = stats.repositories.reduce(
    (acc, r) => ({ files: acc.files + r.files, symbols: acc.symbols + r.symbols, edges: acc.edges + r.edges }),
    { files: 0, symbols: 0, edges: 0 },
  );
  const topCwe = stats.top_cwes[0];
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      <Tile
        icon={GitCommitHorizontal}
        label="Pushes scanned"
        value={stats.total_pushes}
        detail={`${stats.repositories.length} ${stats.repositories.length === 1 ? "repository" : "repositories"}`}
      />
      <Tile
        icon={TriangleAlert}
        label="Faulty push rate"
        value={pct(faultRate)}
        detail={`${stats.faulty_pushes} pushes with verified vulns`}
      />
      <Tile
        icon={OctagonX}
        label="Merges blocked"
        value={stats.blocked_merges}
        detail={topCwe ? `Most common: ${topCwe.cwe}${cweName(topCwe.cwe) ? ` (${cweName(topCwe.cwe)})` : ""}` : "CRITICAL / HIGH findings"}
      />
      <Tile
        icon={ShieldCheck}
        label="False positives rejected"
        value={stats.false_positives_rejected}
        detail="by the adversarial skeptic pass"
      />
      <Tile
        icon={Network}
        label="Call graph"
        value={
          <span className="font-mono text-xl">
            {graph.symbols}
            <span className="text-sm text-muted-foreground"> symbols</span>
          </span>
        }
        detail={
          stats.repositories.length
            ? `${graph.edges} edges across ${graph.files} files${repo && stats.repositories.length === 1 ? ` · ${repo.full_name}` : ""}`
            : "No repositories yet"
        }
      />
    </div>
  );
}
