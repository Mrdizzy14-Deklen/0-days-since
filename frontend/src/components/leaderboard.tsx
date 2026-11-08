import Link from "next/link";
import { Bug, Flame, Medal, Sparkles } from "lucide-react";

import { DevAvatar } from "@/components/dev-avatar";
import { ScoreBar } from "@/components/score-bar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  CRAFT_COLOR,
  CRAFT_WARN_THRESHOLD,
  MAX_CRAFT,
  MAX_SECURITY,
  SECURITY_COLOR,
  cweName,
  pct,
} from "@/lib/format";
import type { Developer } from "@/lib/types";
import { cn } from "@/lib/utils";

function RankMark({ rank }: { rank: number }) {
  if (rank <= 3) {
    const tone = ["text-[#d4a72c]", "text-[#a3a3a3]", "text-[#b0703c]"][rank - 1];
    return (
      <span className="flex items-center gap-0.5 font-mono text-sm font-semibold">
        <Medal className={cn("size-4", tone)} aria-hidden />
        {rank}
      </span>
    );
  }
  return <span className="pl-[18px] font-mono text-sm text-muted-foreground">{rank}</span>;
}

function CweBadge({ cwe }: { cwe: string }) {
  const name = cweName(cwe);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex h-6 max-w-full items-center gap-1 rounded-md border border-critical/40 bg-critical/10 px-1.5 text-xs">
          <Bug className="size-3 shrink-0 text-critical" aria-hidden />
          <span className="truncate font-mono">{cwe}</span>
          {name && <span className="hidden truncate text-muted-foreground xl:inline">{name}</span>}
        </span>
      </TooltipTrigger>
      <TooltipContent>Most frequent verified weakness{name ? `: ${name}` : ""}</TooltipContent>
    </Tooltip>
  );
}

function SmellBadge({ smell }: { smell: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex h-6 max-w-full items-center gap-1 rounded-md border border-warning/40 bg-warning/10 px-1.5 text-xs">
          <Sparkles className="size-3 shrink-0 text-warning" aria-hidden />
          <span className="truncate">{smell}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>Most frequent code smell</TooltipContent>
    </Tooltip>
  );
}

export function Leaderboard({ developers }: { developers: Developer[] }) {
  if (developers.length === 0) {
    return (
      <p className="px-1 py-8 text-center text-sm text-muted-foreground">
        No scored pushes yet. Push Python code to an installed repository to join the board.
      </p>
    );
  }
  return (
    <div className="-mx-4 overflow-x-auto sm:mx-0">
      <table className="w-full min-w-[760px] text-sm">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="w-12 py-2 pl-4 font-medium sm:pl-2">#</th>
            <th className="py-2 font-medium">Developer</th>
            <th className="py-2 text-right font-medium">Score</th>
            <th className="w-[22%] py-2 pl-6 font-medium">Security · Craft</th>
            <th className="py-2 text-right font-medium">Pushes</th>
            <th className="py-2 text-right font-medium">Streak</th>
            <th className="py-2 pl-4 pr-4 font-medium sm:pr-2">Most frequent</th>
          </tr>
        </thead>
        <tbody>
          {developers.map((d) => (
            <tr key={d.id} className="group border-b last:border-0 hover:bg-muted/40">
              <td className="py-3 pl-4 sm:pl-2">
                <RankMark rank={d.rank ?? 0} />
              </td>
              <td className="py-3">
                <Link href={`/developers/${d.id}`} className="flex items-center gap-2.5">
                  <DevAvatar login={d.github_login} src={d.avatar_url} />
                  <span className="min-w-0">
                    <span className="block truncate font-medium group-hover:underline">
                      {d.display_name}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">
                      @{d.github_login}
                    </span>
                  </span>
                </Link>
              </td>
              <td className="py-3 text-right">
                <span className="font-mono text-xl font-semibold tabular-nums">
                  {d.composite_score}
                </span>
                <span className="font-mono text-xs text-muted-foreground">/1000</span>
              </td>
              <td className="space-y-1.5 py-3 pl-6">
                <ScoreBar
                  label="Security"
                  value={d.security_score}
                  max={MAX_SECURITY}
                  color={SECURITY_COLOR}
                  compact
                />
                <ScoreBar
                  label="Craft"
                  value={d.craft_score}
                  max={MAX_CRAFT}
                  color={CRAFT_COLOR}
                  threshold={CRAFT_WARN_THRESHOLD}
                  compact
                />
              </td>
              <td className="py-3 text-right font-mono tabular-nums">
                <div>{d.total_pushes}</div>
                <div className="text-xs text-muted-foreground">
                  {d.faulty_pushes} faulty
                  {d.total_pushes > 0 && ` · ${pct(d.fault_ratio)}`}
                </div>
              </td>
              <td className="py-3 text-right">
                <span
                  className="inline-flex items-center gap-1 font-mono tabular-nums"
                  title={`Best streak: ${d.best_clean_streak}`}
                >
                  <Flame
                    className={cn(
                      "size-4",
                      d.clean_streak > 0 ? "fill-orange-500/25 text-orange-500" : "text-muted-foreground/40",
                    )}
                    aria-hidden
                  />
                  {d.clean_streak}
                </span>
                <div className="text-xs text-muted-foreground">best {d.best_clean_streak}</div>
              </td>
              <td className="py-3 pl-4 pr-4 sm:pr-2">
                <div className="flex max-w-[260px] flex-col items-start gap-1">
                  {d.top_cwe ? (
                    <CweBadge cwe={d.top_cwe} />
                  ) : (
                    <span className="text-xs text-muted-foreground">No verified CWEs</span>
                  )}
                  {d.top_smell && <SmellBadge smell={d.top_smell} />}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
