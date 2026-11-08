import Link from "next/link";
import { Bug, Flame, ShieldCheck, Sparkles } from "lucide-react";

import { DevAvatar } from "@/components/dev-avatar";
import { FlipNumber } from "@/components/flip-number";
import { ScoreBar } from "@/components/score-bar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  CRAFT_COLOR,
  CRAFT_WARN_THRESHOLD,
  MAX_CRAFT,
  MAX_SECURITY,
  SECURITY_COLOR,
  cweName,
} from "@/lib/format";
import { CWE_TIPS, smellTip } from "@/lib/insights";
import type { Developer } from "@/lib/types";
import { cn } from "@/lib/utils";

/** The "wall of shame": the three lowest scores, worst first. */
const MEDAL = [
  { label: "Worst", ring: "ring-[#d03b3b]", chip: "bg-[#d03b3b] text-white" },
  { label: "2nd Worst", ring: "ring-[#ec835a]", chip: "bg-[#ec835a] text-[#12120f]" },
  { label: "3rd Worst", ring: "ring-[#fab219]", chip: "bg-[#fab219] text-[#12120f]" },
];

export function Movement({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return null;
  const label = value > 0 ? `Up ${value}` : value < 0 ? `Down ${-value}` : "No change";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            "inline-flex items-center font-mono text-[11px] tabular-nums",
            value > 0 ? "text-delta-up" : value < 0 ? "text-delta-down" : "text-muted-foreground",
          )}
        >
          {value > 0 ? `▲${value}` : value < 0 ? `▼${-value}` : "–"}
        </span>
      </TooltipTrigger>
      <TooltipContent>{label} vs. 7 days ago</TooltipContent>
    </Tooltip>
  );
}

export function CweBadge({ cwe }: { cwe: string }) {
  const name = cweName(cwe);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex h-6 max-w-full items-center gap-1 rounded-md border border-critical/35 bg-critical/8 px-1.5 text-xs">
          <Bug className="size-3 shrink-0 text-critical" aria-hidden />
          <span className="truncate">{name ?? cwe}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-64">
        <div className="font-medium">
          Most frequent weakness: {cwe}
          {name ? ` (${name})` : ""}
        </div>
        {CWE_TIPS[cwe] && <div className="mt-1 opacity-80">Tip: {CWE_TIPS[cwe]}</div>}
      </TooltipContent>
    </Tooltip>
  );
}

export function SmellBadge({ smell }: { smell: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex h-6 max-w-full items-center gap-1 rounded-md border border-warning/40 bg-warning/8 px-1.5 text-xs">
          <Sparkles className="size-3 shrink-0 text-warning" aria-hidden />
          <span className="truncate">{smell}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-64">
        <div className="font-medium">Most frequent code smell</div>
        <div className="mt-1 opacity-80">Tip: {smellTip(smell)}</div>
      </TooltipContent>
    </Tooltip>
  );
}

function CleanBadge() {
  return (
    <span className="inline-flex h-6 items-center gap-1 rounded-md border border-good/35 bg-good/8 px-1.5 text-xs">
      <ShieldCheck className="size-3 text-good" aria-hidden /> No vulnerabilities
    </span>
  );
}

function Streak({ d }: { d: Developer }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center gap-1 text-sm tabular-nums">
          <Flame
            className={cn("size-4", d.clean_streak > 0 ? "fill-orange-500/25 text-orange-500" : "text-muted-foreground/40")}
            aria-hidden
          />
          <span className="font-mono">{d.clean_streak}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {d.clean_streak} clean {d.clean_streak === 1 ? "push" : "pushes"} in a row · best {d.best_clean_streak}
      </TooltipContent>
    </Tooltip>
  );
}

function Badges({ d }: { d: Developer }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1">
      {d.top_cwe ? <CweBadge cwe={d.top_cwe} /> : d.total_pushes > 0 ? <CleanBadge /> : null}
      {d.top_smell && <SmellBadge smell={d.top_smell} />}
    </div>
  );
}

function Bars({ d }: { d: Developer }) {
  return (
    <div className="space-y-1.5">
      <ScoreBar label="Security" value={d.security_score} max={MAX_SECURITY} color={SECURITY_COLOR} compact />
      <ScoreBar
        label="Craft"
        value={d.craft_score}
        max={MAX_CRAFT}
        color={CRAFT_COLOR}
        threshold={CRAFT_WARN_THRESHOLD}
        compact
      />
    </div>
  );
}

function YouTag() {
  return (
    <span className="rounded-[3px] border border-foreground bg-brand px-1.5 py-px font-display text-xs font-black uppercase text-brand-foreground">You</span>
  );
}

function PodiumCard({ d, place, movement, isYou }: { d: Developer; place: number; movement: number | null | undefined; isYou: boolean }) {
  const medal = MEDAL[place];
  return (
    <Link
      href={`/developers/${d.id}`}
      className={cn(
        "plate group flex flex-col gap-4 overflow-hidden p-4 transition-transform duration-200 hover:-translate-x-0.5 hover:-translate-y-0.5",
        isYou && "outline-4 outline-offset-2 outline-[var(--brand)]",
      )}
    >
      {place === 0 && <div className="hazard-tape -mx-4 -mt-4 h-2.5" aria-hidden />}
      <div className="flex items-center justify-between">
        <span className={cn("rounded-[3px] border-2 border-foreground px-2 py-0.5 font-display text-base font-black uppercase leading-none", medal.chip)}>
          {medal.label}
        </span>
        <Movement value={movement} />
      </div>
      <div className="flex items-center gap-3">
        <DevAvatar login={d.github_login} src={d.avatar_url} className={cn("size-11 ring-2", medal.ring)} />
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="truncate font-semibold group-hover:underline">{d.display_name}</span>
            {isYou && <YouTag />}
          </div>
          <div className="truncate text-xs text-muted-foreground">@{d.github_login}</div>
        </div>
      </div>
      <div className="flex items-end gap-2">
        <FlipNumber value={d.composite_score} />
        <span className="pb-1 font-mono text-xs text-muted-foreground">/1000</span>
      </div>
      <Bars d={d} />
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">
        <span>
          <span className="font-mono text-foreground">{d.total_pushes}</span> pushes ·{" "}
          <span className="font-mono text-foreground">{d.faulty_pushes}</span> faulty
        </span>
        <Streak d={d} />
      </div>
      <Badges d={d} />
    </Link>
  );
}

const ROW_GRID =
  "grid grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-3 lg:grid-cols-[2.5rem_minmax(0,1.3fr)_6rem_minmax(0,1.4fr)_6.5rem_3.5rem_minmax(0,1.2fr)] lg:gap-x-5";

function Row({ d, movement, isYou }: { d: Developer; movement: number | null | undefined; isYou: boolean }) {
  return (
    <li>
      <Link
        href={`/developers/${d.id}`}
        className={cn(ROW_GRID, "group rounded-lg px-3 py-3 transition-colors hover:bg-muted/60", isYou && "bg-brand-soft")}
      >
        <div className="flex flex-col items-center leading-none">
          <span className="font-display text-3xl font-black text-muted-foreground">{d.rank}</span>
          <Movement value={movement} />
        </div>
        <div className="flex min-w-0 items-center gap-2.5">
          <DevAvatar login={d.github_login} src={d.avatar_url} />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-medium group-hover:underline">{d.display_name}</span>
              {isYou && <YouTag />}
            </div>
            <div className="truncate text-xs text-muted-foreground">@{d.github_login}</div>
          </div>
        </div>
        <div className="text-right">
          <span className="font-display text-4xl font-black leading-none tabular-nums">{d.composite_score}</span>
          <span className="font-mono text-[10px] text-muted-foreground">/1000</span>
        </div>
        {/* On small screens these wrap under the name; on desktop they become columns. */}
        <div className="col-span-3 grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] lg:contents">
          <Bars d={d} />
          <div className="flex items-center gap-4 text-xs text-muted-foreground lg:contents">
            <span className="lg:text-right">
              <span className="font-mono text-sm text-foreground">{d.total_pushes}</span> pushes
              <span className="block lg:mt-0.5">
                <span className="font-mono text-foreground">{d.faulty_pushes}</span> faulty
              </span>
            </span>
            <span className="lg:flex lg:justify-center">
              <Streak d={d} />
            </span>
          </div>
          <div className="sm:col-span-2 lg:col-span-1">
            <Badges d={d} />
          </div>
        </div>
      </Link>
    </li>
  );
}

export function Leaderboard({
  developers,
  movement,
  viewerLogin,
}: {
  developers: Developer[];
  movement: Record<string, number | null>;
  viewerLogin: string | null;
}) {
  if (developers.length === 0) {
    return (
      <div className="card-surface px-6 py-12 text-center">
        <p className="font-medium">No scores yet</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Push Python code to a connected repository and the first scores appear here in about 30
          seconds.
        </p>
      </div>
    );
  }
  // Bottom three get the cards (worst first); everyone else is ranked below, best first.
  const podium = developers.length >= 3 ? developers.slice(-3).reverse() : [];
  const rest = developers.slice(0, developers.length - podium.length);
  return (
    <div className="space-y-4">
      {podium.length > 0 && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {podium.map((d, i) => (
            <PodiumCard
              key={d.id}
              d={d}
              place={i}
              movement={movement[d.github_login]}
              isYou={d.github_login === viewerLogin}
            />
          ))}
        </div>
      )}
      {rest.length > 0 && (
        <div className="card-surface p-2">
          <div className={cn(ROW_GRID, "hidden px-3 pb-1 pt-2 text-xs text-muted-foreground lg:grid")} aria-hidden>
            <span className="text-center">#</span>
            <span>Developer</span>
            <span className="text-right">Score</span>
            <span>Security · Craft</span>
            <span className="text-right">Pushes</span>
            <span className="text-center">Streak</span>
            <span>Most frequent issue</span>
          </div>
          <ul className="divide-y divide-border/60">
            {rest.map((d) => (
              <Row key={d.id} d={d} movement={movement[d.github_login]} isYou={d.github_login === viewerLogin} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
