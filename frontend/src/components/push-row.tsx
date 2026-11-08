import Link from "next/link";
import { CircleCheck, CircleSlash, Loader2, OctagonX, TriangleAlert, type LucideIcon } from "lucide-react";

import { RichText } from "@/components/rich-text";
import { DevAvatar } from "@/components/dev-avatar";
import { RelativeTime } from "@/components/relative-time";
import { PointsDelta } from "@/components/status";
import { pushCheckState, type CheckState } from "@/lib/format";
import type { Push } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATE: Record<CheckState, { label: string; icon: LucideIcon; tone: string }> = {
  passed: { label: "Passed", icon: CircleCheck, tone: "text-good" },
  warned: { label: "Warned", icon: TriangleAlert, tone: "text-warning" },
  failed: { label: "Failed", icon: OctagonX, tone: "text-critical" },
  scanning: { label: "Scanning", icon: Loader2, tone: "text-muted-foreground" },
  errored: { label: "Error", icon: CircleSlash, tone: "text-muted-foreground" },
  skipped: { label: "Not scored", icon: CircleSlash, tone: "text-muted-foreground" },
};

function VulnCounts({ vulns }: { vulns: Push["vulns"] }) {
  const parts = (
    [
      ["critical", "critical", "bg-critical text-white"],
      ["high", "high", "bg-serious text-black"],
      ["medium", "medium", "bg-warning text-black"],
      ["low", "low", "bg-muted text-foreground"],
    ] as const
  ).filter(([k]) => vulns[k] > 0);
  if (parts.length === 0) return null;
  return (
    <span className="inline-flex items-center gap-1">
      {parts.map(([k, word, tone]) => (
        <span key={k} className={cn("rounded px-1.5 text-[10px] font-semibold leading-4", tone)}>
          {vulns[k]} {word}
        </span>
      ))}
    </span>
  );
}

export function PushRow({
  push,
  showAuthor = true,
  fresh = false,
  summary = true,
}: {
  push: Push;
  showAuthor?: boolean;
  fresh?: boolean;
  summary?: boolean;
}) {
  const state = pushCheckState(push);
  const { label, icon: Icon, tone } = STATE[state];
  const login = push.developer?.github_login ?? "unknown";
  const scored = state === "passed" || state === "warned" || state === "failed";
  return (
    <li className={cn(fresh && "feed-in")}>
      <Link href={`/pushes/${push.id}`} className="group flex gap-3 px-4 py-3 transition-colors hover:bg-muted/50">
        <div className="relative mt-0.5 shrink-0 self-start">
          {showAuthor ? (
            <DevAvatar login={login} src={push.developer?.avatar_url} className="size-8" />
          ) : (
            <span className="grid size-8 place-items-center rounded-full bg-muted">
              <Icon className={cn("size-4", tone, state === "scanning" && "animate-spin")} aria-hidden />
            </span>
          )}
          {showAuthor && (
            <span className="absolute -bottom-1 -right-1 grid size-4 place-items-center rounded-full bg-card">
              <Icon className={cn("size-3.5", tone, state === "scanning" && "animate-spin")} aria-hidden />
            </span>
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <p className="truncate text-sm font-medium group-hover:underline">
              {push.commit_message?.split("\n")[0] || "(no commit message)"}
            </p>
            {scored && <PointsDelta value={push.points_delta} className="shrink-0 text-sm" suffix="" />}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span className={cn("font-medium", tone === "text-muted-foreground" ? "" : "text-foreground")}>
              <span className="sr-only">Check </span>
              {label}
            </span>
            {showAuthor && <span>@{login}</span>}
            <span className="font-mono">{push.pr_number ? `PR #${push.pr_number}` : push.short_sha}</span>
            <VulnCounts vulns={push.vulns} />
            <RelativeTime iso={push.completed_at ?? push.created_at} className="ml-auto shrink-0" />
          </div>
          {summary && push.ai_summary && (
            <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-muted-foreground"><RichText text={push.ai_summary} /></p>
          )}
        </div>
      </Link>
    </li>
  );
}
