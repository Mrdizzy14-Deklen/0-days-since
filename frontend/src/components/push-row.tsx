import Link from "next/link";
import { Bot, GitBranch } from "lucide-react";

import { DevAvatar } from "@/components/dev-avatar";
import { RelativeTime } from "@/components/relative-time";
import { CheckBadge, PointsDelta } from "@/components/status";
import { pushCheckState } from "@/lib/format";
import type { Push } from "@/lib/types";
import { cn } from "@/lib/utils";

function VulnCounts({ vulns }: { vulns: Push["vulns"] }) {
  const parts = (
    [
      ["critical", "C", "bg-critical text-white"],
      ["high", "H", "bg-serious text-black"],
      ["medium", "M", "bg-warning text-black"],
      ["low", "L", "bg-muted text-foreground"],
    ] as const
  ).filter(([k]) => vulns[k] > 0);
  if (parts.length === 0) return null;
  return (
    <span className="inline-flex items-center gap-1" aria-label="Verified vulnerabilities">
      {parts.map(([k, letter, tone]) => (
        <span
          key={k}
          title={`${vulns[k]} ${k}`}
          className={cn("rounded px-1 font-mono text-[10px] font-semibold leading-4", tone)}
        >
          {vulns[k]}
          {letter}
        </span>
      ))}
    </span>
  );
}

export function PushRow({
  push,
  showAuthor = true,
  fresh = false,
}: {
  push: Push;
  showAuthor?: boolean;
  fresh?: boolean;
}) {
  const state = pushCheckState(push);
  const login = push.developer?.github_login ?? "unknown";
  return (
    <li className={cn("relative", fresh && "feed-in")}>
      <Link
        href={`/pushes/${push.id}`}
        className="flex gap-3 px-4 py-3 transition-colors hover:bg-muted/50"
      >
        {showAuthor && (
          <DevAvatar login={login} src={push.developer?.avatar_url} className="mt-0.5 size-7" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <p className="line-clamp-2 text-sm font-medium leading-snug">
              {push.commit_message || "(no commit message)"}
            </p>
            {state !== "scanning" && state !== "skipped" && state !== "errored" && (
              <PointsDelta value={push.points_delta} className="shrink-0 text-sm" suffix="" />
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <CheckBadge state={state} className="h-5" />
            {showAuthor && <span className="text-foreground/80">@{login}</span>}
            <span className="font-mono">{push.short_sha}</span>
            {push.branch && (
              <span className="inline-flex items-center gap-0.5">
                <GitBranch className="size-3" aria-hidden />
                {push.pr_number ? `PR #${push.pr_number}` : push.branch}
              </span>
            )}
            <VulnCounts vulns={push.vulns} />
            <RelativeTime iso={push.completed_at ?? push.created_at} className="ml-auto" />
          </div>
          {push.ai_summary && (
            <p className="mt-1.5 flex gap-1.5 text-xs leading-relaxed text-muted-foreground">
              <Bot className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              <span className="line-clamp-3">{push.ai_summary}</span>
            </p>
          )}
        </div>
      </Link>
    </li>
  );
}
