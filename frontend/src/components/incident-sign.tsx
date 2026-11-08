import Link from "next/link";

import { FlipNumber } from "@/components/flip-number";
import type { IncidentStats } from "@/lib/insights";

/**
 * The workplace-safety board: days since the team's last push with a confirmed
 * vulnerability. Green "safe condition" sign while the count is above zero, red at zero.
 */
export function IncidentSign({ stats }: { stats: IncidentStats | null }) {
  if (!stats) return null;
  const { days, last, record } = stats;
  const safe = days > 0;
  return (
    <section
      aria-label={`${days} days since last incident`}
      className="plate overflow-hidden text-white"
      // Enamel sign greens/reds: deeper than the status tokens so white stencil text reads.
      style={{ background: safe ? "#0b7d2e" : "#b3261e" }}
    >
      <div className="flex items-center justify-between border-b-2 border-black/40 bg-black/15 px-4 py-1.5">
        <span className="font-stencil text-sm uppercase tracking-[0.2em]">{safe ? "Safety first" : "Incident reported"}</span>
        <span className="font-mono text-[10px] uppercase tracking-widest opacity-80">Team board</span>
      </div>
      <div className="flex items-center gap-4 px-4 py-4">
        <FlipNumber
          value={days}
          size="lg"
          tileClassName="bg-[#fbf8f0] text-[#12120f] border-2 border-black/60 shadow-[inset_0_-6px_0_rgba(0,0,0,0.08)]"
        />
        <div className="font-stencil text-3xl uppercase leading-[0.9] tracking-wide sm:text-4xl">
          {days === 1 ? "Day" : "Days"} since
          <br />
          last incident
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t-2 border-black/30 bg-black/15 px-4 py-2 text-xs">
        {last ? (
          <Link href={`/pushes/${last.id}`} className="min-w-0 truncate underline-offset-2 hover:underline">
            Last: <span className="font-semibold">{last.commit_message?.split("\n")[0]}</span> · @
            {last.developer?.github_login}
          </Link>
        ) : (
          <span>No confirmed vulnerabilities in recent pushes</span>
        )}
        <span className="shrink-0 font-mono uppercase tracking-wider opacity-90">Record {record}d</span>
      </div>
    </section>
  );
}
