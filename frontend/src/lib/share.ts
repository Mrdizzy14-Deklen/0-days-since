/**
 * Wordle-style share text. Spoiler-free on purpose: squares and numbers only, never code,
 * file names or vulnerability details, so it is safe to paste anywhere.
 */

import { pushCheckState } from "@/lib/format";
import type { Developer, Push } from "@/lib/types";

/** Just what the grid needs (keeps the page payload small). */
export type SharePush = Pick<Push, "status" | "conclusion" | "completed_at" | "created_at"> & {
  developer: { github_login: string } | null;
};

export function toSharePush(p: Push): SharePush {
  return {
    status: p.status,
    conclusion: p.conclusion,
    completed_at: p.completed_at,
    created_at: p.created_at,
    developer: p.developer ? { github_login: p.developer.github_login } : null,
  };
}

export type DayResult = "passed" | "warned" | "failed" | "none";

export const SQUARE: Record<DayResult, string> = {
  passed: "🟩",
  warned: "🟨",
  failed: "🟥",
  none: "⬜",
};

/** Day 1 is launch day (HackUTD ZeroDay, Nov 7 2026), like Wordle's puzzle numbers. */
const LAUNCH = new Date(2026, 10, 7);

export function dayNumber(now: Date = new Date()): number {
  const start = new Date(LAUNCH.getFullYear(), LAUNCH.getMonth(), LAUNCH.getDate()).getTime();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  return Math.max(1, Math.round((today - start) / 86_400_000) + 1);
}

function localDay(d: Date): string {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** The last `days` calendar days, oldest first, in the viewer's time zone. */
export function lastDays(now: Date, days = 7): Date[] {
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    d.setDate(d.getDate() - (days - 1 - i));
    return d;
  });
}

/** Worst outcome of a developer's pushes on each day: one blocked push makes the day red. */
export function dayResults(pushes: SharePush[], login: string, days: Date[]): DayResult[] {
  const byDay = new Map<string, DayResult>();
  const rank: Record<DayResult, number> = { none: 0, passed: 1, warned: 2, failed: 3 };
  for (const p of pushes) {
    if (p.developer?.github_login !== login) continue;
    const state = pushCheckState(p);
    if (state !== "passed" && state !== "warned" && state !== "failed") continue;
    const key = localDay(new Date(p.completed_at ?? p.created_at ?? 0));
    const prev = byDay.get(key) ?? "none";
    if (rank[state] > rank[prev]) byDay.set(key, state);
  }
  return days.map((d) => byDay.get(localDay(d)) ?? "none");
}

export const LEGEND = "🟩 clean · 🟨 warned · 🟥 blocked · ⬜ no push";

export function teamShareText(opts: {
  title: string;
  developers: Developer[];
  pushes: SharePush[];
  daysSince: number | null;
  record: number | null;
  now: Date;
}): string {
  const days = lastDays(opts.now);
  const rows = opts.developers.map(
    (d) => `${dayResults(opts.pushes, d.github_login, days).map((r) => SQUARE[r]).join("")} ${d.github_login}`,
  );
  const board =
    opts.daysSince === null
      ? ""
      : `\n🦺 ${opts.daysSince} ${opts.daysSince === 1 ? "day" : "days"} since last incident` +
        (opts.record !== null ? ` (record ${opts.record})` : "");
  return `0 Days Since #${dayNumber(opts.now)} · ${opts.title}${board}\n\n${rows.join("\n")}\n\nLast 7 days · ${LEGEND}`;
}

export function personalShareText(opts: {
  developer: Developer;
  rank: number | null;
  teamSize: number | null;
  pushes: SharePush[];
  now: Date;
}): string {
  const d = opts.developer;
  const squares = dayResults(opts.pushes, d.github_login, lastDays(opts.now)).map((r) => SQUARE[r]).join("");
  const rank = opts.rank ? ` · #${opts.rank}${opts.teamSize ? ` of ${opts.teamSize}` : ""}` : "";
  const streak = d.clean_streak > 0 ? ` · 🔥 ${d.clean_streak} clean in a row` : "";
  return `0 Days Since #${dayNumber(opts.now)} · @${d.github_login}\n${squares}\n${d.composite_score} pts${rank}${streak}`;
}
