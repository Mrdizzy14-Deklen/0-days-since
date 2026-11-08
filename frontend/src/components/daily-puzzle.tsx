"use client";

import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Lightbulb, Share2, Tag } from "lucide-react";
import { toast } from "sonner";

import { RichText } from "@/components/rich-text";
import { Button } from "@/components/ui/button";
import { MARK_SQUARE, markGuess, puzzleForDay, type DailyPuzzle, type Mark } from "@/lib/puzzles";
import { cn } from "@/lib/utils";

const MAX_GUESSES = 3;
const STATS_KEY = "zd-puzzle:stats";

interface GameState {
  guesses: number[];
  category: string | null;
}

interface Stats {
  played: number;
  won: number;
  streak: number;
  best: number;
  lastDay: number;
  dist: [number, number, number, number]; // solved in 1, 2, 3, failed
}

const EMPTY_STATS: Stats = { played: 0, won: 0, streak: 0, best: 0, lastDay: 0, dist: [0, 0, 0, 0] };

function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? ({ ...fallback, ...JSON.parse(raw) } as T) : fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable: progress lasts for this visit only */
  }
}

function untilMidnight(now: number): string {
  const d = new Date(now);
  const next = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
  const s = Math.max(0, Math.floor((next - now) / 1000));
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
}

const MARK_STYLE: Record<Mark, string> = {
  hit: "bg-[#0ca30c] text-white border-[#0ca30c]",
  warm: "bg-[#e3a008] text-black border-[#e3a008]",
  cold: "bg-foreground text-background border-foreground",
};

/** Wordle for security: find the vulnerable line in three guesses, then name the bug. */
export function DailyPuzzleGame() {
  const [puzzle, setPuzzle] = useState<DailyPuzzle | null>(null);
  const [game, setGame] = useState<GameState>({ guesses: [], category: null });
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [now, setNow] = useState(0);
  const [copied, setCopied] = useState(false);

  // Everything depends on the viewer's local date, so start after mount.
  useEffect(() => {
    const p = puzzleForDay();
    setPuzzle(p);
    setGame(load(`zd-puzzle:${p.number}`, { guesses: [], category: null }));
    setStats(load(STATS_KEY, EMPTY_STATS));
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const marks = useMemo(
    () => (puzzle ? game.guesses.map((g) => markGuess(g, puzzle.answerLines)) : []),
    [game.guesses, puzzle],
  );
  const solved = marks.includes("hit");
  const over = solved || game.guesses.length >= MAX_GUESSES;
  const done = over && game.category !== null;

  if (!puzzle) {
    return <div className="h-96 animate-pulse rounded-md bg-muted" aria-busy="true" />;
  }
  const p = puzzle;

  function persist(next: GameState) {
    setGame(next);
    save(`zd-puzzle:${p.number}`, next);
  }

  function finishRound(won: boolean, tries: number) {
    const prev = load(STATS_KEY, EMPTY_STATS);
    if (prev.lastDay === p.number) return; // already recorded today
    const streak = won ? (prev.lastDay === p.number - 1 ? prev.streak + 1 : 1) : 0;
    const dist = [...prev.dist] as Stats["dist"];
    dist[won ? tries - 1 : 3] += 1;
    const next: Stats = {
      played: prev.played + 1,
      won: prev.won + (won ? 1 : 0),
      streak,
      best: Math.max(prev.best, streak),
      lastDay: p.number,
      dist,
    };
    setStats(next);
    save(STATS_KEY, next);
  }

  function guess(line: number) {
    if (over || game.guesses.includes(line)) return;
    const guesses = [...game.guesses, line];
    persist({ ...game, guesses });
    const mark = markGuess(line, p.answerLines);
    if (mark === "hit") {
      finishRound(true, guesses.length);
      toast.success(["Zero-day found first try!", "Nice catch.", "Phew, just in time."][guesses.length - 1]);
    } else if (guesses.length >= MAX_GUESSES) {
      finishRound(false, guesses.length);
    }
  }

  const shareText = () =>
    `Daily Zero-Day #${p.number} ${solved ? game.guesses.length : "X"}/${MAX_GUESSES} 🦺\n` +
    marks.map((m) => MARK_SQUARE[m]).join("") +
    (game.category ? `\n🏷️ ${game.category === p.bug ? "✅" : "❌"}` : "") +
    `\n0 Days Since`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(shareText());
      setCopied(true);
      toast.success("Copied. Paste it in your team chat.");
      setTimeout(() => setCopied(false), 1800);
    } catch {
      toast.error("Couldn't copy automatically.");
    }
  }

  const lines = p.code.split("\n");
  const misses = marks.filter((m) => m !== "hit").length;
  const last = marks.at(-1);
  const winRate = stats.played ? Math.round((stats.won / stats.played) * 100) : 0;
  const maxDist = Math.max(1, ...stats.dist);

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div className="min-w-0 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="eyebrow">Puzzle {p.number} · {p.title}</div>
            <p className="mt-1 text-sm text-muted-foreground">
              Click the line with the vulnerability. {MAX_GUESSES} guesses; 🟨 means you&apos;re within two lines.
            </p>
          </div>
          <div className="flex gap-1.5" aria-label={`${game.guesses.length} of ${MAX_GUESSES} guesses used`}>
            {Array.from({ length: MAX_GUESSES }, (_, i) => (
              <span
                key={i}
                className={cn(
                  "grid size-10 place-items-center rounded-[4px] border-2 font-display text-lg font-black",
                  marks[i] ? MARK_STYLE[marks[i]] : "border-border bg-card text-muted-foreground",
                )}
              >
                {game.guesses[i] !== undefined && <span className="flip-digit">{game.guesses[i]}</span>}
              </span>
            ))}
          </div>
        </div>

        <div className="plate overflow-hidden">
          <div className="flex items-center gap-2 border-b-2 border-foreground bg-muted/60 px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
            <span className="size-2.5 rounded-full bg-[#d03b3b]" />
            <span className="size-2.5 rounded-full bg-[#e3a008]" />
            <span className="size-2.5 rounded-full bg-[#0ca30c]" />
            <span className="ml-2">{p.title.toLowerCase().replace(/\s+/g, "_")}.py</span>
          </div>
          <ol className="overflow-x-auto py-2 font-mono text-[13px] leading-6">
            {lines.map((text, i) => {
              const n = i + 1;
              const gi = game.guesses.indexOf(n);
              const mark = gi >= 0 ? marks[gi] : null;
              const reveal = over && p.answerLines.includes(n);
              return (
                <li key={n}>
                  <button
                    type="button"
                    disabled={over}
                    onClick={() => guess(n)}
                    aria-label={`Line ${n}: ${text.trim() || "blank"}`}
                    className={cn(
                      "group flex w-full min-w-max items-stretch text-left transition-colors",
                      !over && "hover:bg-brand-soft",
                      mark === "cold" && "bg-foreground/10 line-through decoration-foreground/40",
                      mark === "warm" && "bg-[#e3a008]/20",
                      (mark === "hit" || reveal) && "bg-[#0ca30c]/20",
                    )}
                  >
                    <span className="w-10 shrink-0 select-none pr-3 text-right text-muted-foreground group-hover:text-foreground">
                      {n}
                    </span>
                    <span className={cn("whitespace-pre pr-4", reveal && "font-semibold")}>{text || " "}</span>
                    {reveal && (
                      <span className="ml-auto mr-3 self-center rounded-[3px] bg-[#0ca30c] px-1.5 font-sans text-[10px] font-bold uppercase text-white">
                        Zero-day
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ol>
        </div>

        <div aria-live="polite" className="min-h-6 text-sm">
          {!over && last === "warm" && <p>🟨 Warm: the bug is within two lines of {game.guesses.at(-1)}.</p>}
          {!over && last === "cold" && <p>⬛ Cold. Keep reading.</p>}
          {!over && misses >= 2 && (
            <p className="mt-1 flex gap-1.5 text-muted-foreground">
              <Lightbulb className="mt-0.5 size-4 shrink-0" aria-hidden /> Hint: {p.hint}
            </p>
          )}
          {over && !solved && <p>Out of guesses. The highlighted line is the zero-day.</p>}
        </div>

        {over && game.category === null && (
          <section className="card-surface p-4" aria-labelledby="bonus-title">
            <h2 id="bonus-title" className="card-title flex items-center gap-2">
              <Tag className="size-4" aria-hidden /> Bonus: name the bug
            </h2>
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {p.options.map((o) => (
                <Button key={o} variant="outline" className="justify-start" onClick={() => persist({ ...game, category: o })}>
                  {o}
                </Button>
              ))}
            </div>
          </section>
        )}

        {done && (
          <section className="card-surface space-y-3 p-4" aria-labelledby="explain-title">
            <h2 id="explain-title" className="card-title">
              {p.bug} <span className="font-mono text-sm font-normal text-muted-foreground">{p.cwe}</span>
            </h2>
            <p className="text-sm">
              {game.category === p.bug ? "🏷️ ✅ You named it. " : `🏷️ ❌ You said ${game.category}. `}
              <RichText text={p.explanation} />
            </p>
            <div>
              <div className="eyebrow mb-1">The fix</div>
              <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">{p.fix}</pre>
            </div>
          </section>
        )}
      </div>

      <aside className="space-y-4 lg:sticky lg:top-20 lg:self-start">
        <section className="plate p-4" aria-labelledby="stats-title">
          <h2 id="stats-title" className="card-title">Your stats</h2>
          <dl className="mt-3 grid grid-cols-4 gap-2 text-center">
            {[
              ["Played", stats.played],
              ["Win %", winRate],
              ["Streak", stats.streak],
              ["Best", stats.best],
            ].map(([k, v]) => (
              <div key={k as string}>
                <dd className="font-display text-3xl font-black leading-none">{v}</dd>
                <dt className="mt-1 text-[11px] text-muted-foreground">{k}</dt>
              </div>
            ))}
          </dl>
          <div className="mt-4 space-y-1">
            {["1", "2", "3", "X"].map((label, i) => (
              <div key={label} className="flex items-center gap-2 text-xs">
                <span className="w-3 font-mono">{label}</span>
                <span
                  className={cn("flex h-5 items-center justify-end rounded-[2px] px-1.5 font-mono text-[11px] text-white",
                    i === 3 ? "bg-foreground/50" : "bg-[#0ca30c]")}
                  style={{ width: `${Math.max(8, (stats.dist[i] / maxDist) * 100)}%` }}
                >
                  {stats.dist[i]}
                </span>
              </div>
            ))}
          </div>
        </section>

        {done ? (
          <section className="card-surface space-y-3 p-4">
            <pre className="whitespace-pre-wrap rounded-md bg-muted p-3 text-center font-mono text-sm leading-relaxed">
              {shareText()}
            </pre>
            <Button onClick={copy} className="w-full border-2 border-foreground bg-brand font-display text-lg font-bold uppercase text-brand-foreground shadow-[3px_3px_0_var(--foreground)] hover:bg-brand">
              {copied ? <Check className="size-4" /> : <Share2 className="size-4" />}
              {copied ? "Copied" : "Share result"}
            </Button>
            <p className="text-center text-xs text-muted-foreground">
              Next zero-day in <span className="font-mono text-foreground">{untilMidnight(now)}</span>
            </p>
          </section>
        ) : (
          <section className="card-surface p-4 text-sm text-muted-foreground">
            <Copy className="mb-2 size-4" aria-hidden />
            Same puzzle for everyone today. Finish it to get a spoiler-free result to share with your team.
          </section>
        )}
      </aside>
    </div>
  );
}
