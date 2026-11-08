"use client";

import { useState } from "react";
import { Check, Copy, Share2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { dayNumber, lastDays, personalShareText, teamShareText, type SharePush } from "@/lib/share";
import type { Developer } from "@/lib/types";
import { cn } from "@/lib/utils";

const TILE: Record<string, string> = {
  "🟩": "bg-[#0ca30c]",
  "🟨": "bg-[#e3a008]",
  "🟥": "bg-[#d03b3b]",
  "⬜": "bg-muted border-2 border-border",
};

/** Splits a line like "🟩🟨⬜ name" into its squares (emoji are multi-code-unit). */
function squaresOf(line: string): string[] {
  return Array.from(line).filter((ch) => ch in TILE);
}

/**
 * "Share" button + dialog with a Wordle-style preview. The text is built on the client so
 * the day boundaries follow the viewer's time zone.
 */
function ShareButton({
  build,
  label = "Share",
  heading,
}: {
  build: (now: Date) => string;
  label?: string;
  heading: string;
}) {
  const [text, setText] = useState("");
  const [copied, setCopied] = useState(false);
  const days = lastDays(new Date());
  const rows = text
    .split("\n")
    .filter((l) => squaresOf(l).length >= 7)
    .map((l) => ({ squares: squaresOf(l), name: l.replace(/^[^\p{L}@]+/u, "").trim() }));

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success("Copied. Paste it in Slack, Teams or anywhere.");
      setTimeout(() => setCopied(false), 1800);
    } catch {
      toast.error("Couldn't copy automatically. Select the text and copy it.");
    }
  }

  return (
    <Dialog onOpenChange={(open) => open && setText(build(new Date()))}>
      <DialogTrigger asChild>
        <Button className="border-2 border-foreground bg-brand font-display text-base font-bold uppercase tracking-wide text-brand-foreground shadow-[3px_3px_0_var(--foreground)] hover:bg-brand hover:brightness-95">
          <Share2 className="size-4" /> {label}
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-display text-3xl font-black uppercase leading-none">
            {heading} #{dayNumber()}
          </DialogTitle>
          <DialogDescription>
            Spoiler-free: only squares and scores, never code or vulnerability details.
          </DialogDescription>
        </DialogHeader>

        <div className="rounded-md border-2 border-foreground bg-card p-4">
          <div className="mb-2 grid grid-cols-[repeat(7,1.75rem)] gap-1.5 pl-0 text-center font-mono text-[10px] text-muted-foreground">
            {days.map((d) => (
              <span key={d.toISOString()}>{d.toLocaleDateString("en-US", { weekday: "narrow" })}</span>
            ))}
          </div>
          <ul className="space-y-1.5">
            {rows.map((r, i) => (
              <li key={i} className="flex items-center gap-3">
                <span className="grid grid-cols-[repeat(7,1.75rem)] gap-1.5">
                  {r.squares.map((sq, j) => (
                    <span
                      key={j}
                      className={cn("flip-digit size-7 rounded-[3px]", TILE[sq])}
                      style={{ "--d": i * 7 + j } as React.CSSProperties}
                      aria-hidden
                    />
                  ))}
                </span>
                {rows.length > 1 && <span className="truncate font-mono text-xs">{r.name}</span>}
              </li>
            ))}
          </ul>
        </div>

        <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
          {text}
        </pre>
        <Button onClick={copy} size="lg" className="w-full font-display text-lg font-bold uppercase">
          {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Copy result"}
        </Button>
      </DialogContent>
    </Dialog>
  );
}

export function TeamShareButton(props: {
  title: string;
  developers: Developer[];
  pushes: SharePush[];
  daysSince: number | null;
  record: number | null;
}) {
  return (
    <ShareButton
      heading="Team board"
      label="Share the board"
      build={(now) => teamShareText({ ...props, now })}
    />
  );
}

export function PersonalShareButton(props: {
  developer: Developer;
  rank: number | null;
  teamSize: number | null;
  pushes: SharePush[];
}) {
  return (
    <ShareButton heading="My week" label="Share my week" build={(now) => personalShareText({ ...props, now })} />
  );
}
