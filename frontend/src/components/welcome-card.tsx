"use client";

import { useEffect, useState } from "react";
import { GitCommitHorizontal, MousePointerClick, ShieldCheck, X } from "lucide-react";

import { Button } from "@/components/ui/button";

const KEY = "zeroday:welcome-dismissed";

const STEPS = [
  {
    icon: GitCommitHorizontal,
    title: "Push code as usual",
    text: "Every push to a connected Python repo is reviewed automatically in about 30 seconds.",
  },
  {
    icon: ShieldCheck,
    title: "Get a pass, warn or fail",
    text: "The result appears as a GitHub check. Confirmed critical or high issues block the merge.",
  },
  {
    icon: MousePointerClick,
    title: "Open a push to fix it",
    text: "See exactly where the problem is, how attacker input reaches it, and how to fix it.",
  },
];

/** First-visit explainer; dismissal is remembered per browser. */
export function WelcomeCard() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    try {
      setVisible(localStorage.getItem(KEY) !== "1");
    } catch {
      setVisible(true);
    }
  }, []);
  if (!visible) return null;
  const dismiss = () => {
    setVisible(false);
    try {
      localStorage.setItem(KEY, "1");
    } catch {
      /* storage unavailable: dismiss for this visit only */
    }
  };
  return (
    <section className="card-surface relative overflow-hidden border-2 border-dashed border-foreground/40 p-5" aria-label="How it works">
      <Button variant="ghost" size="icon" className="absolute right-2 top-2" onClick={dismiss} aria-label="Dismiss">
        <X className="size-4" />
      </Button>
      <div className="eyebrow relative">Safety briefing</div>
      <h2 className="relative font-display text-3xl font-extrabold uppercase leading-none">How scoring works</h2>
      <ol className="relative mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
        {STEPS.map((s, i) => (
          <li key={s.title} className="flex gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-[4px] border-2 border-foreground bg-brand text-brand-foreground">
              <s.icon className="size-4" aria-hidden />
            </span>
            <div>
              <div className="text-sm font-medium">
                <span className="mr-1.5 font-display text-lg font-black">{i + 1}</span>
                {s.title}
              </div>
              <p className="mt-0.5 text-sm text-muted-foreground">{s.text}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
