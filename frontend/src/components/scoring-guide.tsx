"use client";

import { BookOpen, Bot, CircleCheck, OctagonX, ShieldHalf, Sparkles, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { CRAFT_COLOR, SECURITY_COLOR } from "@/lib/format";

function Section({ title, icon: Icon, children }: { title: string; icon: React.ComponentType<{ className?: string }>; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <Icon className="size-4 text-brand-text" aria-hidden /> {title}
      </h3>
      <div className="space-y-2 text-sm leading-relaxed text-muted-foreground">{children}</div>
    </section>
  );
}

/** Plain-language explanation of the score, opened from the header on every page. */
export function ScoringGuide({ compact = false }: { compact?: boolean }) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="ghost" size={compact ? "icon" : "sm"} aria-label="How scoring works">
          <BookOpen className="size-4" />
          {!compact && <span className="hidden md:inline">How scoring works</span>}
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>How scoring works</SheetTitle>
          <SheetDescription>
            Every push to a connected Python repository is reviewed in about 30 seconds and adds
            to your score.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-7 px-4 pb-8">
          <div className="rounded-xl border p-4">
            <div className="text-xs text-muted-foreground">Your score, out of 1,000</div>
            <div className="mt-2 flex h-3 overflow-hidden rounded-full">
              <div style={{ width: "70%", background: SECURITY_COLOR }} />
              <div className="w-[2px] bg-card" />
              <div style={{ width: "30%", background: CRAFT_COLOR }} />
            </div>
            <div className="mt-2 flex justify-between text-xs">
              <span>
                <span className="font-mono font-semibold">700</span> Security
              </span>
              <span>
                <span className="font-mono font-semibold">300</span> Code craft
              </span>
            </div>
          </div>

          <Section title="Security (700 points)" icon={ShieldHalf}>
            <p>
              Each push with a confirmed vulnerability counts against you, weighted by how serious
              it is. Your security score is based on the <em>average</em> across all your pushes,
              so one mistake hurts but clean pushes earn it back.
            </p>
            <div className="overflow-hidden rounded-lg border text-xs">
              {[
                ["Critical", "1.0", "e.g. eval on user input, unpickling request data"],
                ["High", "0.7", "e.g. SQL or shell injection"],
                ["Medium", "0.4", "e.g. path traversal, SSRF"],
                ["Low", "0.15", "e.g. open redirect"],
              ].map(([sev, w, ex]) => (
                <div key={sev} className="flex items-baseline gap-3 border-b px-3 py-2 last:border-0">
                  <span className="w-14 font-medium text-foreground">{sev}</span>
                  <span className="w-8 font-mono text-foreground">{w}</span>
                  <span>{ex}</span>
                </div>
              ))}
            </div>
            <p className="rounded-lg bg-muted px-3 py-2 font-mono text-xs text-foreground">
              security = 700 × (1 − total weight ÷ pushes)
            </p>
            <p>
              Example: one High finding in your first push gives 700 × (1 − 0.7) = 210. After a
              clean second push it is 700 × (1 − 0.7 ÷ 2) = 455.
            </p>
          </Section>

          <Section title="Code craft (300 points)" icon={Sparkles}>
            <p>
              Three scores out of 100 for the functions you changed, averaged over all your pushes:
            </p>
            <ul className="list-disc space-y-1 pl-5">
              <li>
                <span className="text-foreground">Documentation</span>: docstrings on public
                functions
              </li>
              <li>
                <span className="text-foreground">Readability</span>: short functions, shallow
                nesting, clear names
              </li>
              <li>
                <span className="text-foreground">Type hints</span>: annotated parameters and
                return values
              </li>
            </ul>
          </Section>

          <Section title="What the GitHub check means" icon={CircleCheck}>
            <ul className="space-y-2">
              <li className="flex gap-2">
                <OctagonX className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
                <span>
                  <span className="font-medium text-foreground">Failed</span>: a critical or high
                  issue was confirmed. The merge is blocked until it is fixed.
                </span>
              </li>
              <li className="flex gap-2">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
                <span>
                  <span className="font-medium text-foreground">Warned</span>: only medium or low
                  issues, or code craft under 180/300. You can still merge.
                </span>
              </li>
              <li className="flex gap-2">
                <CircleCheck className="mt-0.5 size-4 shrink-0 text-good" aria-hidden />
                <span>
                  <span className="font-medium text-foreground">Passed</span>: nothing to fix.
                </span>
              </li>
            </ul>
          </Section>

          <Section title="Who reviews the code" icon={Bot}>
            <p>
              A code map follows user input across files to find where it reaches something
              dangerous, like a database query or a shell command. An AI reviewer then looks for
              logic bugs, and a second AI pass tries to prove each finding wrong.
            </p>
            <p>
              Findings it dismisses as false alarms don&apos;t count against you. Comments that
              try to talk the AI out of a finding are flagged instead.
            </p>
          </Section>
        </div>
      </SheetContent>
    </Sheet>
  );
}
