import { DailyPuzzleGame } from "@/components/daily-puzzle";

export function PlayPageBody() {
  return (
    <div className="reveal space-y-6">
      <div style={{ "--i": 0 } as React.CSSProperties}>
        <h1 className="font-display text-6xl font-black uppercase leading-none tracking-tight">Daily Zero-Day</h1>
        <p className="mt-2 text-muted-foreground">One vulnerable snippet a day, the same for everyone. Find the bug in three tries.</p>
      </div>
      <div style={{ "--i": 1 } as React.CSSProperties}>
        <DailyPuzzleGame />
      </div>
    </div>
  );
}
