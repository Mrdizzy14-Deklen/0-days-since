"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts";

import type { DailyPoint } from "@/lib/types";

const dayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

interface Row {
  day: string;
  clean: number;
  faulty: number;
  net: number;
  avg: number;
}

function DayTooltip({ active, payload }: TooltipContentProps<number, string>) {
  if (!active || !payload?.length) return null;
  const r = payload[0].payload as Row;
  return (
    <div className="min-w-44 rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="mb-1 text-muted-foreground">{dayFmt.format(new Date(r.day))}</div>
      <div className="flex items-center gap-2">
        <span className="size-2.5 rounded-[2px] bg-[var(--status-good)]" aria-hidden />
        <span className="font-mono font-semibold">{r.clean}</span> clean
      </div>
      <div className="flex items-center gap-2">
        <span className="size-2.5 rounded-[2px] bg-[var(--status-critical)]" aria-hidden />
        <span className="font-mono font-semibold">{r.faulty}</span> with confirmed vulnerabilities
      </div>
      <div className="mt-1 border-t pt-1 text-muted-foreground">
        net <span className="font-mono text-foreground">{r.net > 0 ? `+${r.net}` : r.net}</span> pts · avg score{" "}
        <span className="font-mono text-foreground">{Math.round(r.avg)}</span>
      </div>
    </div>
  );
}

/** Pushes per day, split by outcome. Data comes from the team_daily_scores aggregate. */
export function DailyChart({ series }: { series: DailyPoint[] }) {
  const rows: Row[] = series.map((d) => ({
    day: d.day,
    clean: d.pushes - d.faulty_pushes,
    faulty: d.faulty_pushes,
    net: d.net_points,
    avg: d.avg_composite,
  }));
  if (rows.length === 0) {
    return <p className="grid h-48 place-items-center text-sm text-muted-foreground">No scored pushes in this period.</p>;
  }
  return (
    <div>
      <ul className="mb-3 flex gap-4 text-xs text-muted-foreground" aria-label="Legend">
        <li className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-[2px] bg-[var(--status-good)]" aria-hidden /> Clean pushes
        </li>
        <li className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-[2px] bg-[var(--status-critical)]" aria-hidden /> Confirmed vulnerabilities
        </li>
      </ul>
      <div className="h-56" role="img" aria-label="Pushes per day, clean versus with confirmed vulnerabilities">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 8, right: 24, bottom: 0, left: -12 }} barCategoryGap="25%">
            <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
            <XAxis
              dataKey="day"
              tickFormatter={(d: string) => dayFmt.format(new Date(d))}
              tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
              axisLine={{ stroke: "var(--chart-axis)" }}
              tickLine={false}
              minTickGap={24}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
              axisLine={false}
              tickLine={false}
              width={40}
            />
            <Tooltip cursor={{ fill: "var(--muted)", opacity: 0.6 }} content={(p) => <DayTooltip {...(p as TooltipContentProps<number, string>)} />} isAnimationActive={false} />
            <Bar dataKey="clean" stackId="d" fill="var(--status-good)" stroke="var(--card)" strokeWidth={2} isAnimationActive={false} />
            <Bar dataKey="faulty" stackId="d" fill="var(--status-critical)" stroke="var(--card)" strokeWidth={2} radius={[3, 3, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
