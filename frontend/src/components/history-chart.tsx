"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts";

import { CRAFT_COLOR, MAX_COMPOSITE, SECURITY_COLOR, signed } from "@/lib/format";
import type { ScorePoint } from "@/lib/types";

const dateFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

interface Row {
  t: number;
  security: number;
  craft: number;
  composite: number;
  delta: number | null;
}

function HistoryTooltip({ active, payload }: TooltipContentProps<number, string>) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as Row;
  return (
    <div className="min-w-44 rounded-lg border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="mb-1.5 text-muted-foreground">{dateFmt.format(new Date(row.t))}</div>
      <div className="flex items-center gap-2">
        <span className="font-mono text-sm font-semibold tabular-nums">{row.composite}</span>
        <span className="text-muted-foreground">composite</span>
        {row.delta !== null && (
          <span className="ml-auto font-mono text-muted-foreground">push {signed(row.delta)}</span>
        )}
      </div>
      {(
        [
          ["security", "Security", SECURITY_COLOR],
          ["craft", "Craft", CRAFT_COLOR],
        ] as const
      ).map(([k, label, color]) => (
        <div key={k} className="mt-1 flex items-center gap-2">
          <span className="size-2 rounded-sm" style={{ background: color }} aria-hidden />
          <span className="font-mono font-semibold tabular-nums">{row[k]}</span>
          <span className="text-muted-foreground">{label}</span>
        </div>
      ))}
    </div>
  );
}

/** Composite over time as a stack: Security (0-700) + Craft (0-300) = Composite (0-1000). */
export function HistoryChart({ history, now }: { history: ScorePoint[]; now: number }) {
  const rows: Row[] = history.map((p) => ({
    t: new Date(p.t).getTime(),
    security: p.security,
    craft: p.craft,
    composite: p.composite,
    delta: p.delta,
  }));
  if (rows.length) rows.push({ ...rows[rows.length - 1], t: now, delta: null });
  if (rows.length === 0) {
    return <p className="grid h-56 place-items-center text-sm text-muted-foreground">No scored pushes yet.</p>;
  }
  return (
    <div>
      <ul className="mb-2 flex gap-4 text-xs text-muted-foreground" aria-label="Legend">
        <li className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm" style={{ background: SECURITY_COLOR }} aria-hidden /> Security (of 700)
        </li>
        <li className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm" style={{ background: CRAFT_COLOR }} aria-hidden /> Craft (of 300)
        </li>
      </ul>
      <div className="h-56" role="img" aria-label="Score history: security and craft stacked to the composite score">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={rows} margin={{ top: 8, right: 24, bottom: 0, left: -4 }}>
            <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
            <XAxis
              dataKey="t"
              type="number"
              scale="time"
              domain={["dataMin", "dataMax"]}
              tickFormatter={(t: number) => dateFmt.format(new Date(t))}
              tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
              axisLine={{ stroke: "var(--chart-axis)" }}
              tickLine={false}
              minTickGap={32}
            />
            <YAxis
              domain={[0, MAX_COMPOSITE]}
              tickCount={6}
              tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
              axisLine={false}
              tickLine={false}
              width={44}
            />
            <Tooltip
              cursor={{ stroke: "var(--chart-muted)", strokeWidth: 1 }}
              content={(props) => <HistoryTooltip {...(props as TooltipContentProps<number, string>)} />}
              isAnimationActive={false}
            />
            <Area
              dataKey="security"
              stackId="score"
              type="stepAfter"
              stroke={SECURITY_COLOR}
              strokeWidth={2}
              fill={SECURITY_COLOR}
              fillOpacity={0.25}
              isAnimationActive={false}
            />
            <Area
              dataKey="craft"
              stackId="score"
              type="stepAfter"
              stroke={CRAFT_COLOR}
              strokeWidth={2}
              fill={CRAFT_COLOR}
              fillOpacity={0.25}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
