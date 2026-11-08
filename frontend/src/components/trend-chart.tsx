"use client";

import { useMemo, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from "recharts";

import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { MAX_COMPOSITE, MAX_CRAFT, MAX_SECURITY, seriesColor, signed } from "@/lib/format";
import type { Developer, ScorePoint } from "@/lib/types";
import { cn } from "@/lib/utils";

type Metric = "composite" | "security" | "craft";
type Range = "7" | "14" | "30";
type View = "chart" | "table";

const METRIC_MAX: Record<Metric, number> = {
  composite: MAX_COMPOSITE,
  security: MAX_SECURITY,
  craft: MAX_CRAFT,
};
const METRIC_LABEL: Record<Metric, string> = {
  composite: "Composite",
  security: "Security",
  craft: "Craft",
};

interface Row {
  t: number;
  pushes: { login: string; delta: number }[];
  [login: string]: number | { login: string; delta: number }[] | undefined;
}

const dateFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const dateTimeFmt = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
});

/**
 * Builds a carry-forward table: one row per snapshot time, each developer's latest value at
 * or before it (scores only change on a push, so the lines are drawn as steps).
 */
function buildRows(
  series: Record<string, ScorePoint[]>,
  metric: Metric,
  since: number,
  now: number,
): Row[] {
  const events: { t: number; login: string; value: number; delta: number }[] = [];
  for (const [login, points] of Object.entries(series)) {
    for (const p of points) {
      events.push({ t: new Date(p.t).getTime(), login, value: p[metric], delta: p.delta });
    }
  }
  events.sort((a, b) => a.t - b.t);
  const current: Record<string, number> = {};
  const rows: Row[] = [];
  // Values before the window start become the opening level of each line.
  for (const e of events) if (e.t < since) current[e.login] = e.value;
  if (Object.keys(current).length) rows.push({ t: since, pushes: [], ...current });
  for (const e of events) {
    if (e.t < since) continue;
    current[e.login] = e.value;
    const last = rows.at(-1);
    if (last && last.t === e.t) {
      last[e.login] = e.value;
      last.pushes.push({ login: e.login, delta: e.delta });
    } else {
      rows.push({ t: e.t, pushes: [{ login: e.login, delta: e.delta }], ...current });
    }
  }
  if (rows.length) rows.push({ t: now, pushes: [], ...current });
  return rows;
}

function ChartTooltip({
  active,
  payload,
  label,
  names,
  metric,
}: TooltipContentProps<number, string> & { names: Record<string, string>; metric: Metric }) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as Row;
  const entries = payload
    .filter((p) => typeof p.value === "number")
    .sort((a, b) => (b.value as number) - (a.value as number));
  return (
    <div className="min-w-48 rounded-lg border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="mb-1.5 text-muted-foreground">{dateTimeFmt.format(new Date(label as number))} UTC</div>
      <ul className="space-y-1">
        {entries.map((p) => {
          const pushed = row.pushes.find((x) => x.login === p.dataKey);
          return (
            <li key={String(p.dataKey)} className="flex items-center gap-2">
              <span className="h-0.5 w-3 rounded-full" style={{ background: p.color }} aria-hidden />
              <span className="font-mono font-semibold tabular-nums text-foreground">{p.value}</span>
              <span className="truncate text-muted-foreground">{names[String(p.dataKey)]}</span>
              {pushed && (
                <span className="ml-auto font-mono text-muted-foreground">
                  push {signed(pushed.delta)}
                </span>
              )}
            </li>
          );
        })}
      </ul>
      <div className="mt-1.5 text-[10px] text-muted-foreground">{METRIC_LABEL[metric]} score</div>
    </div>
  );
}

export function TrendChart({
  series,
  developers,
  now,
}: {
  series: Record<string, ScorePoint[]>;
  developers: Developer[];
  /** Server render time, so the chart's right edge is stable across hydration. */
  now: number;
}) {
  const [metric, setMetric] = useState<Metric>("composite");
  const [range, setRange] = useState<Range>("30");
  const [view, setView] = useState<View>("chart");
  const [focus, setFocus] = useState<string | null>(null);

  // Color follows the developer (stable id order), never their rank.
  const byId = useMemo(() => [...developers].sort((a, b) => a.id - b.id), [developers]);
  const colors = useMemo(
    () => Object.fromEntries(byId.map((d, i) => [d.github_login, seriesColor(i)])),
    [byId],
  );
  const names = useMemo(
    () => Object.fromEntries(developers.map((d) => [d.github_login, d.display_name])),
    [developers],
  );
  const since = now - Number(range) * 86_400_000;
  const rows = useMemo(() => buildRows(series, metric, since, now), [series, metric, since, now]);
  const logins = byId.map((d) => d.github_login).filter((l) => series[l]?.length);
  const max = METRIC_MAX[metric];

  const table = logins
    .map((login) => {
      const pts = series[login] ?? [];
      const inRange = pts.filter((p) => new Date(p.t).getTime() >= since);
      const before = pts.filter((p) => new Date(p.t).getTime() < since).at(-1);
      const start = before?.[metric] ?? inRange[0]?.[metric] ?? null;
      const end = pts.at(-1)?.[metric] ?? null;
      return { login, start, end, pushes: inRange.length };
    })
    .sort((a, b) => (b.end ?? 0) - (a.end ?? 0));

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          value={metric}
          onValueChange={(v) => v && setMetric(v as Metric)}
          aria-label="Score"
        >
          {(Object.keys(METRIC_LABEL) as Metric[]).map((m) => (
            <ToggleGroupItem key={m} value={m} className="px-3">
              {METRIC_LABEL[m]}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          value={range}
          onValueChange={(v) => v && setRange(v as Range)}
          aria-label="Time range"
        >
          {(["7", "14", "30"] as Range[]).map((r) => (
            <ToggleGroupItem key={r} value={r} className="px-3">
              {r}d
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          value={view}
          onValueChange={(v) => v && setView(v as View)}
          aria-label="View"
          className="ml-auto"
        >
          <ToggleGroupItem value="chart" className="px-3">
            Chart
          </ToggleGroupItem>
          <ToggleGroupItem value="table" className="px-3">
            Table
          </ToggleGroupItem>
        </ToggleGroup>
      </div>

      {/* Legend: line keys, click to focus one developer (others recede). */}
      <ul className="mt-4 flex flex-wrap gap-x-4 gap-y-1.5" aria-label="Developers">
        {logins.map((login) => (
          <li key={login}>
            <button
              type="button"
              onClick={() => setFocus((f) => (f === login ? null : login))}
              aria-pressed={focus === login}
              className={cn(
                "flex items-center gap-1.5 rounded text-xs transition-opacity",
                focus && focus !== login ? "opacity-40" : "opacity-100",
              )}
            >
              <span className="h-0.5 w-4 rounded-full" style={{ background: colors[login] }} aria-hidden />
              <span className="text-muted-foreground hover:text-foreground">{names[login] ?? login}</span>
            </button>
          </li>
        ))}
      </ul>

      {view === "chart" ? (
        <div className="mt-3 h-72 w-full" role="img" aria-label={`${METRIC_LABEL[metric]} score over the last ${range} days by developer`}>
          {rows.length === 0 ? (
            <p className="grid h-full place-items-center text-sm text-muted-foreground">
              No scored pushes in this range.
            </p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={rows} margin={{ top: 8, right: 24, bottom: 0, left: -4 }}>
                <CartesianGrid vertical={false} stroke="var(--chart-grid)" strokeWidth={1} />
                <XAxis
                  dataKey="t"
                  type="number"
                  scale="time"
                  domain={[since, now]}
                  tickFormatter={(t: number) => dateFmt.format(new Date(t))}
                  tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
                  axisLine={{ stroke: "var(--chart-axis)" }}
                  tickLine={false}
                  minTickGap={32}
                />
                <YAxis
                  domain={[0, max]}
                  tickCount={6}
                  tick={{ fill: "var(--chart-muted)", fontSize: 10, fontFamily: "var(--font-code)" }}
                  axisLine={false}
                  tickLine={false}
                  width={44}
                />
                <Tooltip
                  cursor={{ stroke: "var(--chart-muted)", strokeWidth: 1 }}
                  content={(props) => (
                    <ChartTooltip {...(props as TooltipContentProps<number, string>)} names={names} metric={metric} />
                  )}
                  isAnimationActive={false}
                />
                {logins.map((login) => (
                  <Line
                    key={login}
                    dataKey={login}
                    name={names[login] ?? login}
                    type="stepAfter"
                    stroke={colors[login]}
                    strokeWidth={focus === login ? 3 : 2}
                    strokeOpacity={focus && focus !== login ? 0.18 : 1}
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--card)" }}
                    connectNulls={false}
                    isAnimationActive={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      ) : (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="py-2 font-medium">Developer</th>
                <th className="py-2 text-right font-medium">{range}d ago</th>
                <th className="py-2 text-right font-medium">Now</th>
                <th className="py-2 text-right font-medium">Change</th>
                <th className="py-2 text-right font-medium">Pushes</th>
              </tr>
            </thead>
            <tbody className="font-mono tabular-nums">
              {table.map((r) => (
                <tr key={r.login} className="border-b last:border-0">
                  <td className="py-2 font-sans">
                    <span className="mr-2 inline-block h-0.5 w-3 rounded-full align-middle" style={{ background: colors[r.login] }} aria-hidden />
                    {names[r.login] ?? r.login}
                  </td>
                  <td className="py-2 text-right">{r.start ?? "—"}</td>
                  <td className="py-2 text-right">{r.end ?? "—"}</td>
                  <td className="py-2 text-right">
                    {r.start !== null && r.end !== null ? signed(r.end - r.start) : "—"}
                  </td>
                  <td className="py-2 text-right">{r.pushes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
