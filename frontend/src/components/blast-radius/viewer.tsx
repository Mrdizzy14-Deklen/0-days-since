"use client";

import { useMemo, useState } from "react";
import {
  ArrowRight,
  Crosshair,
  FileCode,
  GitCommitHorizontal,
  Import,
  Route,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
  X,
} from "lucide-react";

import { RichText } from "@/components/rich-text";
import { SeverityBadge } from "@/components/status";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { baseName, seriesColor, shortSymbol, sinkLabel } from "@/lib/format";
import type { BlastRadius, Finding, GraphNode, IncidentModule } from "@/lib/types";
import { cn } from "@/lib/utils";

import {
  NODE_H,
  NODE_W,
  buildFlows,
  defaultFlow,
  edgeKey,
  layoutGraph,
  type Flow,
  type PlacedNode,
} from "./layout";

const ROLE_LABEL: Record<string, string> = {
  seed: "Changed",
  upstream: "Calls in",
  downstream: "Called",
};

function EntryBadge({ node }: { node: GraphNode }) {
  const route = [node.http_methods.join(","), node.route_path].filter(Boolean).join(" ");
  return (
    <span className="inline-flex h-5 items-center gap-1 rounded bg-[var(--series-1)]/15 px-1.5 text-[10px] font-medium text-foreground">
      <Route className="size-3 text-[var(--series-1)]" aria-hidden />
      <span className="max-w-[120px] truncate font-mono">{route || node.framework || "entry"}</span>
    </span>
  );
}

function SinkBadge({ kind, tainted }: { kind: string; tainted: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 rounded px-1.5 text-[10px] font-medium",
        tainted ? "bg-critical text-white" : "bg-muted text-foreground ring-1 ring-inset ring-border",
      )}
    >
      <Crosshair className="size-3" aria-hidden />
      {sinkLabel(kind)}
      {tainted && <span className="sr-only">(reachable by tainted data)</span>}
    </span>
  );
}

function NodeCard({
  node,
  fileColor,
  onFlow,
  dimmed,
  compromised,
  onHover,
}: {
  node: PlacedNode;
  fileColor: string;
  onFlow: boolean;
  dimmed: boolean;
  compromised: boolean;
  onHover: (id: string | null) => void;
}) {
  const sinkKinds = [...new Map(node.sinks.map((s) => [s.kind, s])).values()];
  return (
    <div
      className={cn(
        "absolute flex flex-col justify-between rounded-lg border bg-card px-2.5 py-2 text-left shadow-sm transition-[opacity,box-shadow] duration-200",
        node.role === "seed" && "border-dashed border-foreground/40",
        onFlow && "border-solid border-critical shadow-[0_0_0_3px_color-mix(in_oklab,var(--status-critical)_25%,transparent)]",
        compromised && !onFlow && "bg-[color-mix(in_oklab,var(--status-critical)_6%,var(--card))]",
        dimmed ? "opacity-30" : "opacity-100",
      )}
      style={{ left: node.x, top: node.y, width: NODE_W, height: NODE_H }}
      onMouseEnter={() => onHover(node.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(node.id)}
      onBlur={() => onHover(null)}
      tabIndex={0}
      aria-label={`${node.qualname} in ${node.file_path} line ${node.lineno}, ${ROLE_LABEL[node.role]}`}
    >
      <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
        <span className="size-2 shrink-0 rounded-full" style={{ background: fileColor }} aria-hidden />
        <span className="truncate font-mono">
          {node.file_path}:{node.lineno}
        </span>
        <span className="ml-auto shrink-0 uppercase tracking-wide">
          {ROLE_LABEL[node.role]}
          {node.role !== "seed" && node.hop ? ` ·${node.hop}` : ""}
        </span>
      </div>
      <div className="truncate font-mono text-[13px] font-semibold" title={node.qualname}>
        {node.qualname === "<module>" ? `${baseName(node.file_path)} (module)` : node.qualname}
      </div>
      <div className="flex min-h-5 flex-wrap items-center gap-1 overflow-hidden">
        {node.role === "seed" && (
          <span className="inline-flex h-5 items-center gap-1 rounded bg-muted px-1.5 text-[10px] font-medium">
            <GitCommitHorizontal className="size-3" aria-hidden /> changed
          </span>
        )}
        {node.is_entry_point && <EntryBadge node={node} />}
        {sinkKinds.map((s) => (
          <SinkBadge key={s.kind} kind={s.kind} tainted={node.sinks.some((x) => x.kind === s.kind && x.tainted)} />
        ))}
      </div>
    </div>
  );
}

function FlowTrace({ flow, byId }: { flow: Flow; byId: Map<string, GraphNode> }) {
  const steps =
    flow.steps ??
    flow.nodes.map((id, i) => {
      const n = byId.get(id);
      return {
        file: n?.file_path ?? id.split(":")[0],
        line: n?.lineno ?? 0,
        symbol: id,
        role: (i === 0 ? "source" : i === flow.nodes.length - 1 ? "sink" : "propagator") as
          | "source"
          | "sink"
          | "propagator",
        snippet: "",
      };
    });
  const roleTitle = { source: "Entry point (user input)", propagator: "Passes through", sink: "Dangerous call" } as const;
  return (
    <ol className="flex flex-col gap-2 md:flex-row md:items-stretch">
      {steps.map((s, i) => {
        const node = byId.get(s.symbol);
        return (
          <li key={`${s.symbol}-${i}`} className="flex min-w-0 flex-1 flex-col gap-2 md:flex-row md:items-center">
            <div
              className={cn(
                "min-w-0 flex-1 rounded-lg border p-3",
                s.role === "sink" && "border-critical/50 bg-critical/5",
              )}
            >
              <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {s.role === "source" ? (
                  <Route className="size-3" aria-hidden />
                ) : s.role === "sink" ? (
                  <Crosshair className="size-3 text-critical" aria-hidden />
                ) : (
                  <Waypoints className="size-3" aria-hidden />
                )}
                {roleTitle[s.role]}
                {s.role === "source" && node?.route_path && (
                  <span className="normal-case tracking-normal">
                    · {node.http_methods.join(",")} {node.route_path}
                  </span>
                )}
              </div>
              <div className="mt-1 truncate font-mono text-sm font-semibold">{shortSymbol(s.symbol)}</div>
              <div className="truncate font-mono text-xs text-muted-foreground">
                {s.file}
                {s.line ? `:${s.line}` : ""}
              </div>
              {s.snippet && (
                <pre className="mt-2 overflow-x-auto rounded bg-muted px-2 py-1.5 font-mono text-[11px] leading-relaxed">
                  <code>{s.snippet}</code>
                </pre>
              )}
              {s.role === "source" && node && node.sources.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {node.sources.map((src) => (
                    <span key={src} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">
                      {src.replace(/^route_param:/, "param ")}
                    </span>
                  ))}
                </div>
              )}
            </div>
            {i < steps.length - 1 && (
              <ArrowRight className="mx-auto size-4 shrink-0 rotate-90 text-critical md:rotate-0" aria-hidden />
            )}
          </li>
        );
      })}
    </ol>
  );
}

function IncidentScope({
  scope,
  dependents,
  fileColors,
  focusFile,
  onFocus,
}: {
  scope: IncidentModule[];
  dependents: string[];
  fileColors: Map<string, string>;
  focusFile: string | null;
  onFocus: (f: string | null) => void;
}) {
  const compromised = scope.filter((m) => m.compromised).length;
  const roleWord: Record<string, string> = { seed: "changed", upstream: "calls the change", downstream: "called by the change" };
  return (
    <aside className="card-surface self-start overflow-hidden" aria-labelledby="scope-title">
      <header className="border-b px-4 py-3">
        <h3 id="scope-title" className="font-semibold">
          Affected files
        </h3>
        <p className="text-xs text-muted-foreground">
          {compromised > 0
            ? `${compromised} of ${scope.length} files sit on a confirmed attack path`
            : `${scope.length} files are reachable from this change; none are compromised`}
        </p>
      </header>
      <ul className="divide-y">
        {scope.map((m) => {
          const active = focusFile === m.file_path;
          return (
            <li key={m.file_path}>
              <button
                type="button"
                onClick={() => onFocus(active ? null : m.file_path)}
                aria-pressed={active}
                className={cn(
                  "w-full px-4 py-2.5 text-left transition-colors hover:bg-muted/50",
                  active && "bg-muted",
                )}
              >
                <div className="flex items-center gap-2">
                  <span
                    className="size-2 shrink-0 rounded-full"
                    style={{ background: fileColors.get(m.file_path) }}
                    aria-hidden
                  />
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{m.file_path}</span>
                  {m.compromised ? (
                    <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-medium">
                      <ShieldAlert className="size-3.5 text-critical" aria-hidden /> On attack path
                    </span>
                  ) : (
                    <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-muted-foreground">
                      <ShieldCheck className="size-3.5" aria-hidden /> Reachable
                    </span>
                  )}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-2 gap-y-0.5 pl-4 text-[11px] text-muted-foreground">
                  <span>{m.roles.map((r) => roleWord[r] ?? r).join(" · ")}</span>
                  <span>
                    {m.symbols} {m.symbols === 1 ? "symbol" : "symbols"}
                  </span>
                  {m.entry_points > 0 && <span>{m.entry_points} entry</span>}
                  {m.sinks.length > 0 && (
                    <span className="text-foreground/80">sinks: {m.sinks.map(sinkLabel).join(", ")}</span>
                  )}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
      {dependents.length > 0 && (
        <div className="border-t px-4 py-3">
          <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
            <Import className="size-3.5" aria-hidden /> Other modules that import this code
          </div>
          <div className="flex flex-wrap gap-1">
            {dependents.map((d) => (
              <span key={d} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                {d}
              </span>
            ))}
          </div>
        </div>
      )}
    </aside>
  );
}

/**
 * Cross-File Blast-Radius Incident Viewer: the 2-hop call-graph slice around the changed
 * symbols, laid out entry -> modified function -> sink, with selectable taint flows and the
 * incident scope (which modules sit on a verified attack path).
 */
export function BlastRadiusViewer({
  radius,
  vulnerabilities,
  scope,
}: {
  radius: Partial<BlastRadius>;
  vulnerabilities: Finding[];
  scope: IncidentModule[];
}) {
  const flows = useMemo(() => buildFlows(radius, vulnerabilities), [radius, vulnerabilities]);
  const layout = useMemo(() => layoutGraph(radius, flows), [radius, flows]);
  const byId = useMemo(() => new Map((radius.nodes ?? []).map((n) => [n.id, n])), [radius.nodes]);
  const [flowId, setFlowId] = useState<string | null>(() => defaultFlow(flows)?.id ?? null);
  const [hover, setHover] = useState<string | null>(null);
  const [focusFile, setFocusFile] = useState<string | null>(null);

  const flow = flows.find((f) => f.id === flowId) ?? null;
  const flowNodes = new Set(flow?.nodes ?? []);
  const flowEdges = new Set(flow ? flow.nodes.slice(1).map((v, i) => edgeKey(flow.nodes[i], v)) : []);
  const compromisedFiles = new Set(scope.filter((m) => m.compromised).map((m) => m.file_path));

  const files = useMemo(
    () => [...new Set([...(radius.impacted_files ?? []), ...layout.nodes.map((n) => n.file_path)])].sort(),
    [radius.impacted_files, layout.nodes],
  );
  // Slots 1-7 for file identity (slot 8 is red and would read as "critical" here).
  const fileColors = useMemo(
    () => new Map(files.map((f, i) => [f, i < 7 ? seriesColor(i) : seriesColor(99)])),
    [files],
  );

  const neighbors = useMemo(() => {
    if (!hover) return null;
    const s = new Set([hover]);
    for (const e of layout.edges) {
      if (e.source === hover) s.add(e.target);
      if (e.target === hover) s.add(e.source);
    }
    return s;
  }, [hover, layout.edges]);

  const isDimmed = (n: GraphNode) =>
    (focusFile !== null && n.file_path !== focusFile) || (neighbors !== null && !neighbors.has(n.id));

  if (layout.nodes.length === 0) {
    return (
      <div className="rounded-xl border bg-card p-8 text-center text-sm text-muted-foreground">
        No Python symbols were touched by this push, so there is no blast radius to show.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="min-w-0 space-y-4">
        {flows.length > 0 && (
          <div className="flex flex-wrap items-center gap-2" role="radiogroup" aria-label="Attack paths">
            <span className="text-xs font-medium text-muted-foreground">Attack paths</span>
            {flows.map((f) => (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={f.id === flowId}
                onClick={() => setFlowId(f.id === flowId ? null : f.id)}
                className={cn(
                  "inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors",
                  f.id === flowId ? "border-critical bg-critical/10" : "hover:bg-muted",
                )}
              >
                {f.severity && <SeverityBadge severity={f.severity} className="h-4 text-[9px]" />}
                <span className="truncate"><RichText text={f.label} /></span>
                {f.crossFile && (
                  <span className="shrink-0 rounded bg-muted px-1 text-[10px] text-muted-foreground">
                    cross-file
                  </span>
                )}
                {!f.status && !f.tainted && (
                  <span className="shrink-0 text-[10px] text-muted-foreground">input doesn&apos;t reach it</span>
                )}
                {f.status === "rejected" && (
                  <span className="shrink-0 text-[10px] text-muted-foreground">dismissed</span>
                )}
              </button>
            ))}
          </div>
        )}

        <div className="relative overflow-x-auto rounded-xl border bg-[color-mix(in_oklab,var(--muted)_40%,var(--card))] [background-image:radial-gradient(var(--border)_1px,transparent_1px)] [background-size:16px_16px]">
          <div className="relative" style={{ width: layout.width, height: layout.height }}>
            <svg
              width={layout.width}
              height={layout.height}
              className="absolute inset-0"
              aria-hidden
            >
              <defs>
                <marker id="br-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--chart-muted)" />
                </marker>
                <marker id="br-arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--status-critical)" />
                </marker>
              </defs>
              {layout.edges.map((e) => {
                const hot = flowEdges.has(e.key);
                const faded =
                  (neighbors && !(neighbors.has(e.source) && neighbors.has(e.target))) ||
                  (focusFile && byId.get(e.source)?.file_path !== focusFile && byId.get(e.target)?.file_path !== focusFile);
                return (
                  <path
                    key={e.key}
                    d={e.d}
                    fill="none"
                    stroke={hot ? "var(--status-critical)" : "var(--chart-muted)"}
                    strokeWidth={hot ? 2.5 : 1.5}
                    strokeOpacity={faded ? 0.15 : hot ? 1 : 0.7}
                    strokeDasharray={!hot && (e.confidence < 0.6 || e.synthetic) ? "4 4" : undefined}
                    className={hot ? "taint-flow" : undefined}
                    markerEnd={`url(#${hot ? "br-arrow-hot" : "br-arrow"})`}
                  />
                );
              })}
            </svg>
            {layout.nodes.map((n) => (
              <NodeCard
                key={n.id}
                node={n}
                fileColor={fileColors.get(n.file_path) ?? seriesColor(99)}
                onFlow={flowNodes.has(n.id)}
                dimmed={isDimmed(n)}
                compromised={compromisedFiles.has(n.file_path)}
                onHover={setHover}
              />
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <svg width="22" height="6" aria-hidden><line x1="0" y1="3" x2="22" y2="3" stroke="var(--chart-muted)" strokeWidth="1.5" /></svg>
            call
          </span>
          <span className="inline-flex items-center gap-1.5">
            <svg width="22" height="6" aria-hidden><line x1="0" y1="3" x2="22" y2="3" stroke="var(--chart-muted)" strokeWidth="1.5" strokeDasharray="4 4" /></svg>
            likely call (inferred)
          </span>
          <span className="inline-flex items-center gap-1.5">
            <svg width="22" height="6" aria-hidden><line x1="0" y1="3" x2="22" y2="3" stroke="var(--status-critical)" strokeWidth="2.5" strokeDasharray="8 4" /></svg>
            selected attack path
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-3 w-5 rounded border border-dashed border-foreground/40" aria-hidden />
            changed in this push
          </span>
          <span className="inline-flex items-center gap-1.5">
            <FileCode className="size-3" aria-hidden /> dot color = file it lives in
          </span>
          {focusFile && (
            <button
              type="button"
              onClick={() => setFocusFile(null)}
              className="ml-auto inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-foreground hover:bg-muted"
            >
              <X className="size-3" aria-hidden /> Showing {baseName(focusFile)}
            </button>
          )}
        </div>

        {flow && (
          <section aria-label="Selected attack path" className="card-surface p-4">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold">Attack path, step by step</h3>
              {flow.rule && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">{flow.rule}</span>
                  </TooltipTrigger>
                  <TooltipContent>Rule that reported this path</TooltipContent>
                </Tooltip>
              )}
              <span className="text-xs text-muted-foreground">
                {flow.crossFile ? "Crosses files" : "Within one file"}
                {flow.tainted ? " · user input reaches the dangerous call" : " · user input does not reach the dangerous call"}
              </span>
            </div>
            <FlowTrace flow={flow} byId={byId} />
          </section>
        )}
      </div>

      <IncidentScope
        scope={scope}
        dependents={radius.dependent_modules ?? []}
        fileColors={fileColors}
        focusFile={focusFile}
        onFocus={setFocusFile}
      />
    </div>
  );
}
