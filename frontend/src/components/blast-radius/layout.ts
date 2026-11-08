import { shortSymbol, sinkLabel } from "@/lib/format";
import type {
  BlastRadius,
  Finding,
  FindingStatus,
  GraphEdge,
  GraphNode,
  Severity,
  TaintStep,
} from "@/lib/types";

export const NODE_W = 236;
export const NODE_H = 86;
export const COL_GAP = 92;
export const ROW_GAP = 18;
export const PAD = 20;

/** A selectable entry -> ... -> sink flow: a finding's taint trace or a graph taint path. */
export interface Flow {
  id: string;
  label: string;
  nodes: string[];
  steps: TaintStep[] | null;
  severity: Severity | null;
  status: FindingStatus | null;
  counted: boolean;
  crossFile: boolean;
  tainted: boolean;
  entryRoute: string | null;
  sinkKinds: string[];
  rule: string | null;
}

export function buildFlows(radius: Partial<BlastRadius>, vulns: Finding[]): Flow[] {
  const flows: Flow[] = [];
  const seen = new Set<string>();
  const byId = new Map((radius.nodes ?? []).map((n) => [n.id, n]));

  for (const f of vulns) {
    const steps = f.taint_flow ?? [];
    if (steps.length < 2) continue;
    const nodes = steps.map((s) => s.symbol);
    const key = nodes.join(">");
    if (seen.has(key)) continue;
    seen.add(key);
    const sink = byId.get(nodes.at(-1)!);
    flows.push({
      id: `finding-${f.id}`,
      label: f.title,
      nodes,
      steps,
      severity: f.severity,
      status: f.status,
      counted: f.counted_in_score,
      crossFile: new Set(steps.map((s) => s.file)).size > 1,
      tainted: f.status !== "rejected",
      entryRoute: byId.get(nodes[0])?.route_path ?? null,
      sinkKinds: [...new Set((sink?.sinks ?? []).map((s) => s.kind))],
      rule: f.rule_id,
    });
  }

  (radius.taint_paths ?? []).forEach((p, i) => {
    const key = p.nodes.join(">");
    if (seen.has(key) || p.nodes.length < 2) return;
    seen.add(key);
    const entry = p.entry_route ?? shortSymbol(p.nodes[0]);
    flows.push({
      id: `path-${i}`,
      label: `${entry} → ${shortSymbol(p.nodes.at(-1)!)}${p.sink_kinds.length ? ` (${p.sink_kinds.map(sinkLabel).join(", ")})` : ""}`,
      nodes: p.nodes,
      steps: null,
      severity: null,
      status: null,
      counted: false,
      crossFile: p.cross_file,
      tainted: p.args_flow && p.sink_tainted,
      entryRoute: p.entry_route,
      sinkKinds: p.sink_kinds,
      rule: null,
    });
  });
  return flows;
}

/** The flow shown first: a scored finding, else a fully tainted path, else anything. */
export function defaultFlow(flows: Flow[]): Flow | null {
  return (
    flows.find((f) => f.counted) ??
    flows.find((f) => f.status === "verified") ??
    flows.find((f) => f.tainted && f.crossFile) ??
    flows.find((f) => f.tainted) ??
    flows[0] ??
    null
  );
}

export interface PlacedNode extends GraphNode {
  x: number;
  y: number;
  layer: number;
}

export interface PlacedEdge extends GraphEdge {
  key: string;
  d: string;
  synthetic: boolean;
}

export interface GraphLayout {
  nodes: PlacedNode[];
  edges: PlacedEdge[];
  width: number;
  height: number;
}

export const edgeKey = (u: string, v: string) => `${u}->${v}`;

/**
 * Layered left-to-right layout: callers on the left, callees (and sinks) on the right.
 * Layers are the longest call path from a root after breaking cycles; rows are ordered by
 * file, then refined with a barycenter pass to reduce edge crossings.
 */
export function layoutGraph(radius: Partial<BlastRadius>, flows: Flow[]): GraphLayout {
  const all = radius.nodes ?? [];
  const flowPairs: [string, string][] = flows.flatMap((f) =>
    f.nodes.slice(1).map((v, i) => [f.nodes[i], v] as [string, string]),
  );
  const referenced = new Set<string>([
    ...(radius.edges ?? []).flatMap((e) => [e.source, e.target]),
    ...flowPairs.flat(),
  ]);
  // Module pseudo-nodes are noise unless something actually points at them.
  const nodes = all.filter((n) => n.kind !== "module" || referenced.has(n.id));
  const ids = new Set(nodes.map((n) => n.id));

  const edgeMap = new Map<string, GraphEdge & { synthetic: boolean }>();
  for (const e of radius.edges ?? []) {
    if (ids.has(e.source) && ids.has(e.target) && e.source !== e.target) {
      const k = edgeKey(e.source, e.target);
      if (!edgeMap.has(k)) edgeMap.set(k, { ...e, synthetic: false });
    }
  }
  for (const [u, v] of flowPairs) {
    const k = edgeKey(u, v);
    if (ids.has(u) && ids.has(v) && u !== v && !edgeMap.has(k)) {
      edgeMap.set(k, { source: u, target: v, kind: "flow", lineno: 0, confidence: 1, synthetic: true });
    }
  }
  const edges = [...edgeMap.values()];

  // --- break cycles (DFS from callers first) --------------------------------------------
  const out = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of edges) out.get(e.source)!.push(e.target);
  const roleRank = { upstream: 0, seed: 1, downstream: 2 } as const;
  const order = [...nodes].sort(
    (a, b) =>
      roleRank[a.role] - roleRank[b.role] ||
      (a.role === "upstream" ? b.hop - a.hop : a.hop - b.hop) ||
      a.file_path.localeCompare(b.file_path) ||
      a.lineno - b.lineno,
  );
  const state = new Map<string, 0 | 1 | 2>();
  const back = new Set<string>();
  const visit = (u: string) => {
    state.set(u, 1);
    for (const v of out.get(u)!) {
      const s = state.get(v) ?? 0;
      if (s === 1) back.add(edgeKey(u, v));
      else if (s === 0) visit(v);
    }
    state.set(u, 2);
  };
  for (const n of order) if (!state.get(n.id)) visit(n.id);

  // --- longest-path layering on the DAG --------------------------------------------------
  const dag = edges.filter((e) => !back.has(edgeKey(e.source, e.target)));
  const indeg = new Map<string, number>(nodes.map((n) => [n.id, 0]));
  for (const e of dag) indeg.set(e.target, indeg.get(e.target)! + 1);
  const layer = new Map<string, number>(nodes.map((n) => [n.id, 0]));
  const queue = order.filter((n) => indeg.get(n.id) === 0).map((n) => n.id);
  const dagOut = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of dag) dagOut.get(e.source)!.push(e.target);
  while (queue.length) {
    const u = queue.shift()!;
    for (const v of dagOut.get(u)!) {
      layer.set(v, Math.max(layer.get(v)!, layer.get(u)! + 1));
      indeg.set(v, indeg.get(v)! - 1);
      if (indeg.get(v) === 0) queue.push(v);
    }
  }

  // Unconnected nodes sit with their role: callers left, changed code middle, callees right.
  const connected = new Set(edges.flatMap((e) => [e.source, e.target]));
  const connectedSeeds = nodes.filter((n) => n.role === "seed" && connected.has(n.id));
  const seedLayer = connectedSeeds.length
    ? Math.min(...connectedSeeds.map((n) => layer.get(n.id)!))
    : nodes.some((n) => n.role === "upstream")
      ? 1
      : 0;
  const maxLayer = Math.max(0, ...[...layer.values()]);
  for (const n of nodes) {
    if (connected.has(n.id)) continue;
    layer.set(n.id, n.role === "upstream" ? 0 : n.role === "seed" ? seedLayer : Math.max(maxLayer, seedLayer + 1));
  }
  // Compress empty columns.
  const used = [...new Set(layer.values())].sort((a, b) => a - b);
  const remap = new Map(used.map((l, i) => [l, i]));
  for (const n of nodes) layer.set(n.id, remap.get(layer.get(n.id)!)!);

  // --- ordering within columns -----------------------------------------------------------
  const columns: GraphNode[][] = Array.from({ length: used.length }, () => []);
  for (const n of order) columns[layer.get(n.id)!].push(n);
  for (const col of columns) col.sort((a, b) => a.file_path.localeCompare(b.file_path) || a.lineno - b.lineno);
  const preds = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of edges) preds.get(e.target)!.push(e.source);
  for (let sweep = 0; sweep < 2; sweep++) {
    const pos = new Map<string, number>();
    columns.forEach((col) => col.forEach((n, i) => pos.set(n.id, i)));
    for (let c = 1; c < columns.length; c++) {
      const bary = new Map(
        columns[c].map((n, i) => {
          const ps = preds.get(n.id)!.filter((p) => layer.get(p)! < c);
          return [n.id, ps.length ? ps.reduce((s, p) => s + pos.get(p)!, 0) / ps.length : i];
        }),
      );
      columns[c].sort((a, b) => bary.get(a.id)! - bary.get(b.id)!);
      columns[c].forEach((n, i) => pos.set(n.id, i));
    }
  }

  // --- coordinates -------------------------------------------------------------------------
  const tallest = Math.max(1, ...columns.map((c) => c.length));
  const height = PAD * 2 + tallest * NODE_H + (tallest - 1) * ROW_GAP;
  const width = PAD * 2 + columns.length * NODE_W + Math.max(0, columns.length - 1) * COL_GAP;
  const placed = new Map<string, PlacedNode>();
  columns.forEach((col, c) => {
    const colH = col.length * NODE_H + (col.length - 1) * ROW_GAP;
    const top = (height - colH) / 2;
    col.forEach((n, i) => {
      placed.set(n.id, {
        ...n,
        layer: c,
        x: PAD + c * (NODE_W + COL_GAP),
        y: top + i * (NODE_H + ROW_GAP),
      });
    });
  });

  const placedEdges: PlacedEdge[] = edges.map((e) => {
    const s = placed.get(e.source)!;
    const t = placed.get(e.target)!;
    return { ...e, key: edgeKey(e.source, e.target), d: edgePath(s, t) };
  });

  return { nodes: [...placed.values()], edges: placedEdges, width, height };
}

function edgePath(s: PlacedNode, t: PlacedNode): string {
  const sy = s.y + NODE_H / 2;
  const ty = t.y + NODE_H / 2;
  if (t.layer > s.layer) {
    const sx = s.x + NODE_W;
    const tx = t.x;
    const dx = (tx - sx) / 2;
    return `M ${sx} ${sy} C ${sx + dx} ${sy}, ${tx - dx} ${ty}, ${tx} ${ty}`;
  }
  if (t.layer === s.layer) {
    // Same column: loop out to the right and come back in.
    const x = s.x + NODE_W;
    const bulge = 36 + Math.min(60, Math.abs(ty - sy) / 4);
    return `M ${x} ${sy} C ${x + bulge} ${sy}, ${x + bulge} ${ty}, ${x} ${ty}`;
  }
  // Back edge (recursion / cycle): leave on the left, arrive on the right.
  const sx = s.x;
  const tx = t.x + NODE_W;
  return `M ${sx} ${sy} C ${sx - 60} ${sy}, ${tx + 60} ${ty}, ${tx} ${ty}`;
}
