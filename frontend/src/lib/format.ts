import type { Conclusion, Push, ScanStatus, Severity } from "@/lib/types";

export const MAX_COMPOSITE = 1000;
export const MAX_SECURITY = 700;
export const MAX_CRAFT = 300;
export const CRAFT_WARN_THRESHOLD = 180;

/** Fixed categorical slots; identity is assigned by stable id order, never by rank. */
export const SERIES = Array.from({ length: 8 }, (_, i) => `var(--series-${i + 1})`);
export const SERIES_OVERFLOW = "var(--chart-muted)";

export function seriesColor(index: number): string {
  return index >= 0 && index < SERIES.length ? SERIES[index] : SERIES_OVERFLOW;
}

export const CWE_NAMES: Record<string, string> = {
  "CWE-22": "Path traversal",
  "CWE-78": "OS command injection",
  "CWE-79": "Cross-site scripting",
  "CWE-88": "Argument injection",
  "CWE-89": "SQL injection",
  "CWE-390": "Swallowed error",
  "CWE-396": "Overbroad except",
  "CWE-94": "Code injection",
  "CWE-95": "Eval injection",
  "CWE-200": "Information exposure",
  "CWE-295": "Improper cert validation",
  "CWE-306": "Missing authentication",
  "CWE-327": "Broken crypto",
  "CWE-328": "Weak hash",
  "CWE-347": "Unverified JWT",
  "CWE-377": "Insecure temp file",
  "CWE-489": "Debug mode enabled",
  "CWE-502": "Unsafe deserialization",
  "CWE-601": "Open redirect",
  "CWE-639": "IDOR",
  "CWE-798": "Hardcoded credentials",
  "CWE-862": "Missing authorization",
  "CWE-918": "SSRF",
  "CWE-1336": "Template injection",
  "CWE-1427": "Prompt injection",
};

export function cweName(cwe: string | null | undefined): string | null {
  if (!cwe) return null;
  return CWE_NAMES[cwe] ?? null;
}

export const SINK_LABELS: Record<string, string> = {
  sql: "SQL",
  command: "Shell",
  code_exec: "Code exec",
  deserialization: "Deserialize",
  file: "File I/O",
  network: "Outbound HTTP",
  template: "Template",
  redirect: "Redirect",
  db_orm: "ORM",
  crypto: "Crypto",
  log: "Log",
};

export function sinkLabel(kind: string): string {
  return SINK_LABELS[kind] ?? kind.replace(/_/g, " ");
}

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export type CheckState = "passed" | "warned" | "failed" | "scanning" | "errored" | "skipped";

/** Collapse the backend's status + conclusion into the three-state check shown in the UI. */
export function checkState(status: ScanStatus, conclusion: Conclusion | null): CheckState {
  if (status === "queued" || status === "in_progress") return "scanning";
  if (status === "failed") return "errored";
  if (status === "skipped" || conclusion === "skipped") return "skipped";
  if (conclusion === "failure") return "failed";
  if (conclusion === "neutral") return "warned";
  if (conclusion === "success") return "passed";
  return "skipped";
}

export function pushCheckState(p: Pick<Push, "status" | "conclusion">): CheckState {
  return checkState(p.status, p.conclusion);
}

/** "app.services.billing:BillingService.search_invoices" -> "BillingService.search_invoices" */
export function shortSymbol(nodeId: string): string {
  const [, qual] = nodeId.split(":", 2);
  if (!qual) return nodeId;
  return qual === "<module>" ? `${nodeId.split(":")[0]} (module)` : qual;
}

export function moduleOf(nodeId: string): string {
  return nodeId.split(":", 1)[0];
}

export function baseName(path: string): string {
  return path.split("/").pop() ?? path;
}

export function signed(n: number): string {
  return n > 0 ? `+${n}` : `${n}`;
}

export function pct(n: number, digits = 0): string {
  return `${(n * 100).toFixed(digits)}%`;
}

const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

export function relativeTime(iso: string | null, now = Date.now()): string {
  if (!iso) return "—";
  const seconds = (new Date(iso).getTime() - now) / 1000;
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return RTF.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

export function absoluteTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  });
}

export function modelLabel(model: string | null): string | null {
  if (!model) return null;
  if (model === "demo-replay") return "Scripted demo replay";
  return model;
}

export function appInstallUrl(): string | null {
  const slug = process.env.NEXT_PUBLIC_GITHUB_APP_SLUG;
  return slug ? `https://github.com/apps/${slug}/installations/new` : null;
}

/** The two composite components keep one identity everywhere (bars, stacked history). */
export const SECURITY_COLOR = SERIES[0];
export const CRAFT_COLOR = SERIES[1];
