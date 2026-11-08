/** Plain-language helpers: tips, verdicts, rank movement and achievements. */

import { CRAFT_WARN_THRESHOLD, cweName, pushCheckState, type CheckState } from "@/lib/format";
import type { Developer, Finding, Push, ScorePoint, TeamStats } from "@/lib/types";

export const CWE_TIPS: Record<string, string> = {
  "CWE-22": "Resolve file paths and check they stay inside the allowed folder before opening them.",
  "CWE-78": "Pass an argument list to subprocess and never use shell=True with user input.",
  "CWE-79": "Let the template engine autoescape output; never mark user input as safe.",
  "CWE-88": "Pass user values as separate list arguments, never inside a command string.",
  "CWE-89": "Use parameterized queries; never build SQL with f-strings or string concatenation.",
  "CWE-94": "Never execute code built from user input.",
  "CWE-95": "Replace eval() with a lookup table or ast.literal_eval for plain literals.",
  "CWE-295": "Keep TLS certificate verification turned on (no verify=False).",
  "CWE-306": "Require authentication on every route that reads or changes data.",
  "CWE-328": "Use SHA-256 or better; for passwords use bcrypt or argon2.",
  "CWE-347": "Always verify JWT signatures and pin the allowed algorithms.",
  "CWE-377": "Create temp files with tempfile.NamedTemporaryFile or mkstemp.",
  "CWE-489": "Turn debug mode off outside local development.",
  "CWE-502": "Never unpickle untrusted data; use JSON for anything from users.",
  "CWE-601": "Only redirect to relative paths or an allow-list of hosts.",
  "CWE-639": "Check that the requested record belongs to the signed-in user.",
  "CWE-798": "Load secrets from environment variables or a secrets manager.",
  "CWE-918": "Allow-list outbound hosts and block private and metadata IP ranges.",
  "CWE-1336": "Never render templates that users can supply.",
  "CWE-1427": "Don't leave instructions for the AI reviewer in code or comments.",
};

export const SMELL_TIPS: Record<string, string> = {
  "Missing docstrings": "Add a one-line docstring to each public function saying what it does.",
  "Missing type hints": "Annotate parameters and return values so tools can catch mistakes.",
  "High complexity": "Split long chains of if/else into small, named helper functions.",
  "Deep nesting": "Return early instead of nesting; flatten loops inside conditions.",
  "Long functions": "Break functions over ~50 lines into smaller steps.",
  "Long lines": "Keep lines under 100 characters so diffs stay readable.",
  "PEP 8 naming": "Use snake_case for functions and variables, PascalCase for classes.",
  "Syntax errors": "Run the file locally before pushing; the scanner can't read broken code.",
  "Bare except": "Catch the specific exception you expect instead of a bare except.",
  "Swallowed exceptions": "Log or re-raise errors instead of silently passing.",
  "Mutable defaults": "Use None as the default and create the list or dict inside the function.",
  "Too many parameters": "Group related parameters into a dataclass or settings object.",
  "Wildcard imports": "Import the names you use explicitly instead of import *.",
  "Readability": "Smaller functions with clear names make reviews faster.",
};

export function smellTip(smell: string): string {
  return SMELL_TIPS[smell] ?? "Small, well-named, documented functions keep this score high.";
}

/** Rank change versus `days` ago (positive = moved up). null = no score back then. */
export function rankMovement(
  developers: Developer[],
  series: Record<string, ScorePoint[]>,
  now: number,
  days = 7,
): Record<string, number | null> {
  const cutoff = now - days * 86_400_000;
  const then: { login: string; score: number }[] = [];
  for (const d of developers) {
    const past = (series[d.github_login] ?? []).filter((p) => new Date(p.t).getTime() <= cutoff).at(-1);
    if (past) then.push({ login: d.github_login, score: past.composite });
  }
  then.sort((a, b) => b.score - a.score);
  const thenRank = new Map(then.map((x, i) => [x.login, i + 1]));
  // Compare only among developers who were ranked back then.
  const nowRanked = developers.filter((d) => thenRank.has(d.github_login));
  const nowRank = new Map(nowRanked.map((d, i) => [d.github_login, i + 1]));
  return Object.fromEntries(
    developers.map((d) => {
      const before = thenRank.get(d.github_login);
      const after = nowRank.get(d.github_login);
      return [d.github_login, before && after ? before - after : null];
    }),
  );
}

export interface Verdict {
  state: CheckState;
  title: string;
  detail: string;
}

function where(f: Finding): string {
  return `${f.file_path}${f.start_line ? `:${f.start_line}` : ""}`;
}

/** One-sentence explanation of the check result, for the top of the push page. */
export function pushVerdict(push: Push, vulns: Finding[]): Verdict {
  const state = pushCheckState(push);
  const counted = vulns.filter((f) => f.counted_in_score);
  const blocking = counted.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
  const name = (f: Finding) => cweName(f.cwe) ?? f.title;
  switch (state) {
    case "failed": {
      const first = blocking[0] ?? counted[0];
      const more = blocking.length > 1 ? ` and ${blocking.length - 1} more` : "";
      return {
        state,
        title: "Merge blocked",
        detail: first
          ? `${name(first)} in ${where(first)}${more}. Fix it and push again to pass the check.`
          : "A critical or high-severity issue was verified in this push.",
      };
    }
    case "warned": {
      if (counted.length) {
        const first = counted[0];
        return {
          state,
          title: "Passed with warnings",
          detail: `${counted.length} lower-severity ${counted.length === 1 ? "issue" : "issues"} to review, starting with ${name(first)} in ${where(first)}.`,
        };
      }
      return {
        state,
        title: "Passed with warnings",
        detail: `Code craft scored ${Math.round(push.craft_push_score ?? 0)}/300, below the ${CRAFT_WARN_THRESHOLD} bar. See the Code craft tab for quick wins.`,
      };
    }
    case "passed":
      return {
        state,
        title: "All clear",
        detail: `No verified vulnerabilities${push.craft_push_score !== null ? ` and code craft ${Math.round(push.craft_push_score)}/300` : ""}.`,
      };
    case "scanning":
      return {
        state,
        title: "Scanning…",
        detail: "Mapping the code and running the AI review. Results usually arrive in about 30 seconds.",
      };
    case "errored":
      return { state, title: "Scan didn't finish", detail: push.error ?? "The scanner hit an error." };
    default:
      return { state, title: "Not scored", detail: "This push had no Python changes to review." };
  }
}

export interface Achievement {
  id: string;
  label: string;
  detail: string;
}

export function achievements(d: Developer): Achievement[] {
  const out: Achievement[] = [];
  if (d.total_pushes > 0 && d.faulty_pushes === 0)
    out.push({ id: "clean", label: "Zero vulnerabilities", detail: "No verified security issue in any push" });
  if (d.best_clean_streak >= 3)
    out.push({ id: "streak", label: `${d.best_clean_streak}-push streak`, detail: "Longest run of clean pushes" });
  if ((d.craft_breakdown.type_hints ?? 0) >= 95)
    out.push({ id: "typed", label: "Fully typed", detail: "Type hints on almost every parameter and return" });
  if ((d.craft_breakdown.docs ?? 0) >= 85)
    out.push({ id: "docs", label: "Great docs", detail: "Most functions have docstrings" });
  if ((d.craft_breakdown.readability ?? 0) >= 95)
    out.push({ id: "readable", label: "Readable code", detail: "Low complexity and shallow nesting" });
  return out;
}

export interface FocusArea {
  kind: "security" | "craft" | "none";
  title: string;
  tip: string;
}

/** The single most useful thing this developer could improve. */
export function focusArea(d: Developer): FocusArea {
  if (d.top_cwe) {
    return {
      kind: "security",
      title: `Most of your lost points come from ${cweName(d.top_cwe) ?? d.top_cwe}`,
      tip: CWE_TIPS[d.top_cwe] ?? "Review the push pages for this weakness to see the fix.",
    };
  }
  const subs = [
    ["documentation", d.craft_breakdown.docs, "Add a one-line docstring to each public function."],
    ["readability", d.craft_breakdown.readability, "Keep functions short and shallow; return early instead of nesting."],
    ["type hints", d.craft_breakdown.type_hints, "Annotate parameters and return values."],
  ] as const;
  const weakest = subs
    .filter(([, v]) => v !== null)
    .sort((a, b) => (a[1] as number) - (b[1] as number))[0];
  if (weakest && (weakest[1] as number) < 90) {
    return {
      kind: "craft",
      title: `Your weakest craft area is ${weakest[0]} (${Math.round(weakest[1] as number)}/100)`,
      tip: weakest[2],
    };
  }
  return { kind: "none", title: "Nothing to fix right now", tip: "Keep pushing clean, documented code to hold your rank." };
}

export interface IncidentStats {
  /** Whole days since the most recent push with a confirmed vulnerability. */
  days: number;
  last: Push | null;
  /** Longest stretch without an incident within the loaded history, in days. */
  record: number;
}

const DAY_MS = 86_400_000;
const pushTime = (p: Push) => new Date(p.completed_at ?? p.created_at ?? 0).getTime();

/** "Days since last incident" for a team, from its recent pushes. null when nothing is scored. */
export function incidentStats(pushes: Push[], now: number): IncidentStats | null {
  const scored = pushes.filter((p) => p.status === "completed").sort((a, b) => pushTime(b) - pushTime(a));
  if (scored.length === 0) return null;
  const incidents = scored.filter((p) => p.is_faulty);
  const last = incidents[0] ?? null;
  const since = last ? pushTime(last) : pushTime(scored.at(-1)!);
  const edges = [pushTime(scored.at(-1)!), ...incidents.map(pushTime).sort((a, b) => a - b), now];
  let record = 0;
  for (let i = 1; i < edges.length; i++) record = Math.max(record, Math.floor((edges[i] - edges[i - 1]) / DAY_MS));
  return { days: Math.floor((now - since) / DAY_MS), last, record };
}

/** Team page title: the repository's name; teams with several repos fall back to the team name. */
export function pageTitle(stats: TeamStats | null, teamName: string): string {
  const repos = stats?.repositories ?? [];
  return repos.length === 1 ? (repos[0].full_name.split("/").pop() ?? teamName) : teamName;
}
