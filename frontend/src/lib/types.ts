/** Response shapes of the 0 Days Since FastAPI backend (`backend/app/api.py`). */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Conclusion = "success" | "neutral" | "failure" | "cancelled" | "skipped";
export type ScanStatus = "queued" | "in_progress" | "completed" | "failed" | "skipped";
export type FindingStatus = "verified" | "rejected" | "unverified";

export interface TeamRef {
  id: number;
  slug: string;
  name: string;
}

export interface TeamSummary extends TeamRef {
  account: string | null;
  installed: boolean;
  /** Listed in the backend's PUBLIC_TEAMS (the read-only demo). */
  public?: boolean;
}

export interface Developer {
  id: number;
  rank: number | null;
  github_login: string;
  display_name: string;
  avatar_url: string | null;
  role: string;
  composite_score: number;
  security_score: number;
  craft_score: number;
  total_pushes: number;
  faulty_pushes: number;
  fault_ratio: number;
  weighted_fault_sum: number;
  clean_streak: number;
  best_clean_streak: number;
  top_cwe: string | null;
  top_smell: string | null;
  cwe_counts: Record<string, number>;
  smell_counts: Record<string, number>;
  craft_breakdown: {
    docs: number | null;
    readability: number | null;
    type_hints: number | null;
  };
  last_push_at: string | null;
}

export interface Leaderboard {
  team: TeamRef;
  developers: Developer[];
}

export interface TeamStats {
  total_pushes: number;
  faulty_pushes: number;
  blocked_merges: number;
  false_positives_rejected: number;
  top_cwes: { cwe: string; count: number }[];
  repositories: {
    id: number;
    full_name: string;
    files: number;
    symbols: number;
    edges: number;
    last_scanned_sha: string | null;
  }[];
}

export interface Push {
  id: number;
  event_type: string;
  ref: string | null;
  branch: string;
  before_sha: string | null;
  after_sha: string;
  short_sha: string;
  pr_number: number | null;
  commit_message: string | null;
  commit_url: string | null;
  status: ScanStatus;
  conclusion: Conclusion | null;
  points_delta: number;
  composite_before: number | null;
  composite_after: number | null;
  security_before: number | null;
  security_after: number | null;
  craft_before: number | null;
  craft_after: number | null;
  craft_push_score: number | null;
  docs_score: number | null;
  readability_score: number | null;
  type_hints_score: number | null;
  vulns: { critical: number; high: number; medium: number; low: number };
  is_faulty: boolean;
  ai_summary: string | null;
  llm_model: string | null;
  files_changed: string[];
  additions: number;
  deletions: number;
  error: string | null;
  created_at: string | null;
  completed_at: string | null;
  developer: { id: number; github_login: string; avatar_url: string | null } | null;
  repository: { id: number; full_name: string } | null;
}

export interface TaintStep {
  file: string;
  line: number;
  symbol: string;
  role: "source" | "propagator" | "sink";
  snippet: string;
}

export interface Finding {
  id: number;
  category: "security" | "quality";
  source: "static" | "ai";
  status: FindingStatus;
  severity: Severity;
  rule_id: string;
  cwe: string | null;
  title: string;
  description: string | null;
  remediation: string | null;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  symbol_node_id: string | null;
  confidence: number | null;
  verifier_reasoning: string | null;
  taint_flow: TaintStep[] | null;
  counted_in_score: boolean;
}

export interface SinkSite {
  kind: string;
  call: string;
  lineno: number;
  tainted: boolean;
  direct_source?: boolean;
  tainted_by?: string[];
  unsafe_construction?: boolean;
}

export type NodeRole = "seed" | "upstream" | "downstream";

export interface GraphNode {
  id: string;
  name: string;
  qualname: string;
  kind: string;
  file_path: string;
  lineno: number;
  end_lineno: number | null;
  role: NodeRole;
  hop: number;
  is_entry_point: boolean;
  framework: string | null;
  route_path: string | null;
  http_methods: string[];
  sources: string[];
  sinks: SinkSite[];
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: string;
  lineno: number;
  confidence: number;
}

export interface TaintPath {
  nodes: string[];
  files: string[];
  cross_file: boolean;
  entry_route: string | null;
  entry_sources: string[];
  sink_kinds: string[];
  sink_tainted: boolean;
  args_flow: boolean;
}

export interface BlastRadius {
  seeds: string[];
  upstream: Record<string, number>;
  downstream: Record<string, number>;
  nodes: GraphNode[];
  edges: GraphEdge[];
  entry_points: string[];
  sinks: (SinkSite & { node: string; file_path: string })[];
  taint_paths: TaintPath[];
  impacted_files: string[];
  dependent_modules: string[];
}

export interface IncidentModule {
  file_path: string;
  roles: NodeRole[];
  symbols: number;
  sinks: string[];
  entry_points: number;
  compromised: boolean;
}

export interface SymbolQuality {
  node_id: string;
  file_path: string;
  lineno: number;
  complexity: number;
  nesting: number;
  length: number;
  type_hint_coverage: number;
  has_docstring: boolean;
  readability: number;
}

export interface QualityMetrics {
  graded_symbols: number;
  documentable: number;
  documented: number;
  docstring_coverage: number;
  type_hint_coverage: number;
  comment_density: number;
  avg_complexity: number;
  max_complexity: number;
  long_functions: number;
  deep_nesting: number;
  long_lines: number;
  naming_violations: number;
  best_practice_violations: Record<string, number>;
  docs_score: number;
  readability_score: number;
  type_hints_score: number;
  craft_score: number;
  per_symbol?: SymbolQuality[];
  ai_notes?: string;
}

export interface PushDetail {
  team: TeamRef | null;
  push: Push;
  vulnerabilities: Finding[];
  quality_findings: Finding[];
  quality_metrics: QualityMetrics | null;
  blast_radius: Partial<BlastRadius>;
  incident_scope: IncidentModule[];
  agent?: AgentTrace;
}

export interface ScorePoint {
  t: string;
  composite: number;
  security: number;
  craft: number;
  delta: number;
  push_event_id: number | null;
}

export interface Trends {
  days: number;
  series: Record<string, ScorePoint[]>;
}

export interface DeveloperDetail {
  team: TeamRef | null;
  developer: Developer;
  history: ScorePoint[];
  recent_pushes: Push[];
}

export interface AgentStep {
  step: number;
  thought: string;
  action: string;
  args: Record<string, unknown>;
  observation: string;
  /** How long the model took to choose this step (newer scans only). */
  ms?: number;
}

export interface AgentInvestigation {
  plan: string[];
  steps: AgentStep[];
  model: string | null;
  finished: boolean;
  error: string | null;
}

export interface AgentFix {
  finding_title: string;
  rule_id: string;
  cwe: string | null;
  file_paths: string[];
  explanation: string;
  commit_message: string;
  diff: string;
  verified: boolean;
  verification: string;
  pr_number: number | null;
  pr_url: string | null;
  error: string | null;
}

/** Wall-clock milliseconds per scan phase (newer scans only). */
export interface ScanTimings {
  agent_ms?: number;
  one_shot_ms?: number;
  skeptic_ms?: number;
  ai_total_ms?: number;
  fixes_ms?: number;
  analysis_ms?: number;
}

export interface AgentTrace {
  investigation?: AgentInvestigation | null;
  fixes?: AgentFix[];
  timings?: ScanTimings;
}

export interface DailyPoint {
  day: string;
  pushes: number;
  faulty_pushes: number;
  net_points: number;
  avg_composite: number;
  min_composite: number;
  max_composite: number;
}

export interface TeamDaily {
  days: number;
  source: "timescale_continuous_aggregate" | "computed";
  series: DailyPoint[];
}

export interface DiscordIntegration {
  connected: boolean;
  /** Masked: the webhook token never leaves the backend. */
  webhook: string | null;
  include_warnings: boolean;
  last_sent_at: string | null;
  last_error: string | null;
}

export interface Integrations {
  can_edit: boolean;
  discord: DiscordIntegration;
}
