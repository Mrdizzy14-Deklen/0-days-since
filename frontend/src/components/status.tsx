import {
  CircleCheck,
  CircleSlash,
  Loader2,
  OctagonX,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";
import type { CheckState } from "@/lib/format";
import type { FindingStatus, Severity } from "@/lib/types";

const CHECK: Record<CheckState, { label: string; icon: LucideIcon; className: string }> = {
  passed: {
    label: "Passed",
    icon: CircleCheck,
    className: "text-good bg-good/10 ring-good/30",
  },
  warned: {
    label: "Warned",
    icon: TriangleAlert,
    className: "text-warning bg-warning/10 ring-warning/30",
  },
  failed: {
    label: "Failed",
    icon: OctagonX,
    className: "text-critical bg-critical/10 ring-critical/30",
  },
  scanning: {
    label: "Scanning",
    icon: Loader2,
    className: "text-muted-foreground bg-muted ring-border",
  },
  errored: {
    label: "Scan error",
    icon: CircleSlash,
    className: "text-muted-foreground bg-muted ring-border",
  },
  skipped: {
    label: "Not scored",
    icon: CircleSlash,
    className: "text-muted-foreground bg-muted ring-border",
  },
};

/** Check status: icon + label (status color never carries meaning alone). */
export function CheckBadge({ state, className }: { state: CheckState; className?: string }) {
  const { label, icon: Icon, className: tone } = CHECK[state];
  return (
    <span
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1 rounded-full px-2 text-xs font-medium ring-1 ring-inset",
        tone,
        className,
      )}
    >
      <Icon className={cn("size-3.5", state === "scanning" && "animate-spin")} aria-hidden />
      <span className="text-foreground">{label}</span>
    </span>
  );
}

const SEVERITY_TONE: Record<Severity, string> = {
  CRITICAL: "bg-critical text-white",
  HIGH: "bg-serious text-black",
  MEDIUM: "bg-warning text-black",
  LOW: "bg-muted text-foreground ring-1 ring-inset ring-border",
  INFO: "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-center rounded px-1.5 font-mono text-[10px] font-semibold tracking-wide",
        SEVERITY_TONE[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

const FINDING_STATUS: Record<FindingStatus, { label: string; icon: LucideIcon; tone: string }> = {
  verified: { label: "Verified", icon: ShieldAlert, tone: "text-critical" },
  rejected: { label: "Rejected by skeptic", icon: ShieldCheck, tone: "text-good" },
  unverified: { label: "Unverified", icon: ShieldQuestion, tone: "text-muted-foreground" },
};

export function FindingStatusLabel({ status }: { status: FindingStatus }) {
  const { label, icon: Icon, tone } = FINDING_STATUS[status];
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      <Icon className={cn("size-3.5", tone)} aria-hidden />
      {label}
    </span>
  );
}

/** Point change with direction carried by sign + arrow, not color alone. */
export function PointsDelta({
  value,
  className,
  suffix = "pts",
}: {
  value: number;
  className?: string;
  suffix?: string;
}) {
  const tone = value > 0 ? "text-delta-up" : value < 0 ? "text-delta-down" : "text-muted-foreground";
  const arrow = value > 0 ? "▲" : value < 0 ? "▼" : "•";
  return (
    <span className={cn("inline-flex items-baseline gap-1 font-mono tabular-nums", tone, className)}>
      <span aria-hidden className="text-[0.7em]">
        {arrow}
      </span>
      {value > 0 ? `+${value}` : value}
      {suffix && <span className="text-[0.75em] text-muted-foreground">{suffix}</span>}
    </span>
  );
}
