import { cn } from "@/lib/utils";

/**
 * Horizontal meter for a bounded score (Security /700, Craft /300, sub-scores /100).
 * The number is always printed next to the bar so the fill is never the only cue.
 */
export function ScoreBar({
  label,
  value,
  max,
  color,
  threshold,
  compact = false,
  className,
}: {
  label: string;
  value: number | null;
  max: number;
  color: string;
  /** Optional marker (e.g. the craft neutral-check threshold). */
  threshold?: number;
  compact?: boolean;
  className?: string;
}) {
  const v = value ?? 0;
  const ratio = Math.max(0, Math.min(1, v / max));
  return (
    <div className={cn("min-w-0", className)}>
      <div className="flex items-baseline justify-between gap-2 text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono tabular-nums">
          <span className="text-foreground">{value === null ? "—" : Math.round(v)}</span>
          <span className="text-muted-foreground">/{max}</span>
        </span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={Math.round(v)}
        className={cn("relative mt-1 overflow-hidden rounded-full bg-muted", compact ? "h-1.5" : "h-2")}
      >
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${ratio * 100}%`, background: color }}
        />
        {threshold !== undefined && (
          <div
            aria-hidden
            className="absolute inset-y-0 w-px bg-foreground/50"
            style={{ left: `${(threshold / max) * 100}%` }}
          />
        )}
      </div>
    </div>
  );
}
