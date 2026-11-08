import { cn } from "@/lib/utils";

/**
 * Scoreboard numerals: each digit sits on its own split-flap tile and flips in on load.
 * The full value stays readable as one string for assistive tech.
 */
export function FlipNumber({
  value,
  size = "md",
  className,
  tileClassName,
}: {
  value: number | string;
  size?: "sm" | "md" | "lg";
  className?: string;
  tileClassName?: string;
}) {
  const text = String(value);
  const dims = {
    sm: "h-9 min-w-6 px-1 text-3xl",
    md: "h-14 min-w-9 px-1.5 text-5xl",
    lg: "h-20 min-w-13 px-2 text-7xl",
  }[size];
  return (
    <span className={cn("inline-flex gap-1 [perspective:400px]", className)} aria-label={text} role="img">
      {text.split("").map((ch, i) => (
        <span
          key={`${i}-${ch}`}
          aria-hidden
          className={cn(
            "relative grid place-items-center overflow-hidden rounded-[4px] bg-foreground font-display font-black leading-none text-background tabular-nums",
            dims,
            tileClassName,
          )}
        >
          <span className="flip-digit" style={{ "--d": i } as React.CSSProperties}>
            {ch}
          </span>
          {/* the split line across the middle of the flap */}
          <span className="pointer-events-none absolute inset-x-0 top-1/2 h-px bg-background/25" />
        </span>
      ))}
    </span>
  );
}
