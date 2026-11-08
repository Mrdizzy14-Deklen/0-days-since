import { cn } from "@/lib/utils";

const FACE =
  "absolute inset-0 grid place-items-center rounded-[5px] border-2 border-foreground leading-none [backface-visibility:hidden]";

/**
 * Mark: a hi-vis safety plate with a stencil zero. When the team's days-since count is known,
 * hovering (or focusing) the plate flips it over to show that number, like the board.
 */
export function LogoMark({ days = null, className }: { days?: number | null; className?: string }) {
  const flips = days !== null;
  const digits = String(days ?? "");
  return (
    <span
      className={cn(
        "relative inline-block h-8 [perspective:300px]",
        digits.length > 2 ? "w-11" : digits.length > 1 ? "w-9" : "w-8",
        className,
      )}
      aria-hidden
    >
      <span
        className={cn(
          "absolute inset-0 rounded-[5px] shadow-[2px_2px_0_var(--foreground)] transition-transform duration-500 [transform-style:preserve-3d] motion-reduce:transition-none",
          flips && "group-hover/logo:[transform:rotateY(180deg)] group-focus-visible/logo:[transform:rotateY(180deg)]",
        )}
      >
        <span className={cn(FACE, "bg-brand font-stencil text-xl text-brand-foreground")}>0</span>
        {flips && (
          <span
            className={cn(FACE, "font-display text-xl font-black text-white [transform:rotateY(180deg)]")}
            style={{ background: (days ?? 0) > 0 ? "#0b7d2e" : "#b3261e" }}
          >
            {digits}
          </span>
        )}
      </span>
    </span>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-display text-xl font-extrabold uppercase leading-none tracking-wide", className)}>
      0 Days Since
    </span>
  );
}
