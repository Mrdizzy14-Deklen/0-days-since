import { cn } from "@/lib/utils";

/** Mark: a hi-vis safety plate with a stencil zero. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "grid size-8 place-items-center rounded-[5px] border-2 border-foreground bg-brand font-stencil text-xl leading-none text-brand-foreground shadow-[2px_2px_0_var(--foreground)]",
        className,
      )}
      aria-hidden
    >
      0
    </span>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-display text-xl font-extrabold uppercase leading-none tracking-wide", className)}>
      ZeroDay<span className="text-muted-foreground">·</span>Score
    </span>
  );
}
