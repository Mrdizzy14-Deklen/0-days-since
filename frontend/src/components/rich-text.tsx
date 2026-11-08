import { Fragment } from "react";

/** Renders `backticked` spans from scanner/AI text as inline code. Everything else is plain text. */
export function RichText({ text }: { text: string | null | undefined }) {
  if (!text) return null;
  const parts = text.split(/(`[^`\n]+`)/g);
  return (
    <>
      {parts.map((p, i) =>
        p.length > 2 && p.startsWith("`") && p.endsWith("`") ? (
          <code key={i} className="rounded bg-muted px-1 py-px font-mono text-[0.85em] text-foreground">
            {p.slice(1, -1)}
          </code>
        ) : (
          <Fragment key={i}>{p}</Fragment>
        ),
      )}
    </>
  );
}
