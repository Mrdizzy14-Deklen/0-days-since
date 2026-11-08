"use client";

import { useEffect, useState } from "react";

import { absoluteTime, relativeTime } from "@/lib/format";

function shortDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
}

/** Relative timestamp that renders the absolute time on the server, then ticks on the client. */
export function RelativeTime({ iso, className }: { iso: string | null; className?: string }) {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);
  return (
    <time dateTime={iso ?? undefined} title={absoluteTime(iso)} className={className}>
      {now === null ? shortDate(iso) : relativeTime(iso, now)}
    </time>
  );
}
