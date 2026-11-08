"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Inbox, Loader2, Search } from "lucide-react";
import { toast } from "sonner";

import { PushRow } from "@/components/push-row";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { pushCheckState, signed } from "@/lib/format";
import type { Push } from "@/lib/types";
import { cn } from "@/lib/utils";

type Connection = "connecting" | "live" | "reconnecting";
type StatusFilter = "all" | "failed" | "warned" | "passed";
const PAGE = 50;
const COMPACT_LIMIT = 8;

function notify(push: Push, router: ReturnType<typeof useRouter>) {
  const state = pushCheckState(push);
  if (state === "scanning") return;
  const who = push.developer?.github_login ?? "someone";
  const title = push.commit_message?.split("\n")[0] ?? push.short_sha;
  const opts = {
    description: `@${who} · ${signed(push.points_delta)} points`,
    action: { label: "View", onClick: () => router.push(`/pushes/${push.id}`) },
    duration: state === "failed" ? 12_000 : 6_000,
  };
  if (state === "failed") toast.error(`Merge blocked: ${title}`, opts);
  else if (state === "warned") toast.warning(`Passed with warnings: ${title}`, opts);
  else if (state === "passed") toast.success(`All clear: ${title}`, opts);
  else toast.info(title, opts);
}

function useMounted() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return mounted;
}

const dayKeyUtc = (iso: string | null) => (iso ?? "").slice(0, 10);
function dayKeyLocal(iso: string | null) {
  if (!iso) return "";
  const d = new Date(iso);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}
function dayLabel(iso: string | null, mounted: boolean): string {
  if (!iso) return "Earlier";
  const d = new Date(iso);
  const opts: Intl.DateTimeFormatOptions = { weekday: "long", month: "short", day: "numeric" };
  if (!mounted) return d.toLocaleDateString("en-US", { ...opts, timeZone: "UTC" });
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString("en-US", opts);
}

/**
 * Live Push & Incident Feed. Starts from the server-rendered list, then subscribes to the
 * backend SSE stream (through the authenticated /api/backend proxy) for new pushes and status
 * changes. New results raise an in-dashboard toast and refresh the server-rendered scores.
 */
export function PushFeed({
  slug,
  initial,
  variant = "compact",
  developers = [],
  viewerLogin = null,
}: {
  slug: string;
  initial: Push[];
  variant?: "compact" | "full";
  developers?: { login: string; name: string }[];
  viewerLogin?: string | null;
}) {
  const router = useRouter();
  const mounted = useMounted();
  const [pushes, setPushes] = useState<Push[]>(initial);
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const [conn, setConn] = useState<Connection>("connecting");
  const [loadingMore, setLoadingMore] = useState(false);
  const [exhausted, setExhausted] = useState(initial.length < PAGE);
  const [status, setStatus] = useState<StatusFilter>("all");
  const [author, setAuthor] = useState<string>("all");
  const [query, setQuery] = useState("");
  const maxId = useRef(initial.reduce((m, p) => Math.max(m, p.id), 0));

  useEffect(() => {
    const cursor = maxId.current ? `?last_event_id=${maxId.current}` : "";
    const es = new EventSource(`/api/backend/teams/${encodeURIComponent(slug)}/stream${cursor}`);
    es.addEventListener("ready", () => setConn("live"));
    es.addEventListener("open", () => setConn((c) => (c === "reconnecting" ? "live" : c)));
    es.addEventListener("error", () => setConn("reconnecting"));
    es.addEventListener("push", (ev) => {
      let push: Push;
      try {
        push = JSON.parse((ev as MessageEvent<string>).data) as Push;
      } catch {
        return;
      }
      maxId.current = Math.max(maxId.current, push.id);
      setPushes((list) => {
        const i = list.findIndex((p) => p.id === push.id);
        if (i === -1) return [push, ...list].sort((a, b) => b.id - a.id);
        const next = list.slice();
        next[i] = push;
        return next;
      });
      setFresh((s) => new Set(s).add(push.id));
      notify(push, router);
      if (push.status === "completed") router.refresh();
    });
    return () => es.close();
  }, [slug, router]);

  const loadMore = useCallback(async () => {
    const oldest = pushes.at(-1)?.id;
    if (!oldest) return;
    setLoadingMore(true);
    try {
      const res = await fetch(
        `/api/backend/teams/${encodeURIComponent(slug)}/pushes?limit=${PAGE}&before_id=${oldest}`,
      );
      if (!res.ok) throw new Error(String(res.status));
      const page = (await res.json()) as Push[];
      setPushes((list) => {
        const known = new Set(list.map((p) => p.id));
        return [...list, ...page.filter((p) => !known.has(p.id))];
      });
      if (page.length < PAGE) setExhausted(true);
    } catch {
      toast.error("Couldn't load older pushes. Try again.");
    } finally {
      setLoadingMore(false);
    }
  }, [pushes, slug]);

  const counts = useMemo(() => {
    const c = { all: pushes.length, failed: 0, warned: 0, passed: 0 };
    for (const p of pushes) {
      const s = pushCheckState(p);
      if (s === "failed" || s === "warned" || s === "passed") c[s]++;
    }
    return c;
  }, [pushes]);

  const q = query.trim().toLowerCase();
  const filtered = pushes.filter((p) => {
    if (status !== "all" && pushCheckState(p) !== status) return false;
    if (author !== "all" && p.developer?.github_login !== author) return false;
    if (q && !`${p.commit_message ?? ""} ${p.short_sha} ${p.ai_summary ?? ""} ${p.developer?.github_login ?? ""}`.toLowerCase().includes(q)) return false;
    return true;
  });
  const shown = variant === "compact" ? filtered.slice(0, COMPACT_LIMIT) : filtered;

  const groups: { key: string; label: string; items: Push[] }[] = [];
  for (const p of shown) {
    const iso = p.completed_at ?? p.created_at;
    const key = mounted ? dayKeyLocal(iso) : dayKeyUtc(iso);
    const last = groups.at(-1);
    if (last && last.key === key) last.items.push(p);
    else groups.push({ key, label: dayLabel(iso, mounted), items: [p] });
  }

  const filters: { id: StatusFilter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "failed", label: "Failed" },
    { id: "warned", label: "Warned" },
    { id: "passed", label: "Passed" },
  ];
  const filtering = status !== "all" || author !== "all" || q !== "";

  return (
    <section className="card-surface flex min-h-0 flex-col overflow-hidden" aria-labelledby="feed-title">
      <header className="space-y-3 border-b px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <h2 id="feed-title" className="font-display text-2xl font-extrabold uppercase leading-none">
            {variant === "compact" ? "Latest pushes" : "All pushes"}
          </h2>
          <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" aria-live="polite">
            <span className="relative flex size-2">
              {conn === "live" && <span className="absolute inline-flex size-full animate-ping rounded-full bg-good opacity-60" />}
              <span className={cn("relative inline-flex size-2 rounded-full", conn === "live" ? "bg-good" : "bg-muted-foreground/50")} />
            </span>
            {conn === "live" ? "Live" : conn === "connecting" ? "Connecting…" : "Reconnecting…"}
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Filter by result">
          {filters.map((f) => (
            <button
              key={f.id}
              type="button"
              role="radio"
              aria-checked={status === f.id}
              onClick={() => setStatus(f.id)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs transition-colors",
                status === f.id ? "border-foreground bg-brand font-semibold text-brand-foreground" : "text-muted-foreground hover:bg-muted",
              )}
            >
              {f.label} <span className="font-mono tabular-nums opacity-70">{counts[f.id]}</span>
            </button>
          ))}
        </div>
        {variant === "full" && (
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search commit messages, SHAs, summaries…"
                className="pl-8"
                aria-label="Search pushes"
              />
            </div>
            <select
              value={author}
              onChange={(e) => setAuthor(e.target.value)}
              aria-label="Filter by developer"
              className="h-9 rounded-md border border-input bg-transparent px-2.5 text-sm"
            >
              <option value="all">All developers</option>
              {viewerLogin && <option value={viewerLogin}>Only my pushes</option>}
              {developers
                .filter((d) => d.login !== viewerLogin)
                .map((d) => (
                  <option key={d.login} value={d.login}>
                    {d.name}
                  </option>
                ))}
            </select>
          </div>
        )}
      </header>

      {shown.length === 0 ? (
        <div className="flex flex-col items-center gap-2 px-4 py-12 text-center text-sm text-muted-foreground">
          <Inbox className="size-6" aria-hidden />
          {pushes.length === 0 ? (
            <p>Waiting for the first push. Results appear here live.</p>
          ) : (
            <>
              <p>No pushes match these filters.</p>
              {filtering && (
                <Button variant="ghost" size="sm" onClick={() => { setStatus("all"); setAuthor("all"); setQuery(""); }}>
                  Clear filters
                </Button>
              )}
            </>
          )}
        </div>
      ) : (
        <div className={cn(variant === "compact" && "lg:max-h-[calc(100dvh-14rem)] lg:overflow-y-auto")}>
          {groups.map((g) => (
            <div key={g.key}>
              <div className="sticky top-0 z-10 border-b bg-card/95 px-4 py-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground backdrop-blur">
                {g.label}
              </div>
              <ul className="divide-y divide-border/60">
                {g.items.map((p) => (
                  <PushRow key={p.id} push={p} fresh={fresh.has(p.id)} summary={variant === "full" || p.is_faulty} />
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {variant === "compact" ? (
        <Link
          href={`/teams/${slug}/pushes`}
          className="flex items-center justify-center gap-1 border-t px-4 py-3 text-sm font-medium text-brand-text hover:bg-muted/50"
        >
          View all pushes <ArrowRight className="size-4" aria-hidden />
        </Link>
      ) : (
        !exhausted && (
          <div className="border-t p-3">
            <Button variant="ghost" className="w-full" onClick={loadMore} disabled={loadingMore}>
              {loadingMore && <Loader2 className="size-4 animate-spin" />}
              Load older pushes
            </Button>
          </div>
        )
      )}
    </section>
  );
}
