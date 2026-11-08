"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Radio } from "lucide-react";
import { toast } from "sonner";

import { PushRow } from "@/components/push-row";
import { Button } from "@/components/ui/button";
import { pushCheckState, signed } from "@/lib/format";
import type { Push } from "@/lib/types";
import { cn } from "@/lib/utils";

type Connection = "connecting" | "live" | "reconnecting";
const PAGE = 25;

function notify(push: Push, router: ReturnType<typeof useRouter>) {
  const state = pushCheckState(push);
  if (state === "scanning") return;
  const who = push.developer?.github_login ?? "someone";
  const title = push.commit_message?.split("\n")[0] ?? push.short_sha;
  const opts = {
    description: `@${who} · ${signed(push.points_delta)} pts${push.ai_summary ? ` — ${push.ai_summary}` : ""}`,
    action: { label: "Open", onClick: () => router.push(`/pushes/${push.id}`) },
    duration: state === "failed" ? 12_000 : 6_000,
  };
  if (state === "failed") toast.error(`Merge blocked: ${title}`, opts);
  else if (state === "warned") toast.warning(`Check warned: ${title}`, opts);
  else if (state === "passed") toast.success(`Clean push: ${title}`, opts);
  else toast.info(title, opts);
}

/**
 * Live Push & Incident Feed. Starts from the server-rendered page, then subscribes to the
 * backend SSE stream (through the authenticated /api/backend proxy) for new pushes and
 * status transitions. New results also raise an in-dashboard toast.
 */
export function PushFeed({ slug, initial }: { slug: string; initial: Push[] }) {
  const router = useRouter();
  const [pushes, setPushes] = useState<Push[]>(initial);
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const [conn, setConn] = useState<Connection>("connecting");
  const [loadingMore, setLoadingMore] = useState(false);
  const [exhausted, setExhausted] = useState(initial.length < PAGE);
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
      // Leaderboard, stats and trends are server-rendered: refresh them once a scan lands.
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
      toast.error("Couldn't load older pushes");
    } finally {
      setLoadingMore(false);
    }
  }, [pushes, slug]);

  return (
    <section className="flex min-h-0 flex-col rounded-xl border bg-card" aria-labelledby="feed-title">
      <header className="flex items-center justify-between gap-2 border-b px-4 py-3">
        <h2 id="feed-title" className="font-semibold">
          Live push feed
        </h2>
        <span
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"
          aria-live="polite"
        >
          <Radio
            className={cn("size-3.5", conn === "live" ? "text-good" : "text-muted-foreground")}
            aria-hidden
          />
          {conn === "live" ? "Live" : conn === "connecting" ? "Connecting…" : "Reconnecting…"}
        </span>
      </header>
      {pushes.length === 0 ? (
        <p className="px-4 py-10 text-center text-sm text-muted-foreground">
          Waiting for the first push…
        </p>
      ) : (
        <ul className="divide-y overflow-y-auto lg:max-h-[calc(100dvh-12rem)]">
          {pushes.map((p) => (
            <PushRow key={p.id} push={p} fresh={fresh.has(p.id)} />
          ))}
          {!exhausted && (
            <li className="p-3">
              <Button
                variant="ghost"
                className="w-full"
                onClick={loadMore}
                disabled={loadingMore}
              >
                {loadingMore && <Loader2 className="size-4 animate-spin" />}
                Load older pushes
              </Button>
            </li>
          )}
        </ul>
      )}
    </section>
  );
}
