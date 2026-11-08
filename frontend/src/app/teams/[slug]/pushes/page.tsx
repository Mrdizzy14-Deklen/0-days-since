import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { PushFeed } from "@/components/push-feed";
import { PageShell, SiteHeader } from "@/components/site-header";
import { getJson } from "@/lib/backend";
import type { Leaderboard, Push } from "@/lib/types";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  return { title: `Pushes · ${(await params).slug}` };
}

export default async function TeamPushesPage({ params }: Params) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, pushes, viewer] = await Promise.all([
    getJson<Leaderboard>(`teams/${s}/leaderboard`),
    getJson<Push[]>(`teams/${s}/pushes?limit=50`),
    getViewer(),
  ]);
  if (!board || !pushes) notFound();
  const developers = board.developers
    .map((d) => ({ login: d.github_login, name: d.display_name }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <>
      <SiteHeader team={board.team} section="pushes" />
      <PageShell>
        <div className="mx-auto max-w-3xl">
          <div className="mb-6">
            <h1 className="text-2xl font-semibold tracking-tight">Pushes</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Every scanned push, newest first. Filter by result or developer, or search, then open
              one for the full review.
            </p>
          </div>
          <PushFeed slug={slug} initial={pushes} variant="full" developers={developers} viewerLogin={viewer.login} />
        </div>
      </PageShell>
    </>
  );
}
