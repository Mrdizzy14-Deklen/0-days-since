import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { PlayPageBody } from "@/components/play-page";
import { PageShell, SiteHeader } from "@/components/site-header";
import { getJson } from "@/lib/backend";
import type { Leaderboard } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Daily Zero-Day" };

export default async function TeamPlayPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const board = await getJson<Leaderboard>(`teams/${encodeURIComponent(slug)}/leaderboard`);
  if (!board) notFound();
  return (
    <>
      <SiteHeader team={board.team} section="play" />
      <PageShell>
        <PlayPageBody />
      </PageShell>
    </>
  );
}
