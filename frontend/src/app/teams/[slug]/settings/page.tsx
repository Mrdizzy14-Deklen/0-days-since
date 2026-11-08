import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { DiscordSettings } from "@/components/discord-settings";
import { PageShell, SectionHeader, SiteHeader } from "@/components/site-header";
import { getJson } from "@/lib/backend";
import type { Integrations, Leaderboard } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Settings" };

export default async function TeamSettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const s = encodeURIComponent(slug);
  const [board, integrations] = await Promise.all([
    getJson<Leaderboard>(`teams/${s}/leaderboard`),
    getJson<Integrations>(`teams/${s}/integrations`),
  ]);
  if (!board || !integrations) notFound();
  return (
    <>
      <SiteHeader team={board.team} section="settings" />
      <PageShell>
        <div className="mx-auto max-w-3xl space-y-10">
          <div>
            <p className="eyebrow">Team settings</p>
            <h1 className="mt-1 font-display text-5xl font-black uppercase leading-[0.9]">Settings</h1>
          </div>
          <section>
            <SectionHeader
              title="Discord alerts"
              description="Post to a Discord channel whenever someone ships a faulty push and the counter resets."
            />
            <DiscordSettings slug={board.team.slug} initial={integrations} />
          </section>
        </div>
      </PageShell>
    </>
  );
}
