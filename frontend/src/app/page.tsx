import Link from "next/link";
import { redirect } from "next/navigation";
import { ArrowRight, Terminal } from "lucide-react";

import { GithubMark } from "@/components/icons";
import { PageShell, SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { getJson } from "@/lib/backend";
import { appInstallUrl } from "@/lib/format";
import type { TeamSummary } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Home() {
  const teams = (await getJson<TeamSummary[]>("teams")) ?? [];
  if (teams.length === 1) redirect(`/teams/${teams[0].slug}`);
  const installUrl = appInstallUrl();

  return (
    <>
      <SiteHeader />
      <PageShell>
        {teams.length > 0 ? (
          <section className="mx-auto max-w-2xl">
            <h1 className="text-2xl font-semibold tracking-tight">Your teams</h1>
            <ul className="mt-6 divide-y rounded-xl border bg-card">
              {teams.map((t) => (
                <li key={t.id}>
                  <Link
                    href={`/teams/${t.slug}`}
                    className="flex items-center justify-between gap-4 px-5 py-4 hover:bg-muted/50"
                  >
                    <div>
                      <div className="font-medium">{t.name}</div>
                      <div className="text-sm text-muted-foreground">
                        {t.installed ? "GitHub App installed" : "App suspended or removed"}
                      </div>
                    </div>
                    <ArrowRight className="size-4 text-muted-foreground" />
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        ) : (
          <section className="mx-auto max-w-xl py-16 text-center">
            <h1 className="text-3xl font-semibold tracking-tight">No teams yet</h1>
            <p className="mt-3 text-muted-foreground">
              Install the 0 Days Since GitHub App on an organization. Every push to its Python
              repositories is scanned, scored and added to the team leaderboard.
            </p>
            <div className="mt-8 flex flex-col items-center gap-4">
              {installUrl && (
                <Button asChild size="lg">
                  <a href={installUrl}>
                    <GithubMark className="size-4" /> Install the GitHub App
                  </a>
                </Button>
              )}
              <div className="w-full rounded-lg border bg-card p-4 text-left text-sm">
                <div className="mb-2 flex items-center gap-2 font-medium">
                  <Terminal className="size-4" /> Or load the demo team
                </div>
                <code className="block overflow-x-auto rounded bg-muted px-3 py-2 font-mono text-xs">
                  cd backend &amp;&amp; .venv/bin/python seed_demo.py
                </code>
              </div>
            </div>
          </section>
        )}
      </PageShell>
    </>
  );
}
