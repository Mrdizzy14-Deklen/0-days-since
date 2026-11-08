import Link from "next/link";
import { redirect } from "next/navigation";
import { ArrowRight, Eye } from "lucide-react";

import { GithubMark } from "@/components/icons";
import { PageShell, SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { getJson } from "@/lib/backend";
import { appInstallUrl } from "@/lib/format";
import type { TeamSummary } from "@/lib/types";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";

export default async function Home() {
  const [viewer, teams] = await Promise.all([
    getViewer(),
    getJson<TeamSummary[]>("teams").then((t) => t ?? []),
  ]);
  const own = teams.filter((t) => !t.public);
  const demo = teams.find((t) => t.public) ?? null;
  // One real team (or only the demo in local mode): go straight to it.
  if (viewer.signedIn && own.length === 1) redirect(`/teams/${own[0].slug}`);
  if (viewer.demoMode && teams.length === 1) redirect(`/teams/${teams[0].slug}`);
  const installUrl = appInstallUrl();
  const signedOut = !viewer.demoMode && !viewer.signedIn;

  return (
    <>
      <SiteHeader />
      <PageShell>
        <section className="mx-auto max-w-2xl py-10">
          <p className="eyebrow">Security, scored daily</p>
          <h1 className="mt-2 font-display text-5xl font-black uppercase leading-[0.9] sm:text-6xl">
            {own.length > 0 ? "Your teams" : signedOut ? "Clock in" : "No teams yet"}
          </h1>
          <p className="mt-4 max-w-xl text-muted-foreground">
            {signedOut
              ? "Sign in with GitHub to see the teams and repositories you work on. Every Python push is reviewed for vulnerabilities and scored out of 1,000."
              : own.length > 0
                ? "Teams whose repositories have the 0 Days Since GitHub App installed."
                : "Install the 0 Days Since GitHub App on your account or organization. Every push to its Python repositories is reviewed, scored, and added to the team leaderboard."}
          </p>

          {own.length > 0 && (
            <ul className="plate mt-8 divide-y-2 divide-foreground/10">
              {own.map((t) => (
                <li key={t.id}>
                  <Link
                    href={`/teams/${t.slug}`}
                    className="flex items-center justify-between gap-4 px-5 py-4 hover:bg-muted/50"
                  >
                    <div>
                      <div className="font-display text-xl font-bold uppercase">{t.name}</div>
                      <div className="text-sm text-muted-foreground">
                        {t.installed ? "GitHub App installed" : "App suspended or removed"}
                      </div>
                    </div>
                    <ArrowRight className="size-4 text-muted-foreground" />
                  </Link>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-8 flex flex-wrap gap-3">
            {signedOut && (
              <Button asChild size="lg">
                <Link href="/signin">
                  <GithubMark className="size-4" /> Sign in with GitHub
                </Link>
              </Button>
            )}
            {!signedOut && own.length === 0 && installUrl && (
              <Button asChild size="lg">
                <a href={installUrl}>
                  <GithubMark className="size-4" /> Install the GitHub App
                </a>
              </Button>
            )}
            {demo && (
              <Button asChild size="lg" variant="outline">
                <Link href={`/teams/${demo.slug}`}>
                  <Eye className="size-4" /> View the demo team
                </Link>
              </Button>
            )}
            <Button asChild size="lg" variant="ghost">
              <Link href="/play">Play today&apos;s Zero-Day</Link>
            </Button>
          </div>

          {viewer.signedIn && own.length === 0 && (
            <p className="mt-6 text-sm text-muted-foreground">
              Already installed it? Your team shows up after the first push, or as soon as GitHub
              reports the installation. Signed in as @{viewer.login}.
            </p>
          )}
        </section>
      </PageShell>
    </>
  );
}
