import Link from "next/link";
import { Check, ChevronsUpDown, LogOut, Settings } from "lucide-react";

import { signOut } from "@/auth";
import { DevAvatar } from "@/components/dev-avatar";
import { GithubMark } from "@/components/icons";
import { LogoMark, Wordmark } from "@/components/logo";
import { ScoringGuide } from "@/components/scoring-guide";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getJson } from "@/lib/backend";
import { incidentStats } from "@/lib/insights";
import type { Push, TeamRef, TeamSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { getViewer } from "@/lib/viewer";

export type Section = "overview" | "pushes" | "data" | "play" | "settings" | null;

function TeamSwitcher({ team, teams }: { team: TeamRef; teams: TeamSummary[] }) {
  if (teams.length <= 1) {
    return (
      <Link href={`/teams/${team.slug}`} className="truncate text-sm font-medium hover:text-foreground">
        {team.name}
      </Link>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-1 px-2 font-medium">
          <span className="max-w-[160px] truncate">{team.name}</span>
          <ChevronsUpDown className="size-3.5 text-muted-foreground" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        <DropdownMenuLabel className="text-xs text-muted-foreground">Switch team</DropdownMenuLabel>
        {teams.map((t) => (
          <DropdownMenuItem key={t.id} asChild>
            <Link href={`/teams/${t.slug}`} className="flex items-center justify-between">
              <span className="truncate">{t.name}</span>
              {t.slug === team.slug && <Check className="size-4" />}
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function NavLink({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "relative flex h-full items-center px-1 font-display text-lg font-bold uppercase tracking-wide transition-colors",
        active ? "text-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      <span className={cn("px-0.5", active && "marker")}>{children}</span>
    </Link>
  );
}

export async function SiteHeader({ team, section = null }: { team?: TeamRef | null; section?: Section }) {
  const viewer = await getViewer();
  const [teams, recent] = team
    ? await Promise.all([
        getJson<TeamSummary[]>("teams").catch(() => null),
        getJson<Push[]>(`teams/${encodeURIComponent(team.slug)}/pushes?limit=50`).catch(() => null),
      ])
    : [null, null];
  const days = recent ? (incidentStats(recent, Date.now())?.days ?? null) : null;

  return (
    <header className="sticky top-[env(safe-area-inset-top,0px)] z-40 border-b-2 border-foreground bg-background/90 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-2 px-4 sm:px-6">
        <Link
          href={team ? `/teams/${team.slug}` : "/"}
          className="group/logo flex shrink-0 items-center gap-2.5 rounded-[5px] outline-none"
          aria-label={days !== null ? `0 Days Since home: ${days} days since last incident` : "0 Days Since home"}
          title={days !== null ? `${days} ${days === 1 ? "day" : "days"} since last incident` : undefined}
        >
          <LogoMark days={days} />
          <Wordmark className="hidden sm:inline" />
        </Link>
        {team && (
          <>
            <span className="text-muted-foreground/50" aria-hidden>
              /
            </span>
            <TeamSwitcher team={team} teams={teams ?? []} />
            <nav className="ml-2 hidden h-full items-center gap-5 sm:flex" aria-label="Team">
              <NavLink href={`/teams/${team.slug}`} active={section === "overview"}>
                Overview
              </NavLink>
              <NavLink href={`/teams/${team.slug}/pushes`} active={section === "pushes"}>
                Pushes
              </NavLink>
              <NavLink href={`/teams/${team.slug}/data`} active={section === "data"}>
                Data
              </NavLink>
              <NavLink href={`/teams/${team.slug}/play`} active={section === "play"}>
                Play
              </NavLink>
            </nav>
          </>
        )}
        <div className="ml-auto flex items-center gap-1">
          {viewer.demoMode && (
            <span className="eyebrow mr-1 hidden rounded-[3px] border border-dashed border-foreground/40 px-2 py-1 lg:inline">
              Demo mode · no sign-in
            </span>
          )}
          {team && (
            <Button
              asChild
              variant="ghost"
              size="icon"
              aria-label="Team settings"
              title="Team settings"
              className={cn(section === "settings" && "bg-brand text-brand-foreground hover:bg-brand")}
            >
              <Link href={`/teams/${team.slug}/settings`}>
                <Settings className="size-4" />
              </Link>
            </Button>
          )}
          <ScoringGuide />
          <ThemeToggle />
          {!viewer.demoMode && !viewer.signedIn && (
            <Button asChild size="sm" className="ml-1">
              <Link href="/signin">
                <GithubMark className="size-4" /> Sign in
              </Link>
            </Button>
          )}
          {viewer.signedIn && viewer.login && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label="Account">
                  <DevAvatar login={viewer.login} src={viewer.image} className="size-7" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuLabel className="font-normal">
                  <div className="text-sm font-medium">{viewer.name}</div>
                  <div className="text-xs text-muted-foreground">@{viewer.login}</div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <form
                  action={async () => {
                    "use server";
                    await signOut({ redirectTo: "/signin" });
                  }}
                >
                  <DropdownMenuItem asChild>
                    <button type="submit" className="w-full">
                      <LogOut className="size-4" /> Sign out
                    </button>
                  </DropdownMenuItem>
                </form>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
      {team && (
        <nav className="flex h-10 items-center gap-5 border-t px-4 sm:hidden" aria-label="Team">
          <NavLink href={`/teams/${team.slug}`} active={section === "overview"}>
            Overview
          </NavLink>
          <NavLink href={`/teams/${team.slug}/pushes`} active={section === "pushes"}>
            Pushes
          </NavLink>
          <NavLink href={`/teams/${team.slug}/data`} active={section === "data"}>
            Data
          </NavLink>
          <NavLink href={`/teams/${team.slug}/play`} active={section === "play"}>
            Play
          </NavLink>
        </nav>
      )}
    </header>
  );
}

export function PageShell({ children }: { children: React.ReactNode }) {
  return <main className="mx-auto w-full max-w-[1400px] px-4 pb-16 pt-6 sm:px-6 lg:pt-8">{children}</main>;
}

/** Consistent section heading: title, one-line explanation, optional action on the right. */
export function SectionHeader({
  title,
  description,
  action,
  id,
  index,
}: {
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  id?: string;
  /** Signage-style section number, e.g. "01". */
  index?: string;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        {index && <div className="eyebrow mb-1">§ {index}</div>}
        <h2 id={id} className="font-display text-3xl font-extrabold uppercase leading-none tracking-wide">
          {title}
        </h2>
        {description && <p className="mt-1.5 text-sm text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  );
}
