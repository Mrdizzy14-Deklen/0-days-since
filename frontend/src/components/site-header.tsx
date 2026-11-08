import Link from "next/link";
import { Check, ChevronsUpDown, LogOut, ShieldHalf } from "lucide-react";

import { signOut } from "@/auth";
import { DevAvatar } from "@/components/dev-avatar";
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
import type { TeamRef, TeamSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { getViewer } from "@/lib/viewer";

export type Section = "overview" | "pushes" | null;

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
        "relative flex h-full items-center px-1 text-sm transition-colors",
        active ? "font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
      {active && <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-brand" aria-hidden />}
    </Link>
  );
}

export async function SiteHeader({ team, section = null }: { team?: TeamRef | null; section?: Section }) {
  const viewer = await getViewer();
  const teams = team ? ((await getJson<TeamSummary[]>("teams").catch(() => null)) ?? []) : [];

  return (
    <header className="sticky top-[env(safe-area-inset-top,0px)] z-40 border-b bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-2 px-4 sm:px-6">
        <Link href="/" className="flex shrink-0 items-center gap-2 font-semibold tracking-tight">
          <span className="grid size-8 place-items-center rounded-lg bg-brand text-brand-foreground shadow-sm">
            <ShieldHalf className="size-4" aria-hidden />
          </span>
          <span className="hidden sm:inline">ZeroDay Score</span>
        </Link>
        {team && (
          <>
            <span className="text-muted-foreground/50" aria-hidden>
              /
            </span>
            <TeamSwitcher team={team} teams={teams} />
            <nav className="ml-2 hidden h-full items-center gap-5 sm:flex" aria-label="Team">
              <NavLink href={`/teams/${team.slug}`} active={section === "overview"}>
                Overview
              </NavLink>
              <NavLink href={`/teams/${team.slug}/pushes`} active={section === "pushes"}>
                Pushes
              </NavLink>
            </nav>
          </>
        )}
        <div className="ml-auto flex items-center gap-1">
          {viewer.demoMode && (
            <span className="mr-1 hidden rounded-full border border-dashed px-2.5 py-0.5 text-xs text-muted-foreground lg:inline">
              Demo mode · no sign-in
            </span>
          )}
          <ScoringGuide />
          <ThemeToggle />
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
}: {
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  id?: string;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        <h2 id={id} className="text-base font-semibold tracking-tight">
          {title}
        </h2>
        {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  );
}
